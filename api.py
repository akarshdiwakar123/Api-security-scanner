"""
api.py — FastAPI backend service for the API Security Scanner.
Run with:  uvicorn api:app --reload --port 8000
Docs at:   http://localhost:8000/docs
"""
import logging
import sqlite3
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from scanner.auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user_id,
)
from scanner.core.engine import ScanConfig, ScanResult, run_scan
from scanner.database import (
    create_user,
    get_user_by_email,
    get_user_by_id,
    fetch_all_scans,
    fetch_scans_for_user,
    fetch_vulnerabilities,
    fetch_all_vulnerabilities,
    delete_scan,
    init_db,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# STARTUP / SHUTDOWN
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Database ready.")
    yield
    logger.info("Shutting down API.")


# =============================================================================
# APP INSTANCE
# =============================================================================
app = FastAPI(
    title="API Security Scanner",
    description="OWASP API Top 10 scanner — async, JWT-secured, production-grade.",
    version="2.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # Tighten this in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# REQUEST / RESPONSE MODELS
# =============================================================================
class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str


class UserOut(BaseModel):
    id: int
    email: str
    username: str
    created_at: str
    is_active: int


class ScanRequest(BaseModel):
    url: str
    endpoint: str
    token: Optional[str] = None
    persist: bool = True

    @field_validator("url")
    @classmethod
    def url_must_have_scheme(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return v.rstrip("/")

    @field_validator("endpoint")
    @classmethod
    def endpoint_must_start_with_slash(cls, v: str) -> str:
        return v if v.startswith("/") else "/" + v


class FindingOut(BaseModel):
    severity: str
    title: str
    endpoint: str
    description: str


class ScanResponse(BaseModel):
    scan_id: Optional[int]
    target: str
    endpoint: str
    total: int
    high: int
    medium: int
    low: int
    findings: list[FindingOut]


class ScanSummary(BaseModel):
    id: int
    user_id: Optional[int]
    target: str
    endpoint: str
    scanned_at: str
    total: int
    high: int
    medium: int
    low: int


class VulnerabilityOut(BaseModel):
    id: int
    scan_id: int
    severity: str
    title: str
    endpoint: str
    description: Optional[str]


# =============================================================================
# HEALTH
# =============================================================================
@app.get("/", tags=["Health"])
async def health():
    return {"status": "online", "service": "API Security Scanner", "version": "2.1.0"}


# =============================================================================
# AUTH ROUTES — Public
# =============================================================================
@app.post(
    "/auth/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Auth"],
    summary="Create a new user account",
)
async def register(body: RegisterRequest):
    # Check for existing email
    if get_user_by_email(body.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists.",
        )
    try:
        hashed = hash_password(body.password)
        user_id = create_user(body.email, body.username, hashed)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already taken.",
        )

    token = create_access_token(user_id, extra={"email": body.email, "username": body.username})
    return TokenResponse(access_token=token, user_id=user_id, username=body.username)


@app.post(
    "/auth/login",
    response_model=TokenResponse,
    tags=["Auth"],
    summary="Login and receive a JWT",
)
async def login(body: LoginRequest):
    user = get_user_by_email(body.email)
    if not user or not verify_password(body.password, user["hashed_pw"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user["is_active"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled.")

    token = create_access_token(user["id"], extra={"email": user["email"], "username": user["username"]})
    return TokenResponse(access_token=token, user_id=user["id"], username=user["username"])


@app.get("/auth/me", response_model=UserOut, tags=["Auth"], summary="Get current user info")
async def get_me(user_id: int = Depends(get_current_user_id)):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return UserOut(**user)


# =============================================================================
# SCAN ROUTES — Protected
# =============================================================================
class ScanQueueResponse(BaseModel):
    message: str
    scan_id: int
    task_id: str
    status: str

@app.post(
    "/scan",
    response_model=ScanQueueResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Scanner"],
    summary="Queue a full security scan (requires authentication)",
)
async def scan_endpoint(
    body: ScanRequest,
    user_id: int = Depends(get_current_user_id),
):
    from scanner.database import get_db_session
    from scanner.models import Scan, User
    from scanner.worker import run_scan_task

    # 1. Create a pending Scan record in the DB
    with get_db_session() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if user.subscription_status == "free" and user.api_usage_current_month >= 5:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="Free tier limit reached (5 scans). Please upgrade to Pro to continue scanning."
            )
        
        user.api_usage_current_month += 1
        
        scan = Scan(
            user_id=user_id,
            target=body.url,
            endpoint=body.endpoint,
            status="pending"
        )
        db.add(scan)
        db.flush()
        scan_id = scan.id

    # 2. Fire celery task
    task = run_scan_task.delay(
        scan_id=scan_id,
        url=body.url,
        endpoint=body.endpoint,
        token=body.token,
        persist=body.persist,
        user_id=user_id
    )

    # 3. Update DB with task_id
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.task_id = task.id

    return ScanQueueResponse(
        message="Scan queued successfully.",
        scan_id=scan_id,
        task_id=task.id,
        status="pending"
    )

@app.get("/scan/status/{scan_id}", tags=["Scanner"], summary="Get scan status")
async def get_scan_status(scan_id: int, user_id: int = Depends(get_current_user_id)):
    from scanner.database import get_db_session
    from scanner.models import Scan
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Build a dict reflecting findings stats if completed
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "task_id": scan.task_id,
            "target": scan.target,
            "endpoint": scan.endpoint,
            "total": scan.total,
            "high": scan.high,
            "medium": scan.medium,
            "low": scan.low
        }


@app.get("/scans", response_model=list[ScanSummary], tags=["History"], summary="Get my scans")
async def list_my_scans(user_id: int = Depends(get_current_user_id)):
    """Return scans belonging to the authenticated user only."""
    return fetch_scans_for_user(user_id)


@app.get("/scans/all", response_model=list[ScanSummary], tags=["History"], summary="[Admin] All scans")
async def list_all_scans(_: int = Depends(get_current_user_id)):
    """Returns all scans (admin-use; add role check before production use)."""
    return fetch_all_scans()


@app.get(
    "/scans/{scan_id}",
    response_model=list[VulnerabilityOut],
    tags=["History"],
    summary="Get vulnerability details for a scan",
)
async def get_scan_findings(scan_id: int, user_id: int = Depends(get_current_user_id)):
    all_user_scans = fetch_scans_for_user(user_id)
    if scan_id not in [s["id"] for s in all_user_scans]:
        raise HTTPException(status_code=403, detail="You do not have access to this scan.")
    
    vulns = fetch_vulnerabilities(scan_id)
    return vulns


@app.get(
    "/scans/{scan_id}/report.pdf",
    tags=["History"],
    summary="Download Scan Report as PDF"
)
async def get_scan_report_pdf(scan_id: int, user_id: int = Depends(get_current_user_id)):
    from fastapi.responses import StreamingResponse
    from scanner.database import get_db_session
    from scanner.models import Scan
    from scanner.report import Report
    
    all_user_scans = fetch_scans_for_user(user_id)
    if scan_id not in [s["id"] for s in all_user_scans]:
        raise HTTPException(status_code=403, detail="You do not have access to this scan.")
        
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        
    vulns = fetch_vulnerabilities(scan_id)
    
    report = Report(target=scan.target)
    report.findings = vulns
    
    buffer = report.generate_pdf(endpoint=scan.endpoint)
    return StreamingResponse(
        buffer, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.pdf"}
    )


@app.delete(
    "/scans/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["History"],
    summary="Delete a scan record",
)
async def remove_scan(scan_id: int, user_id: int = Depends(get_current_user_id)):
    all_user_scans = fetch_scans_for_user(user_id)
    if scan_id not in [s["id"] for s in all_user_scans]:
        raise HTTPException(status_code=403, detail="You do not have permission to delete this scan.")
    try:
        delete_scan(scan_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/vulnerabilities", response_model=list[dict], tags=["Analytics"])
async def all_vulnerabilities(user_id: int = Depends(get_current_user_id)):
    return fetch_all_vulnerabilities(user_id)

# =============================================================================
# BILLING ROUTES — Public & Protected
# =============================================================================
@app.post("/billing/checkout", tags=["Billing"], summary="Get Stripe Checkout URL for Pro Upgrade")
async def checkout(user_id: int = Depends(get_current_user_id)):
    from scanner.database import get_user_by_id
    from scanner.billing import create_checkout_session
    user = get_user_by_id(user_id)
    url = create_checkout_session(user_id=user_id, user_email=user["email"])
    return {"checkout_url": url}

@app.post("/billing/webhook", tags=["Billing"], summary="Stripe Webhook handler")
async def stripe_webhook(request: Request):
    from scanner.billing import verify_webhook_signature
    from scanner.database import get_db_session
    from scanner.models import User
    
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    
    event = verify_webhook_signature(payload, sig_header)
    
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        client_reference_id = session.get('client_reference_id')
        customer_id = session.get('customer')
        
        if client_reference_id:
            with get_db_session() as db:
                user = db.query(User).filter(User.id == int(client_reference_id)).first()
                if user:
                    user.stripe_customer_id = customer_id
                    user.subscription_status = "pro"
                    db.commit()

    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription.get('customer')
        with get_db_session() as db:
            user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
            if user:
                user.subscription_status = "free"
                db.commit()
                
    return {"status": "success"}
