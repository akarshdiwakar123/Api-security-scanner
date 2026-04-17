import os
import logging
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from scanner.models import Base, User, Scan, Vulnerability

logger = logging.getLogger(__name__)

# Fallback to SQLite if DATABASE_URL is not provided (e.g. for simple local testing)
# But defaults to PostgreSQL as requested in the plan
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://scanner_user:scanner_password@localhost:5432/scanner_db")

try:
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
except Exception as e:
    logger.error(f"Failed to create database engine: {e}")
    # Fallback to sqlite if postgres is utterly failing during start
    engine = create_engine("sqlite:///./scanner_history.db", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@contextmanager
def get_db_session():
    """Provide a transactional scope around a series of operations."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database transaction failed: {e}")
        raise
    finally:
        session.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized with SQLAlchemy.")

def create_user(email: str, username: str, hashed_pw: str) -> int:
    with get_db_session() as db:
        user = User(email=email, username=username, hashed_pw=hashed_pw)
        db.add(user)
        db.flush() # get ID before commit
        return user.id

def get_user_by_email(email: str) -> dict | None:
    with get_db_session() as db:
        user = db.query(User).filter(User.email == email).first()
        if user:
            return {"id": user.id, "email": user.email, "username": user.username, "hashed_pw": user.hashed_pw, "is_active": user.is_active}
    return None

def get_user_by_id(user_id: int) -> dict | None:
    with get_db_session() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            return {"id": user.id, "email": user.email, "username": user.username, "created_at": user.created_at.isoformat(), "is_active": user.is_active}
    return None

def save_scan(target: str, endpoint: str, findings: list, user_id: int | None = None, scan_id: int | None = None) -> int:
    severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        severity_count[sev] = severity_count.get(sev, 0) + 1

    with get_db_session() as db:
        if scan_id:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.target = target
                scan.endpoint = endpoint
                scan.total = len(findings)
                scan.high = severity_count.get("HIGH", 0)
                scan.medium = severity_count.get("MEDIUM", 0)
                scan.low = severity_count.get("LOW", 0)
                scan.status = "completed"
            else:
                scan_id = None # Fallback to creating if missing for some reason
        
        if not scan_id:
            scan = Scan(
                user_id=user_id,
                target=target,
                endpoint=endpoint,
                total=len(findings),
                high=severity_count.get("HIGH", 0),
                medium=severity_count.get("MEDIUM", 0),
                low=severity_count.get("LOW", 0),
                status="completed"
            )
            db.add(scan)
        db.flush()
        
        # Clear old vulnerabilities if updating
        if scan_id:
            db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).delete()
            
        for f in findings:
            vuln = Vulnerability(
                scan_id=scan.id,
                severity=f.get("severity", "LOW"),
                title=f.get("title", "Unknown"),
                endpoint=f.get("endpoint", endpoint),
                description=f.get("description", "")
            )
            db.add(vuln)
        return scan.id

def fetch_scans_for_user(user_id: int) -> list[dict]:
    with get_db_session() as db:
        scans = db.query(Scan).filter(Scan.user_id == user_id).order_by(Scan.id.desc()).all()
        return [{"id": s.id, "user_id": s.user_id, "target": s.target, "endpoint": s.endpoint, "scanned_at": s.scanned_at.isoformat(), "total": s.total, "high": s.high, "medium": s.medium, "low": s.low, "status": s.status, "task_id": s.task_id} for s in scans]

def fetch_all_scans() -> list[dict]:
    with get_db_session() as db:
        scans = db.query(Scan).order_by(Scan.id.desc()).all()
        return [{"id": s.id, "user_id": s.user_id, "target": s.target, "endpoint": s.endpoint, "scanned_at": s.scanned_at.isoformat(), "total": s.total, "high": s.high, "medium": s.medium, "low": s.low, "status": s.status, "task_id": s.task_id} for s in scans]

def fetch_vulnerabilities(scan_id: int) -> list[dict]:
    with get_db_session() as db:
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).order_by(Vulnerability.severity).all()
        return [{"id": v.id, "scan_id": v.scan_id, "severity": v.severity, "title": v.title, "endpoint": v.endpoint, "description": v.description} for v in vulns]

def fetch_all_vulnerabilities(user_id: int | None = None) -> list[dict]:
    with get_db_session() as db:
        query = db.query(Vulnerability, Scan).join(Scan)
        if user_id is not None:
            query = query.filter(Scan.user_id == user_id)
        
        results = query.order_by(Vulnerability.id.desc()).all()
        return [{
            "id": v.id, "scan_id": v.scan_id, "severity": v.severity, "title": v.title, "endpoint": v.endpoint, "description": v.description, "target": s.target, "scanned_at": s.scanned_at.isoformat()
        } for v, s in results]

def delete_scan(scan_id: int):
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            db.delete(scan)
