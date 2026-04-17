import os
import asyncio
from celery import Celery
from scanner.core.engine import ScanConfig, run_scan
from scanner.database import SessionLocal, Scan

# Use redis format connection
REDIS_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "scanner_tasks",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

@celery_app.task(name="scanner.run_scan_task")
def run_scan_task(scan_id: int, url: str, endpoint: str, token: str | None, persist: bool, user_id: int):
    """
    Background Celery task to execute the scan asynchronously without blocking HTTP requests.
    """
    config = ScanConfig(
        url=url,
        endpoint=endpoint,
        token=token,
        persist=persist,
        user_id=user_id,
        scan_id=scan_id
    )
    
    # Update state to processing
    db = SessionLocal()
    scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan_record:
        scan_record.status = "processing"
        db.commit()
    db.close()

    try:
        # Run the actual async scanner engine by creating an event loop in the celery thread
        result = asyncio.run(run_scan(config))
        return {"status": "completed", "total": result.total, "scan_id": scan_id}
        
    except Exception as e:
        db = SessionLocal()
        scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan_record:
            scan_record.status = "failed"
            db.commit()
        db.close()
        return {"status": "failed", "error": str(e), "scan_id": scan_id}
