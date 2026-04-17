"""
scanner/core/engine.py
----------------------
Central reusable scan orchestrator.
Both the FastAPI service and the CLI main.py call this — never duplicate logic.
"""
import asyncio
import logging
from dataclasses import dataclass, field

from scanner.http_client import HTTPClient
from scanner.report import Report
from scanner.tests.bola import test_bola
from scanner.tests.cors import test_cors
from scanner.tests.injection import test_injection
from scanner.tests.rate_limit import test_rate_limit
from scanner.database import save_scan

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Input parameters for a scan run."""
    url: str
    endpoint: str
    token: str | None = None
    persist: bool = True          # Save to SQLite/Postgres after scan
    user_id: int | None = None    # Authenticated user (None = anonymous / CLI)
    scan_id: int | None = None    # Pass existing scan_id if already queued


@dataclass
class ScanResult:
    """Structured output returned by run_scan()."""
    scan_id: int | None
    target: str
    endpoint: str
    total: int
    high: int
    medium: int
    low: int
    findings: list[dict] = field(default_factory=list)


async def run_scan(config: ScanConfig) -> ScanResult:
    """
    Execute all scan modules concurrently against the target endpoint.
    Returns a ScanResult. Optionally persists to the database.
    """
    headers = {}
    if config.token:
        headers["Authorization"] = f"Bearer {config.token}"

    client = HTTPClient(base_url=config.url, headers=headers)
    report = Report(target=config.url)

    try:
        await asyncio.gather(
            test_bola(client, config.endpoint, report),
            test_cors(client, config.endpoint, report),
            test_injection(client, config.endpoint, report),
            test_rate_limit(client, config.endpoint, report),
        )
    except Exception as e:
        logger.error(f"Scan engine error on {config.url}{config.endpoint}: {e}")
    finally:
        await client.close()

    total, severity_count = report.summary()

    scan_id = config.scan_id
    if config.persist:
        try:
            scan_id = save_scan(config.url, config.endpoint, report.findings, user_id=config.user_id, scan_id=config.scan_id)
        except Exception as e:
            logger.error(f"Failed to persist scan to DB: {e}")

    return ScanResult(
        scan_id=scan_id,
        target=config.url,
        endpoint=config.endpoint,
        total=total,
        high=severity_count.get("HIGH", 0),
        medium=severity_count.get("MEDIUM", 0),
        low=severity_count.get("LOW", 0),
        findings=report.findings,
    )
