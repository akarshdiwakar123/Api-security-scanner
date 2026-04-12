import sqlite3
import json
import logging
from datetime import datetime
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_PATH = "scanner_history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT UNIQUE NOT NULL,
    username    TEXT UNIQUE NOT NULL,
    hashed_pw   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    is_active   INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target      TEXT    NOT NULL,
    endpoint    TEXT    NOT NULL,
    scanned_at  TEXT    NOT NULL,
    total       INTEGER DEFAULT 0,
    high        INTEGER DEFAULT 0,
    medium      INTEGER DEFAULT 0,
    low         INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    severity    TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    endpoint    TEXT    NOT NULL,
    description TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);
"""

@contextmanager
def get_connection():
    """Thread-safe SQLite context manager. Always closes connection on exit."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Allow dict-style row access
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database transaction failed: {e}")
        raise
    finally:
        conn.close()


def init_db():
    """Initialize the database and create tables if they don't exist."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
    logger.info(f"Database initialized at '{DB_PATH}'")


def save_scan(target: str, endpoint: str, findings: list, user_id: int | None = None) -> int:
    """
    Persist a completed scan and its associated findings.
    Returns the scan_id for reference.
    """
    severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        severity_count[sev] = severity_count.get(sev, 0) + 1

    scanned_at = datetime.utcnow().isoformat()

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (user_id, target, endpoint, scanned_at, total, high, medium, low)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                target,
                endpoint,
                scanned_at,
                len(findings),
                severity_count.get("HIGH", 0),
                severity_count.get("MEDIUM", 0),
                severity_count.get("LOW", 0),
            ),
        )
        scan_id = cursor.lastrowid

        if findings:
            conn.executemany(
                """
                INSERT INTO vulnerabilities (scan_id, severity, title, endpoint, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        f.get("severity", "LOW"),
                        f.get("title", "Unknown"),
                        f.get("endpoint", endpoint),
                        f.get("description", ""),
                    )
                    for f in findings
                ],
            )

    logger.info(f"Scan #{scan_id} saved — {len(findings)} finding(s) for {target}{endpoint}")
    return scan_id


def fetch_all_scans() -> list[dict]:
    """Return all historical scans ordered by most recent first."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_vulnerabilities(scan_id: int) -> list[dict]:
    """Return all vulnerability records linked to a specific scan."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity",
            (scan_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_all_vulnerabilities() -> list[dict]:
    """Return every vulnerability across all scans for global analytics."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT v.*, s.target, s.scanned_at
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            ORDER BY v.id DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def delete_scan(scan_id: int):
    """Hard-delete a scan and its findings (cascades via FK)."""
    with get_connection() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    logger.info(f"Scan #{scan_id} deleted.")


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------
def create_user(email: str, username: str, hashed_pw: str) -> int:
    """Insert a new user. Raises sqlite3.IntegrityError on duplicate email/username."""
    created_at = datetime.utcnow().isoformat()
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO users (email, username, hashed_pw, created_at) VALUES (?, ?, ?, ?)",
            (email, username, hashed_pw, created_at),
        )
        return cursor.lastrowid


def get_user_by_email(email: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def fetch_scans_for_user(user_id: int) -> list[dict]:
    """Return all scans belonging to a specific user."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC", (user_id,)
        ).fetchall()
    return [dict(row) for row in rows]


# Auto-initialize on import
init_db()

