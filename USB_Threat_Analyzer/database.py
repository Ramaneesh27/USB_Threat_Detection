"""
SQLite persistence layer for USB Threat Analyzer.

Owns the schema and all read/write access to history.db so that no
other module writes raw SQL directly. Uses short-lived connections
(check_same_thread=False guarded by a lock) since Flask handles
requests on multiple threads and the USB monitor runs in a background
thread as well.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional

import config
from utils.logger import get_logger

logger = get_logger(__name__)

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id             TEXT PRIMARY KEY,
    usb_name            TEXT,
    drive_letter        TEXT,
    capacity_bytes      INTEGER,
    file_system         TEXT,
    started_at          TEXT,
    finished_at         TEXT,
    files_scanned       INTEGER DEFAULT 0,
    suspicious_files    INTEGER DEFAULT 0,
    highest_risk        INTEGER DEFAULT 0,
    sandbox_used        TEXT,
    report_path         TEXT,
    status              TEXT DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS files (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT NOT NULL,
    file_name           TEXT,
    extension           TEXT,
    absolute_path       TEXT,
    size_bytes          INTEGER,
    sha256              TEXT,
    mime_type           TEXT,
    created_date        TEXT,
    modified_date       TEXT,
    level               INTEGER,
    risk_score          INTEGER,
    risk_level          TEXT,
    reasons_json        TEXT,
    quarantined         INTEGER DEFAULT 0,
    explanations_json   TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
);

CREATE TABLE IF NOT EXISTS quarantine (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT NOT NULL,
    original_path       TEXT,
    quarantine_path     TEXT,
    sha256              TEXT,
    risk_score          INTEGER,
    reasons_json        TEXT,
    quarantined_at      TEXT,
    status              TEXT DEFAULT 'quarantined',
    explanations_json   TEXT,
    source              TEXT DEFAULT 'auto'
);

CREATE TABLE IF NOT EXISTS sandbox_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT NOT NULL,
    file_sha256         TEXT,
    sandbox_type        TEXT,
    started_at          TEXT,
    finished_at         TEXT,
    before_snapshot     TEXT,
    after_snapshot      TEXT,
    diff_json           TEXT,
    verdict_notes       TEXT
);

CREATE INDEX IF NOT EXISTS idx_files_scan_id ON files (scan_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_scan_id ON quarantine (scan_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_scan_id ON sandbox_runs (scan_id);

CREATE TABLE IF NOT EXISTS app_settings (
    key                 TEXT PRIMARY KEY,
    value               TEXT
);
"""


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(config.DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# Columns added after the first release. CREATE TABLE IF NOT EXISTS does not
# alter tables that already exist, so older history.db files get them here.
_COLUMN_MIGRATIONS = (
    ("files", "explanations_json", "TEXT"),
    ("quarantine", "explanations_json", "TEXT"),
    ("quarantine", "source", "TEXT DEFAULT 'auto'"),   # 'auto' (risk score) or 'manual' (user)
)


def _migrate(conn: sqlite3.Connection) -> None:
    for table, column, col_type in _COLUMN_MIGRATIONS:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
            logger.info("Migrated database: added %s.%s", table, column)


def init_db() -> None:
    """Create tables if they do not already exist. Safe to call on every startup."""
    with _lock, _connect() as conn:
        conn.executescript(_SCHEMA)
        _migrate(conn)
    logger.info("Database initialized at %s", config.DATABASE_PATH)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------
def create_scan(scan_id: str, usb_name: str, drive_letter: str,
                 capacity_bytes: int, file_system: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            """INSERT INTO scans (scan_id, usb_name, drive_letter, capacity_bytes,
                                   file_system, started_at, status)
               VALUES (?, ?, ?, ?, ?, ?, 'running')""",
            (scan_id, usb_name, drive_letter, capacity_bytes, file_system,
             datetime.utcnow().isoformat()),
        )


def finish_scan(scan_id: str, files_scanned: int, suspicious_files: int,
                 highest_risk: int, sandbox_used: Optional[str], report_path: Optional[str]) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            """UPDATE scans SET finished_at = ?, files_scanned = ?, suspicious_files = ?,
                                 highest_risk = ?, sandbox_used = ?, report_path = ?, status = 'completed'
               WHERE scan_id = ?""",
            (datetime.utcnow().isoformat(), files_scanned, suspicious_files,
             highest_risk, sandbox_used, report_path, scan_id),
        )


def list_scans(limit: int = 100) -> list[dict]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id: str) -> Optional[dict]:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
def insert_file_result(scan_id: str, result: dict) -> int:
    with _lock, _connect() as conn:
        cur = conn.execute(
            """INSERT INTO files (scan_id, file_name, extension, absolute_path, size_bytes,
                                   sha256, mime_type, created_date, modified_date, level,
                                   risk_score, risk_level, reasons_json, quarantined,
                                   explanations_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id, result.get("file_name"), result.get("extension"),
                result.get("absolute_path"), result.get("size_bytes"),
                result.get("sha256"), result.get("mime_type"),
                result.get("created_date"), result.get("modified_date"),
                result.get("level"), result.get("risk_score"), result.get("risk_level"),
                json.dumps(result.get("reasons", [])), int(result.get("quarantined", False)),
                json.dumps(result.get("explanations", [])),
            ),
        )
        return cur.lastrowid


def list_files_for_scan(scan_id: str) -> list[dict]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM files WHERE scan_id = ? ORDER BY risk_score DESC", (scan_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["reasons"] = json.loads(d.pop("reasons_json") or "[]")
            d["explanations"] = json.loads(d.pop("explanations_json", None) or "[]")
            out.append(d)
        return out


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------
def insert_quarantine_record(scan_id: str, original_path: str, quarantine_path: str,
                              sha256: str, risk_score: int, reasons: list[str],
                              explanations: Optional[list[dict]] = None,
                              source: str = "auto") -> int:
    with _lock, _connect() as conn:
        cur = conn.execute(
            """INSERT INTO quarantine (scan_id, original_path, quarantine_path, sha256,
                                        risk_score, reasons_json, quarantined_at, status,
                                        explanations_json, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'quarantined', ?, ?)""",
            (scan_id, original_path, quarantine_path, sha256, risk_score,
             json.dumps(reasons), datetime.utcnow().isoformat(),
             json.dumps(explanations or []), "manual" if source == "manual" else "auto"),
        )
        return cur.lastrowid


def list_quarantine(limit: int = 500) -> list[dict]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM quarantine ORDER BY quarantined_at DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["reasons"] = json.loads(d.pop("reasons_json") or "[]")
            d["explanations"] = json.loads(d.pop("explanations_json", None) or "[]")
            out.append(d)
        return out


def list_quarantine_for_scan(scan_id: str) -> list[dict]:
    """Every quarantine record created by one scan (oldest first) - used by the PDF report."""
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM quarantine WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["reasons"] = json.loads(d.pop("reasons_json") or "[]")
            d["explanations"] = json.loads(d.pop("explanations_json", None) or "[]")
            d["source"] = d.get("source") or "auto"
            out.append(d)
        return out


def get_quarantine_item(item_id: int) -> Optional[dict]:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT * FROM quarantine WHERE id = ?", (item_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["reasons"] = json.loads(d.pop("reasons_json") or "[]")
        d["explanations"] = json.loads(d.pop("explanations_json", None) or "[]")
        return d


def update_quarantine_status(item_id: int, status: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("UPDATE quarantine SET status = ? WHERE id = ?", (status, item_id))


# ---------------------------------------------------------------------------
# Sandbox runs
# ---------------------------------------------------------------------------
def insert_sandbox_run(scan_id: str, file_sha256: str, sandbox_type: str,
                        started_at: str, finished_at: str, before_snapshot: dict,
                        after_snapshot: dict, diff: dict, verdict_notes: str) -> int:
    with _lock, _connect() as conn:
        cur = conn.execute(
            """INSERT INTO sandbox_runs (scan_id, file_sha256, sandbox_type, started_at,
                                          finished_at, before_snapshot, after_snapshot,
                                          diff_json, verdict_notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, file_sha256, sandbox_type, started_at, finished_at,
             json.dumps(before_snapshot), json.dumps(after_snapshot),
             json.dumps(diff), verdict_notes),
        )
        return cur.lastrowid


def list_sandbox_runs_for_scan(scan_id: str) -> list[dict]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM sandbox_runs WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["before_snapshot"] = json.loads(d.pop("before_snapshot") or "{}")
            d["after_snapshot"] = json.loads(d.pop("after_snapshot") or "{}")
            d["diff"] = json.loads(d.pop("diff_json") or "{}")
            out.append(d)
        return out


# ---------------------------------------------------------------------------
# App settings (generic key-value store for small user preferences, e.g.
# the "Auto-Download Report" toggle - kept separate from config.py because
# these are user-changeable at runtime, not developer-set defaults)
# ---------------------------------------------------------------------------
def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            """INSERT INTO app_settings (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, value),
        )


def get_bool_setting(key: str, default: bool = False) -> bool:
    raw = get_setting(key, "1" if default else "0")
    return raw == "1"


def set_bool_setting(key: str, value: bool) -> None:
    set_setting(key, "1" if value else "0")
