import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.getenv("EHAS_DB_PATH", "database/ethical_hacking.db")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    os.makedirs("database", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL UNIQUE,
                authorized INTEGER NOT NULL DEFAULT 0,
                authorization_note TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                scan_intensity TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                finding_name TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                affected_target TEXT NOT NULL,
                potential_impact TEXT NOT NULL,
                recommended_remediation TEXT NOT NULL,
                score INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
            """
        )


def add_target(target: str, authorized: bool, authorization_note: str) -> int:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO targets(target, authorized, authorization_note, created_at) VALUES (?, ?, ?, ?)",
            (target, int(authorized), authorization_note, _now_iso()),
        )
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def remove_target(target_id: int):
    with get_connection() as conn:
        conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))


def list_targets():
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]


def add_scan(target_id: int, status: str, scan_intensity: str, summary: dict) -> int:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scans(target_id, status, scan_intensity, summary_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (target_id, status, scan_intensity, json.dumps(summary), _now_iso()),
        )
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_finding(scan_id: int, finding: dict):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO findings(
                scan_id, finding_name, category, severity, description, evidence, affected_target,
                potential_impact, recommended_remediation, score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                finding["finding_name"],
                finding["category"],
                finding["severity"],
                finding["description"],
                finding["evidence"],
                finding["affected_target"],
                finding["potential_impact"],
                finding["recommended_remediation"],
                finding["score"],
                _now_iso(),
            ),
        )


def list_scans():
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT s.*, t.target
            FROM scans s
            JOIN targets t ON t.id = s.target_id
            ORDER BY s.created_at DESC
            """
        ).fetchall()
        scans = [dict(row) for row in rows]
        for scan in scans:
            scan["summary_json"] = json.loads(scan["summary_json"])
        return scans


def list_findings_for_scan(scan_id: int):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY score DESC, created_at ASC", (scan_id,)
        ).fetchall()
        return [dict(row) for row in rows]


def count_findings() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]


def add_report(scan_id: int, path: str):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO reports(scan_id, path, created_at) VALUES (?, ?, ?)", (scan_id, path, _now_iso())
        )
