"""SQLite storage for Sentinel scan history and findings."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "data" / "sentinel.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with _connect() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                level TEXT NOT NULL,
                score INTEGER NOT NULL,
                total_lines INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                line_number TEXT NOT NULL,
                message TEXT NOT NULL,
                evidence TEXT,
                matched_pattern TEXT,
                raw_json TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
        )
        connection.commit()


def save_scan(scan_result: dict[str, Any]) -> int:
    init_db()
    with _connect() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO scans
            (file_name, file_path, level, score, total_lines, finding_count, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_result["file"],
                scan_result["file_path"],
                scan_result["level"],
                int(scan_result["score"]),
                int(scan_result["total_lines"]),
                int(scan_result["finding_count"]),
                scan_result["scanned_at"],
            ),
        )
        scan_id = int(cursor.lastrowid)

        for finding in scan_result.get("findings", []):
            cursor.execute(
                """
                INSERT INTO findings
                (scan_id, rule_id, name, severity, category, line_number, message, evidence, matched_pattern, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding.get("rule_id", "UNKNOWN"),
                    finding.get("name", "Unknown finding"),
                    finding.get("severity", "UNKNOWN"),
                    finding.get("category", "General"),
                    str(finding.get("line_number", "-")),
                    finding.get("message", ""),
                    finding.get("evidence", ""),
                    finding.get("matched_pattern", ""),
                    json.dumps(finding, ensure_ascii=False),
                ),
            )
        connection.commit()
        return scan_id


def get_recent_scans(limit: int = 20) -> list[dict[str, Any]]:
    init_db()
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT id, file_name, file_path, level, score, total_lines, finding_count, scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_findings_for_scan(scan_id: int) -> list[dict[str, Any]]:
    init_db()
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT rule_id, name, severity, category, line_number, message, evidence, matched_pattern
            FROM findings
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_frontend_history(limit: int = 20) -> list[dict[str, Any]]:
    history: list[dict[str, Any]] = []
    for scan in get_recent_scans(limit):
        findings = get_findings_for_scan(int(scan["id"]))
        if findings:
            finding_text = [f"[{f['severity']}] {f['name']} — line {f['line_number']}: {f['message']}" for f in findings[:8]]
        else:
            finding_text = ["No suspicious activity detected."]
        history.append(
            {
                "file": scan["file_name"],
                "level": scan["level"],
                "time": scan["scanned_at"],
                "findings": finding_text,
            }
        )
    return history


def get_frontend_alerts(limit: int = 10) -> list[dict[str, Any]]:
    return [
        {"file": scan["file_name"], "level": scan["level"], "time": scan["scanned_at"]}
        for scan in get_recent_scans(50)
        if scan["level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    ][:limit]
