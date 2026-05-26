"""SQLite storage for Sentinel scan history and findings.

This module stores scan results locally in a SQLite database.

Why SQLite:
    Sentinel is designed as a local/offline-capable desktop scanner.
    SQLite is lightweight, built into Python, and does not require a separate
    database server.

The database stores:
- one row per scan in the scans table
- one row per detection/finding in the findings table

The UI then uses this data for:
- scan history
- recent alerts
- reviewing previous scan findings
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


# PROJECT_ROOT points to the main Sentinel project folder.
#
# storage.py is inside:
#     backend/storage.py
#
# parents[1] moves from backend/ to the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]


# SQLite database path.
#
# The database is stored inside the data/ folder so generated runtime data is
# separated from source code.
DB_PATH = PROJECT_ROOT / "data" / "sentinel.db"


def _connect() -> sqlite3.Connection:
    """Create and return a SQLite connection.

    This helper centralizes database connection setup.

    It also makes sure the data/ folder exists before SQLite tries to create
    sentinel.db.
    """

    # Create the data directory if it does not already exist.
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Connect to the local SQLite database file.
    connection = sqlite3.connect(DB_PATH)

    # row_factory lets query results behave like dictionaries.
    # This makes later code cleaner because rows can be converted with dict(row).
    connection.row_factory = sqlite3.Row

    return connection


def init_db() -> None:
    """Initialize the SQLite database tables if they do not already exist.

    This function is safe to call multiple times.

    Sentinel calls it before saving or reading data so the app does not fail
    the first time it runs on a new machine.
    """

    with _connect() as connection:
        cursor = connection.cursor()

        # scans stores the summary of each scan.
        #
        # It does not store every finding directly.
        # Detailed detections go into the findings table linked by scan_id.
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

        # findings stores individual detection results.
        #
        # Each finding belongs to one scan through scan_id.
        # raw_json stores the original finding dictionary so future versions of
        # Sentinel can recover extra fields even if the visible columns change.
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
    """Save one complete scan result to SQLite.

    This function stores:
    1. The scan summary in the scans table.
    2. Each detection/finding in the findings table.

    It returns:
        the new scan_id

    The scan_id is useful because the UI can refer back to this exact scan later.
    """

    # Make sure tables exist before inserting anything.
    init_db()

    with _connect() as connection:
        cursor = connection.cursor()

        # Insert the high-level scan summary first.
        # This creates the parent scan row that findings will link to.
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

        # SQLite gives us the ID of the inserted scan row.
        scan_id = int(cursor.lastrowid)

        # Store every individual finding linked to this scan.
        for finding in scan_result.get("findings", []):
            cursor.execute(
                """
                INSERT INTO findings
                (scan_id, rule_id, name, severity, category, line_number, message, evidence, matched_pattern, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,

                    # Defaults keep storage stable even if a finding is missing
                    # a field due to future changes or an unexpected scan layer.
                    finding.get("rule_id", "UNKNOWN"),
                    finding.get("name", "Unknown finding"),
                    finding.get("severity", "UNKNOWN"),
                    finding.get("category", "General"),
                    str(finding.get("line_number", "-")),
                    finding.get("message", ""),
                    finding.get("evidence", ""),
                    finding.get("matched_pattern", ""),

                    # Store the complete finding as JSON for future reporting.
                    json.dumps(finding, ensure_ascii=False),
                ),
            )

        connection.commit()

        return scan_id


def get_recent_scans(limit: int = 20) -> list[dict[str, Any]]:
    """Return recent scan summaries from the database.

    The newest scans are returned first.

    The limit prevents the UI from loading too many rows at once.
    """

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

    # Convert sqlite3.Row objects into normal dictionaries.
    return [dict(row) for row in rows]


def get_findings_for_scan(scan_id: int) -> list[dict[str, Any]]:
    """Return findings for a specific scan.

    Findings are ordered by insertion order so they appear in the same general
    order Sentinel created them.
    """

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
    """Return scan history formatted for the desktop UI.

    The database stores detailed scan/finding rows.
    The UI needs a simpler shape:
        {
            "file": ...,
            "level": ...,
            "time": ...,
            "findings": [...]
        }

    This function prepares that UI-friendly version.
    """

    history: list[dict[str, Any]] = []

    for scan in get_recent_scans(limit):
        findings = get_findings_for_scan(int(scan["id"]))

        if findings:
            # Only show the first few findings in history.
            # The history page is meant to be a quick overview, not a full report.
            finding_text = [
                f"[{f['severity']}] {f['name']} — line {f['line_number']}: {f['message']}"
                for f in findings[:8]
            ]

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
    """Return recent alert-level scans for the dashboard.

    Alerts are a filtered version of scan history.

    Sentinel shows MEDIUM, HIGH, and CRITICAL scans in the Recent Alerts panel
    because those are the results that need user attention.
    """

    return [
        {
            "file": scan["file_name"],
            "level": scan["level"],
            "time": scan["scanned_at"],
        }
        for scan in get_recent_scans(50)
        if scan["level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    ][:limit]