"""Backend API used by the Sentinel desktop controller."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from .scanner import format_findings_for_frontend
from .scan_router import scan_file
from .storage import get_frontend_alerts, get_frontend_history, init_db, save_scan


def run_scan(file_path: str, scan_mode: str = "auto") -> dict[str, Any]:
    """Run a real file scan, save it to SQLite, and return the UI-friendly result."""

    scan_result = scan_file(file_path, scan_mode=scan_mode)
    scan_id = save_scan(scan_result)

    frontend_findings = format_findings_for_frontend(scan_result)

    scan_mode_used = scan_result.get("scan_mode")
    isolation = scan_result.get("isolation")
    warning = scan_result.get("warning")
    docker_error = scan_result.get("docker_error")
    antivirus = scan_result.get("antivirus")

    insert_position = 0

    if scan_mode_used:
        frontend_findings.insert(insert_position, f"Scan mode: {scan_mode_used}")
        insert_position += 1

    if isolation:
        frontend_findings.insert(insert_position, f"Isolation: {isolation}")
        insert_position += 1

    if antivirus:
        av_engine = antivirus.get("engine", "Unknown antivirus engine")
        av_status = antivirus.get("status", "UNKNOWN")

        if av_status == "INFECTED":
            frontend_findings.insert(
                insert_position,
                f"Antivirus scan: INFECTED via {av_engine} - {antivirus.get('signature', 'Unknown signature')}",
            )
        elif av_status == "CLEAN":
            frontend_findings.insert(
                insert_position,
                f"Antivirus scan: CLEAN via {av_engine}",
            )
        elif av_status == "UNAVAILABLE":
            frontend_findings.insert(
                insert_position,
                f"Antivirus scan: UNAVAILABLE via {av_engine}",
            )
        else:
            frontend_findings.insert(
                insert_position,
                f"Antivirus scan: ERROR via {av_engine} - {antivirus.get('raw_output', 'Unknown error')}",
            )

        insert_position += 1

    if warning:
        frontend_findings.insert(insert_position, f"Warning: {warning}")
        insert_position += 1

    if docker_error:
        frontend_findings.insert(insert_position, f"Docker note: {docker_error}")

    return {
        "scan_id": scan_id,
        "file": scan_result["file"],
        "file_path": scan_result["file_path"],
        "level": scan_result["level"],
        "score": scan_result["score"],
        "findings": frontend_findings,
        "time": scan_result["scanned_at"],
    }


def safe_run_scan(file_path: str, scan_mode: str = "auto") -> dict[str, Any]:
    """Run scan without crashing the UI if a file, permission, or format error happens."""

    try:
        return run_scan(file_path, scan_mode=scan_mode)
    except Exception as exc:
        return {
            "scan_id": None,
            "file": os.path.basename(file_path) if file_path else None,
            "file_path": file_path,
            "level": "--",
            "score": 0,
            "findings": [
                "File could not be scanned.",
                f"Error type: {type(exc).__name__}",
                f"Details: {exc}",
                "Try a readable text-based file such as .txt, .log, .json, .csv, .py, .ps1, .bat, .md, .xml, .yaml, .ini, or .conf.",
            ],
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }


def load_history() -> list[dict[str, Any]]:
    init_db()
    return get_frontend_history(20)


def load_alerts() -> list[dict[str, Any]]:
    init_db()
    return get_frontend_alerts(10)