"""Backend API used by the Sentinel desktop controller.

This file acts as the bridge between the desktop UI/controller and the
lower-level scanner modules.

The controller should not need to know how Docker scanning, local scanning,
antivirus scanning, ZIP scanning, or SQLite storage work internally.

Instead, the controller calls functions from this file:
- safe_run_scan()
- load_history()
- load_alerts()

This keeps the UI layer simpler and keeps backend logic grouped in one place.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from .scanner import format_findings_for_frontend
from .scan_router import scan_file
from .storage import get_frontend_alerts, get_frontend_history, init_db, save_scan


def run_scan(file_path: str, scan_mode: str = "auto") -> dict[str, Any]:
    """Run a real file scan, save it to SQLite, and return a UI-friendly result.

    This function is the main backend entry point for a successful scan.

    It does three jobs:
    1. Sends the file into the scan router.
    2. Saves the raw scan result to SQLite.
    3. Converts the result into a simpler format for the desktop UI.

    The raw backend result contains structured dictionaries.
    The UI needs a friendlier list of text lines, so this function prepares that.
    """

    # Run the selected file through Sentinel's scan router.
    # The scan router decides whether to use Docker mode, local mode, or auto mode.
    scan_result = scan_file(file_path, scan_mode=scan_mode)

    # Save the full scan result in SQLite before formatting it for the UI.
    # This keeps scan history persistent even after the app closes.
    scan_id = save_scan(scan_result)

    # Convert structured findings into readable text lines for the Tkinter UI.
    frontend_findings = format_findings_for_frontend(scan_result)

    # Pull out optional metadata that should appear at the top of the results panel.
    # These fields explain how the scan was performed, not just what was detected.
    scan_mode_used = scan_result.get("scan_mode")
    isolation = scan_result.get("isolation")
    warning = scan_result.get("warning")
    docker_error = scan_result.get("docker_error")
    antivirus = scan_result.get("antivirus")

    # insert_position controls the order of the summary lines.
    # This keeps scan mode, isolation, antivirus, and warnings above the detailed findings.
    insert_position = 0

    # Show whether the file was scanned using Docker, local mode, or another route.
    if scan_mode_used:
        frontend_findings.insert(insert_position, f"Scan mode: {scan_mode_used}")
        insert_position += 1

    # Show whether the scan had container isolation or not.
    # This is important because Docker mode and local mode have different security properties.
    if isolation:
        frontend_findings.insert(insert_position, f"Isolation: {isolation}")
        insert_position += 1

    # Add a readable antivirus summary if the scan produced antivirus metadata.
    # The antivirus scanner returns a normalized dictionary, and this block turns it
    # into one clear line for the user.
    if antivirus:
        av_engine = antivirus.get("engine", "Unknown antivirus engine")
        av_status = antivirus.get("status", "UNKNOWN")

        # INFECTED is shown with the detected signature because that is the most
        # important detail for the user and for the thesis demonstration.
        if av_status == "INFECTED":
            frontend_findings.insert(
                insert_position,
                f"Antivirus scan: INFECTED via {av_engine} - {antivirus.get('signature', 'Unknown signature')}",
            )

        # CLEAN means the antivirus engine did not recognize the file as known malware.
        # Sentinel's own rule scanner may still detect suspicious behavior after this.
        elif av_status == "CLEAN":
            frontend_findings.insert(
                insert_position,
                f"Antivirus scan: CLEAN via {av_engine}",
            )

        # UNAVAILABLE is shown separately from ERROR because it usually means the
        # engine could not be found, not that a scan ran and failed.
        elif av_status == "UNAVAILABLE":
            frontend_findings.insert(
                insert_position,
                f"Antivirus scan: UNAVAILABLE via {av_engine}",
            )

        # Any other antivirus status is treated as an error/incomplete scan.
        # This avoids making failed antivirus checks look safe.
        else:
            frontend_findings.insert(
                insert_position,
                f"Antivirus scan: ERROR via {av_engine} - {antivirus.get('raw_output', 'Unknown error')}",
            )

        insert_position += 1

    # Warnings explain fallback behavior or reduced isolation.
    # Example:
    # Docker failed, so Sentinel used local scanning instead.
    if warning:
        frontend_findings.insert(insert_position, f"Warning: {warning}")
        insert_position += 1

    # Docker errors are kept as an additional note.
    # This helps debugging without replacing the main warning message.
    if docker_error:
        frontend_findings.insert(insert_position, f"Docker note: {docker_error}")

    # Return only the fields the UI needs.
    # The database still stores the fuller scan result.
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
    """Run a scan without crashing the UI if something goes wrong.

    The UI should never crash just because:
    - a file was deleted after selection
    - Windows blocked access
    - the scanner hit an unexpected format
    - a permission error occurred
    - Docker or antivirus behaved unexpectedly

    This wrapper catches unexpected exceptions and returns a normal UI result
    explaining the failure.
    """

    try:
        return run_scan(file_path, scan_mode=scan_mode)

    except Exception as exc:
        # If the scan fails unexpectedly, return a result object shaped like a normal scan.
        # This lets the UI display the error in the results panel instead of crashing.
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
    """Load recent scan history for the UI.

    The database is initialized here to make sure history loading works even
    when this is the first function called after startup.
    """

    # Ensure the SQLite database and tables exist before trying to read history.
    init_db()

    # The UI only needs the most recent entries, not the entire database.
    return get_frontend_history(20)


def load_alerts() -> list[dict[str, Any]]:
    """Load recent alert-level scan results for the dashboard.

    Alerts are shown separately from full history so the user can quickly see
    important recent detections.
    """

    # Ensure the SQLite database and tables exist before trying to read alerts.
    init_db()

    # The dashboard only shows a small number of recent alerts to avoid clutter.
    return get_frontend_alerts(10)