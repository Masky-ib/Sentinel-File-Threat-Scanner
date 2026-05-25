"""Scan router for Sentinel.

Supports three scan execution modes:

1. Auto Mode:
   Tries Docker Sandbox Mode first.
   Falls back to Local Scan Mode if Docker is unavailable or Docker scanning fails.

2. Docker Sandbox Mode:
   Requires Docker.
   Uses ClamAV in Docker + Sentinel rule scanning.

3. Local Scan Mode:
   Uses Microsoft Defender locally + Sentinel rule scanning.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .antivirus_scanner import add_antivirus_result, scan_with_windows_defender
from .docker_check import ensure_docker_available
from .docker_scanner import docker_scan
from .scanner import scan_file as local_scan_file


VALID_SCAN_MODES = {"auto", "docker", "local"}


def _base_scan_result(file_path: str) -> dict[str, Any]:
    """
    Creates a UI/database-compatible scan result when the text scanner
    cannot read the file, but antivirus scanning may still have worked.
    """

    path = Path(file_path)

    return {
        "file": path.name,
        "file_path": str(path.resolve()),
        "file_type": path.suffix.lower() or "no extension",
        "level": "SAFE",
        "score": 0,
        "total_lines": 0,
        "finding_count": 0,
        "findings": [],
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _local_scan(file_path: str, warning: str | None = None) -> dict[str, Any]:
    """
    Runs Microsoft Defender first, then Sentinel's local text/rule scanner.

    This order matters because Defender may quarantine or block malicious
    test files such as EICAR before the text scanner can read them.
    """

    antivirus_result = scan_with_windows_defender(file_path)

    try:
        result = local_scan_file(file_path)

    except Exception as error:
        result = _base_scan_result(file_path)
        result["text_scanner_note"] = (
            "Sentinel's rule-based text scanner could not read this file. "
            f"Reason: {type(error).__name__}: {error}"
        )

    result["scan_mode"] = "Local Scan Mode"
    result["isolation"] = "No container isolation"

    result = add_antivirus_result(result, antivirus_result)

    if warning:
        result["warning"] = warning

    return result


def _docker_error_result(file_path: str, message: str) -> dict[str, Any]:
    """
    Returns a UI/database-compatible result when Docker Sandbox Mode is required
    but cannot run.
    """

    path = Path(file_path)

    return {
        "file": path.name,
        "file_path": str(path.resolve()),
        "file_type": path.suffix.lower() or "no extension",
        "level": "--",
        "score": 0,
        "total_lines": 0,
        "finding_count": 0,
        "findings": [],
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_mode": "Docker Sandbox Mode",
        "isolation": "Container isolation required but unavailable",
        "warning": message,
    }


def scan_file(file_path: str, scan_mode: str = "auto") -> dict[str, Any]:
    """
    Main scan entry point.

    Args:
        file_path:
            Path of the selected file.

        scan_mode:
            "auto"   = try Docker/ClamAV first, fallback to Defender/local.
            "docker" = require Docker Sandbox Mode.
            "local"  = use Local Scan Mode only.
    """

    scan_mode = scan_mode.lower().strip()

    if scan_mode not in VALID_SCAN_MODES:
        scan_mode = "auto"

    if scan_mode == "local":
        return _local_scan(
            file_path,
            warning=(
                "Local Scan Mode was selected. Microsoft Defender was used for antivirus scanning "
                "when available; Docker container isolation was not used."
            ),
        )

    docker_available, docker_message = ensure_docker_available()

    if scan_mode == "docker":
        if not docker_available:
            return _docker_error_result(
                file_path,
                f"Docker Sandbox Mode was selected, but Docker is unavailable. {docker_message}",
            )

        docker_result = docker_scan(file_path)

        if docker_result.get("success"):
            docker_result["docker_status"] = docker_message
            return docker_result

        return _docker_error_result(
            file_path,
            "Docker Sandbox Mode was selected, but the Docker scan failed. "
            f"Details: {docker_result.get('error', 'Unknown Docker error')}",
        )

    # Auto mode
    if docker_available:
        docker_result = docker_scan(file_path)

        if docker_result.get("success"):
            docker_result["docker_status"] = docker_message
            return docker_result

        fallback_result = _local_scan(
            file_path,
            warning=(
                "Docker was available, but the Docker scan failed. "
                "Sentinel used Local Scan Mode with Microsoft Defender fallback."
            ),
        )
        fallback_result["docker_error"] = docker_result.get("error", "Unknown Docker error")

        return fallback_result

    return _local_scan(
        file_path,
        warning=(
            f"{docker_message} Sentinel used Local Scan Mode with Microsoft Defender "
            "antivirus fallback when available."
        ),
    )