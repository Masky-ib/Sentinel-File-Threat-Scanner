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

Also supports safe ZIP archive scanning:
   - Detects ZIP files.
   - Safely extracts contents into a temporary folder.
   - Scans extracted files.
   - Combines results into one archive scan report.
   - Cleans up temporary extraction folders.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .antivirus_scanner import add_antivirus_result, scan_with_windows_defender
from .archive_scanner import cleanup_extracted_archive, is_zip_file, safe_extract_zip
from .docker_check import ensure_docker_available
from .docker_scanner import docker_scan
from .scanner import scan_file as local_scan_file


VALID_SCAN_MODES = {"auto", "docker", "local"}

LEVEL_ORDER = {
    "--": 0,
    "SAFE": 0,
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def _highest_level(levels: list[str]) -> str:
    if not levels:
        return "SAFE"

    return max(levels, key=lambda level: LEVEL_ORDER.get(str(level).upper(), 0))


def _base_scan_result(file_path: str) -> dict[str, Any]:
    """
    Creates a UI/database-compatible scan result when the normal text scanner
    cannot read a file, but other scanning layers may still have worked.
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

    Defender runs first because it may quarantine or block malicious files
    before the text scanner can read them.
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


def _prefix_archive_finding(
    finding: dict[str, Any],
    inner_file_path: str,
    archive_name: str,
) -> dict[str, Any]:
    """
    Marks a finding as coming from a file extracted from an archive.
    """

    inner_name = Path(inner_file_path).name

    return {
        **finding,
        "name": f"Archive member: {finding.get('name', 'Finding')}",
        "message": (
            f"Inside archive '{archive_name}', extracted file '{inner_name}': "
            f"{finding.get('message', '')}"
        ),
        "evidence": finding.get("evidence", ""),
    }


def _archive_note_finding(message: str, severity: str = "LOW") -> dict[str, Any]:
    """
    Creates a structured finding for archive scan notes.
    """

    return {
        "rule_id": "ARCHIVE_SCAN_NOTE",
        "name": "Archive scan note",
        "severity": severity,
        "category": "Archive",
        "line_number": "-",
        "message": message,
        "evidence": "",
        "matched_pattern": "archive processing",
    }


def _scan_zip_archive(file_path: str, scan_mode: str, docker_available: bool = False, docker_message: str = "") -> dict[str, Any]:
    """
    Safely scans a ZIP archive.

    Process:
    1. Scan the original ZIP with the selected antivirus/rule mode.
    2. Safely extract ZIP contents.
    3. Scan each extracted file.
    4. Combine all results into one archive scan report.
    5. Clean up temporary extraction folder.
    """

    archive_path = Path(file_path).resolve()
    archive_name = archive_path.name

    if scan_mode == "docker":
        if not docker_available:
            return _docker_error_result(
                file_path,
                f"Docker Sandbox Mode was selected, but Docker is unavailable. {docker_message}",
            )

        base_result = docker_scan(file_path)

        if not base_result.get("success"):
            return _docker_error_result(
                file_path,
                "Docker Sandbox Mode was selected for ZIP scanning, but the Docker scan failed. "
                f"Details: {base_result.get('error', 'Unknown Docker error')}",
            )

        base_result["docker_status"] = docker_message

    elif scan_mode == "local":
        base_result = _local_scan(
            file_path,
            warning=(
                "Local Scan Mode was selected. ZIP contents were extracted into a temporary folder. "
                "Microsoft Defender was used for antivirus scanning when available; Docker container isolation was not used."
            ),
        )

    else:
        # Auto mode: prefer Docker, fall back to local.
        if docker_available:
            base_result = docker_scan(file_path)

            if base_result.get("success"):
                base_result["docker_status"] = docker_message
            else:
                base_result = _local_scan(
                    file_path,
                    warning=(
                        "Docker was available, but ZIP Docker scanning failed. "
                        "Sentinel used Local Scan Mode with Microsoft Defender fallback."
                    ),
                )
                base_result["docker_error"] = base_result.get("error", "Unknown Docker error")
        else:
            base_result = _local_scan(
                file_path,
                warning=(
                    f"{docker_message} Sentinel used Local Scan Mode with Microsoft Defender "
                    "antivirus fallback when available."
                ),
            )

    base_result["file"] = archive_name
    base_result["file_path"] = str(archive_path)
    base_result["file_type"] = ".zip"

    archive_extract_result = safe_extract_zip(file_path)

    combined_findings = list(base_result.get("findings", []))
    combined_score = int(base_result.get("score", 0))
    combined_levels = [str(base_result.get("level", "SAFE")).upper()]
    combined_total_lines = int(base_result.get("total_lines", 0))

    if not archive_extract_result.get("success"):
        combined_score += 25
        combined_levels.append("MEDIUM")
        combined_findings.insert(
            0,
            _archive_note_finding(
                f"ZIP archive could not be fully extracted: {archive_extract_result.get('error')}",
                severity="MEDIUM",
            ),
        )

        base_result["score"] = combined_score
        base_result["findings"] = combined_findings
        base_result["finding_count"] = len(combined_findings)
        base_result["level"] = _highest_level(combined_levels)
        base_result["total_lines"] = combined_total_lines
        base_result["archive"] = {
            "is_archive": True,
            "archive_type": "zip",
            "extracted_files": 0,
            "notes": archive_extract_result.get("archive_notes", []),
        }

        return base_result

    temp_dir = archive_extract_result.get("temp_dir")
    extracted_files = archive_extract_result.get("extracted_files", [])
    archive_notes = archive_extract_result.get("archive_notes", [])

    try:
        for note in archive_notes:
            combined_findings.insert(0, _archive_note_finding(note, severity="LOW"))

        for extracted_file in extracted_files:
            if scan_mode == "docker" and docker_available:
                inner_result = docker_scan(extracted_file)
            elif scan_mode == "auto" and docker_available:
                inner_result = docker_scan(extracted_file)

                if not inner_result.get("success"):
                    inner_result = _local_scan(
                        extracted_file,
                        warning="Docker scan failed for extracted archive member; local fallback was used.",
                    )
            else:
                inner_result = _local_scan(extracted_file)

            combined_score += int(inner_result.get("score", 0))
            combined_total_lines += int(inner_result.get("total_lines", 0))
            combined_levels.append(str(inner_result.get("level", "SAFE")).upper())

            for finding in inner_result.get("findings", []):
                combined_findings.append(
                    _prefix_archive_finding(finding, extracted_file, archive_name)
                )

        base_result["score"] = combined_score
        base_result["total_lines"] = combined_total_lines
        base_result["findings"] = combined_findings
        base_result["finding_count"] = len(combined_findings)
        base_result["level"] = _highest_level(combined_levels)
        base_result["archive"] = {
            "is_archive": True,
            "archive_type": "zip",
            "extracted_files": len(extracted_files),
            "notes": archive_notes,
        }

        return base_result

    finally:
        cleanup_extracted_archive(temp_dir)


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

    docker_available = False
    docker_message = ""

    if scan_mode in {"auto", "docker"}:
        docker_available, docker_message = ensure_docker_available()

    if is_zip_file(file_path):
        return _scan_zip_archive(
            file_path=file_path,
            scan_mode=scan_mode,
            docker_available=docker_available,
            docker_message=docker_message,
        )

    if scan_mode == "local":
        return _local_scan(
            file_path,
            warning=(
                "Local Scan Mode was selected. Microsoft Defender was used for antivirus scanning "
                "when available; Docker container isolation was not used."
            ),
        )

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