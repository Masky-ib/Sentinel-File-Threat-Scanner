"""Scan router for Sentinel.

This module is the decision-making layer of the scanner.

It does not contain the low-level detection rules themselves.
Instead, it decides which scanner should be used for a selected file.

Supported scan execution modes:

1. Auto Mode:
   Tries Docker Sandbox Mode first.
   Falls back to Local Scan Mode if Docker is unavailable or Docker scanning fails.

2. Docker Sandbox Mode:
   Requires Docker.
   Uses ClamAV in Docker + Sentinel rule scanning inside a container.

3. Local Scan Mode:
   Uses Microsoft Defender locally + Sentinel rule scanning on the host machine.

ZIP archive support:
   - Detects ZIP files.
   - Safely extracts contents into a temporary folder.
   - Scans the original ZIP.
   - Scans extracted files.
   - Combines all results into one archive scan report.
   - Cleans up temporary extraction folders.

Why this file exists:
    The UI and controller should not need to know all the details of Docker,
    Defender, ClamAV, ZIP handling, fallback behavior, or result merging.
    They call scan_file(), and this router chooses the safest available path.
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


# Scan modes accepted by Sentinel.
#
# auto:
#     Prefer Docker if available, otherwise use local scanning.
#
# docker:
#     Require Docker Sandbox Mode.
#     If Docker is unavailable, Sentinel returns an error-style result instead
#     of silently falling back.
#
# local:
#     Skip Docker and scan on the local machine.
VALID_SCAN_MODES = {"auto", "docker", "local"}


# Severity ordering used when combining multiple results.
#
# This is especially important for ZIP scanning because the final archive result
# may include:
# - the original ZIP scan
# - scan results from multiple extracted files
# - archive extraction notes
#
# The final level should be the highest level found anywhere in the archive.
LEVEL_ORDER = {
    "--": 0,
    "SAFE": 0,
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def _highest_level(levels: list[str]) -> str:
    """Return the highest severity level from a list of levels.

    This is used when Sentinel combines several scan results.

    Example:
        ZIP base result: SAFE
        extracted file 1: HIGH
        extracted file 2: MEDIUM

        final ZIP level: HIGH
    """

    # If no levels are provided, default to SAFE.
    # This avoids crashes and gives the lowest-risk result.
    if not levels:
        return "SAFE"

    # Unknown levels are treated as 0 so they do not accidentally outrank
    # known severities.
    return max(levels, key=lambda level: LEVEL_ORDER.get(str(level).upper(), 0))


def _base_scan_result(file_path: str) -> dict[str, Any]:
    """Create a UI/database-compatible scan result.

    This is used when the normal text scanner cannot read a file, but another
    layer, such as antivirus, may still have worked.

    Why this exists:
        Some files are not text-readable, such as executables, binaries, or
        files blocked by antivirus. The app still needs a normal result object
        so it can show the user what happened instead of crashing.
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
    """Run Sentinel's local scan path.

    Local Scan Mode uses:
    1. Microsoft Defender antivirus scanning.
    2. Sentinel's local rule-based text scanner.

    Important design choice:
        Defender runs first.

    Why Defender runs first:
        If a file is malware, Microsoft Defender may block or quarantine it.
        Running Defender first lets Sentinel record that antivirus result before
        the rule scanner tries to read the file.
    """

    # Run the local antivirus layer first.
    antivirus_result = scan_with_windows_defender(file_path)

    try:
        # Run Sentinel's rule-based scanner on the local machine.
        result = local_scan_file(file_path)

    except Exception as error:
        # If the text scanner cannot read the file, keep the antivirus result.
        #
        # This matters because a file may be binary, blocked, quarantined, or
        # otherwise unreadable, while the antivirus result is still meaningful.
        result = _base_scan_result(file_path)
        result["text_scanner_note"] = (
            "Sentinel's rule-based text scanner could not read this file. "
            f"Reason: {type(error).__name__}: {error}"
        )

    # Add scan environment metadata for the UI.
    result["scan_mode"] = "Local Scan Mode"
    result["isolation"] = "No container isolation"

    # Merge Defender's antivirus result into the scan result.
    # This may raise the severity to CRITICAL if malware was detected.
    result = add_antivirus_result(result, antivirus_result)

    # Optional warnings explain reduced isolation or fallback behavior.
    if warning:
        result["warning"] = warning

    return result


def _docker_error_result(file_path: str, message: str) -> dict[str, Any]:
    """Return a UI/database-compatible result when Docker is required but unavailable.

    This is used mainly for Docker Sandbox Only mode.

    In Docker-only mode, Sentinel should not silently fall back to local scanning,
    because the user specifically requested container isolation.
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
    """Mark a finding as coming from a file extracted from an archive.

    Without this, the UI might show a suspicious command but not clearly say
    which file inside the ZIP contained it.

    This function makes archive results more understandable.
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
    """Create a structured finding for archive processing notes.

    Archive notes are converted into finding-like dictionaries so they can be
    displayed in the same result panel as normal detections.

    Examples:
        ZIP archive detected.
        Unsafe path skipped.
        Extraction size limit reached.
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


def _scan_zip_archive(
    file_path: str,
    scan_mode: str,
    docker_available: bool = False,
    docker_message: str = "",
) -> dict[str, Any]:
    """Safely scan a ZIP archive.

    Archive scan process:
    1. Scan the original ZIP file with the selected scan mode.
    2. Safely extract ZIP contents into a temporary folder.
    3. Scan each extracted file.
    4. Combine all results into one archive scan report.
    5. Delete the temporary extraction folder.

    Why scan the original ZIP and the extracted files?
        The original archive may be detected by antivirus.
        The extracted files may reveal suspicious scripts or commands that are
        hidden inside the ZIP.
    """

    archive_path = Path(file_path).resolve()
    archive_name = archive_path.name

    # First scan the ZIP file itself.
    #
    # This base scan gives Sentinel antivirus and metadata results for the
    # archive file before extracted contents are considered.
    if scan_mode == "docker":
        # Docker-only mode requires Docker.
        # If Docker is unavailable, do not fall back silently.
        if not docker_available:
            return _docker_error_result(
                file_path,
                f"Docker Sandbox Mode was selected, but Docker is unavailable. {docker_message}",
            )

        base_result = docker_scan(file_path)

        # If Docker scanning the ZIP itself fails in Docker-only mode, return a
        # clear Docker error result.
        if not base_result.get("success"):
            return _docker_error_result(
                file_path,
                "Docker Sandbox Mode was selected for ZIP scanning, but the Docker scan failed. "
                f"Details: {base_result.get('error', 'Unknown Docker error')}",
            )

        base_result["docker_status"] = docker_message

    elif scan_mode == "local":
        # Local archive scanning extracts files to a temporary folder on the host.
        # The warning makes the reduced isolation clear in the UI.
        base_result = _local_scan(
            file_path,
            warning=(
                "Local Scan Mode was selected. ZIP contents were extracted into a temporary folder. "
                "Microsoft Defender was used for antivirus scanning when available; Docker container isolation was not used."
            ),
        )

    else:
        # Auto mode prefers Docker but allows local fallback.
        if docker_available:
            base_result = docker_scan(file_path)

            if base_result.get("success"):
                base_result["docker_status"] = docker_message
            else:
                # If Docker fails in Auto Mode, use local scanning instead of failing.
                # This keeps Auto Mode user-friendly.
                docker_error = base_result.get("error", "Unknown Docker error")

                base_result = _local_scan(
                    file_path,
                    warning=(
                        "Docker was available, but ZIP Docker scanning failed. "
                        "Sentinel used Local Scan Mode with Microsoft Defender fallback."
                    ),
                )
                base_result["docker_error"] = docker_error
        else:
            # If Docker is not available in Auto Mode, local scan is the expected fallback.
            base_result = _local_scan(
                file_path,
                warning=(
                    f"{docker_message} Sentinel used Local Scan Mode with Microsoft Defender "
                    "antivirus fallback when available."
                ),
            )

    # Normalize the base result so the final report clearly refers to the ZIP,
    # not an internal or temporary file.
    base_result["file"] = archive_name
    base_result["file_path"] = str(archive_path)
    base_result["file_type"] = ".zip"

    # Safely extract archive contents.
    # The archive_scanner module handles path traversal checks, file count limits,
    # size limits, temporary folder creation, and extraction.
    archive_extract_result = safe_extract_zip(file_path)

    # Start the combined result with the original ZIP scan result.
    combined_findings = list(base_result.get("findings", []))
    combined_score = int(base_result.get("score", 0))
    combined_levels = [str(base_result.get("level", "SAFE")).upper()]
    combined_total_lines = int(base_result.get("total_lines", 0))

    # If extraction failed, return the base scan plus an incomplete archive warning.
    #
    # This avoids falsely saying the archive is fully safe when Sentinel could not
    # inspect the contents.
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
        # Add archive processing notes to the combined findings.
        #
        # These are low severity by default because they are informational,
        # unless the extraction module reports something more serious.
        for note in archive_notes:
            combined_findings.insert(0, _archive_note_finding(note, severity="LOW"))

        # Scan every safely extracted file.
        for extracted_file in extracted_files:
            if scan_mode == "docker" and docker_available:
                # Docker-only archive mode scans extracted files with Docker too.
                inner_result = docker_scan(extracted_file)

            elif scan_mode == "auto" and docker_available:
                # Auto Mode prefers Docker for archive members when Docker is available.
                inner_result = docker_scan(extracted_file)

                if not inner_result.get("success"):
                    # If Docker fails for one extracted file, Auto Mode falls back
                    # to local scanning for that file instead of losing the result.
                    inner_result = _local_scan(
                        extracted_file,
                        warning="Docker scan failed for extracted archive member; local fallback was used.",
                    )
            else:
                # Local mode, or Auto Mode without Docker, scans archive members locally.
                inner_result = _local_scan(extracted_file)

            # Combine numeric score and scanned line counts.
            combined_score += int(inner_result.get("score", 0))
            combined_total_lines += int(inner_result.get("total_lines", 0))

            # Track severity so the final ZIP result inherits the highest severity.
            combined_levels.append(str(inner_result.get("level", "SAFE")).upper())

            # Add each finding from the extracted file and mark it as archive content.
            for finding in inner_result.get("findings", []):
                combined_findings.append(
                    _prefix_archive_finding(finding, extracted_file, archive_name)
                )

        # Write combined archive result back into the base result.
        base_result["score"] = combined_score
        base_result["total_lines"] = combined_total_lines
        base_result["findings"] = combined_findings
        base_result["finding_count"] = len(combined_findings)
        base_result["level"] = _highest_level(combined_levels)

        # Keep archive metadata for future UI/reporting improvements.
        base_result["archive"] = {
            "is_archive": True,
            "archive_type": "zip",
            "extracted_files": len(extracted_files),
            "notes": archive_notes,
        }

        return base_result

    finally:
        # Always clean up temporary extracted files, even if scanning one of the
        # archive members fails.
        #
        # This is important because extracted archive members may be suspicious.
        cleanup_extracted_archive(temp_dir)


def scan_file(file_path: str, scan_mode: str = "auto") -> dict[str, Any]:
    """Main scan entry point used by backend_api.py.

    Args:
        file_path:
            Path of the selected file.

        scan_mode:
            "auto"   = try Docker/ClamAV first, fallback to Defender/local.
            "docker" = require Docker Sandbox Mode.
            "local"  = use Local Scan Mode only.

    This function is the main public function of this module.
    Everything else is helper logic.
    """

    # Normalize the scan mode so UI values are handled safely.
    scan_mode = scan_mode.lower().strip()

    # Invalid scan modes default to Auto Mode.
    # Auto Mode is the safest general-purpose default because it tries Docker
    # first but still allows local fallback.
    if scan_mode not in VALID_SCAN_MODES:
        scan_mode = "auto"

    # Docker status is only checked when it might be needed.
    # Local mode does not need Docker, so checking Docker would waste time and
    # could unnecessarily start Docker Desktop.
    docker_available = False
    docker_message = ""

    if scan_mode in {"auto", "docker"}:
        docker_available, docker_message = ensure_docker_available()

    # ZIP files use the archive flow.
    # This happens before normal file scanning because ZIPs need extraction and
    # combined reporting.
    if is_zip_file(file_path):
        return _scan_zip_archive(
            file_path=file_path,
            scan_mode=scan_mode,
            docker_available=docker_available,
            docker_message=docker_message,
        )

    # Local mode explicitly skips Docker.
    if scan_mode == "local":
        return _local_scan(
            file_path,
            warning=(
                "Local Scan Mode was selected. Microsoft Defender was used for antivirus scanning "
                "when available; Docker container isolation was not used."
            ),
        )

    # Docker-only mode requires Docker and does not fall back silently.
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

    # Auto Mode:
    # Try Docker first because it provides container isolation and ClamAV scanning.
    if docker_available:
        docker_result = docker_scan(file_path)

        if docker_result.get("success"):
            docker_result["docker_status"] = docker_message
            return docker_result

        # If Docker fails in Auto Mode, use local scanning instead of failing.
        fallback_result = _local_scan(
            file_path,
            warning=(
                "Docker was available, but the Docker scan failed. "
                "Sentinel used Local Scan Mode with Microsoft Defender fallback."
            ),
        )
        fallback_result["docker_error"] = docker_result.get("error", "Unknown Docker error")

        return fallback_result

    # Auto Mode fallback when Docker is unavailable.
    return _local_scan(
        file_path,
        warning=(
            f"{docker_message} Sentinel used Local Scan Mode with Microsoft Defender "
            "antivirus fallback when available."
        ),
    )