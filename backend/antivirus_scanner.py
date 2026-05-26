"""Antivirus scanner integrations for Sentinel.

This module connects Sentinel to two antivirus engines:

Docker mode:
    Uses ClamAV inside a Docker container.

Local mode:
    Uses Microsoft Defender through MpCmdRun.exe on Windows.

The functions in this file do not decide the full scan mode.
They only run antivirus checks and return normalized antivirus results
that the scan router can merge into Sentinel's final scan output.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any


# Docker image used when Sentinel performs antivirus scanning in Docker mode.
# This image contains ClamAV and is pulled separately through Docker.
CLAMAV_IMAGE = "clamav/clamav:stable"


def _base_av_result(
    engine: str,
    status: str,
    signature: str | None = None,
    raw_output: str = "",
) -> dict[str, Any]:
    """Create a normalized antivirus result dictionary.

    Sentinel uses this same structure for both ClamAV and Microsoft Defender
    so the rest of the backend can process antivirus results consistently.

    Status meanings:
        CLEAN:
            Antivirus completed and did not detect malware.

        INFECTED:
            Antivirus detected malware or a test signature.

        ERROR:
            Antivirus was available, but the scan failed.

        UNAVAILABLE:
            Antivirus engine could not be found or used.
    """

    return {
        "engine": engine,
        "status": status,
        "signature": signature,
        "raw_output": raw_output,
    }


def _find_clamav_defs_folder() -> Path | None:
    """Find Sentinel's custom ClamAV definitions folder.

    Sentinel can load a small custom ClamAV signature file for testing.
    This is useful because Windows Defender may delete the EICAR test file
    before ClamAV can scan it.

    Expected project structure:
        sentinel_file_scanner_v4/
            backend/
            clamav_defs/
                sentinel_test.ndb
            main.py
    """

    # Check the current working directory first.
    # This works when the app is launched from the project root.
    possible_paths = [
        Path.cwd() / "clamav_defs",

        # Check relative to this file as a fallback.
        # This makes the lookup more stable if the app is launched from
        # a different working directory.
        Path(__file__).resolve().parent.parent / "clamav_defs",
    ]

    # Return the first valid custom definitions folder Sentinel can find.
    for path in possible_paths:
        if path.exists() and path.is_dir():
            return path.resolve()

    # Returning None means ClamAV will run with its normal database only.
    return None


def scan_with_clamav_docker(file_path: str) -> dict[str, Any]:
    """Scan a file using ClamAV inside Docker.

    This is Sentinel's antivirus engine for Docker Sandbox Mode.

    ClamAV clamscan return codes:
        0 = clean
        1 = infected
        2 = error
    """

    # Resolve the selected file path so Docker receives an absolute host path.
    path = Path(file_path).resolve()

    # Docker mounts the parent folder and scans only the selected file inside it.
    parent_folder = path.parent
    file_name = path.name

    # Look for Sentinel's custom ClamAV test signatures.
    defs_folder = _find_clamav_defs_folder()

    # Build the docker command in stages.
    # This makes it easier to optionally add the custom definitions folder.
    docker_command = [
        "docker",
        "run",
        "--rm",

        # Mount the selected file's folder into the container as read-only.
        # Read-only mode prevents the scanner container from modifying
        # the user's files.
        "-v",
        f"{parent_folder}:/scan:ro",
    ]

    # If custom ClamAV definitions exist, mount them into the container too.
    if defs_folder is not None:
        docker_command.extend(
            [
                "-v",
                f"{defs_folder}:/defs:ro",
            ]
        )

    # Add the ClamAV image and clamscan command.
    docker_command.extend(
        [
            CLAMAV_IMAGE,
            "clamscan",

            # The summary is not needed for Sentinel's UI.
            # Removing it makes parsing the result easier.
            "--no-summary",
        ]
    )

    # Tell ClamAV to use Sentinel's custom test signatures if they exist.
    if defs_folder is not None:
        docker_command.append("--database=/defs")

    # Scan the selected file through its container path.
    docker_command.append(f"/scan/{file_name}")

    try:
        # Run ClamAV inside Docker.
        # The timeout is long because the first ClamAV run can be slow,
        # especially if Docker is starting or the image is cold.
        result = subprocess.run(
            docker_command,
            capture_output=True,
            text=True,
            timeout=600,
        )

        # ClamAV may write useful output to stdout or stderr depending on the result.
        output = (result.stdout or result.stderr or "").strip()

        # Return code 0 means ClamAV completed and found no malware.
        if result.returncode == 0:
            return _base_av_result(
                "ClamAV Docker",
                "CLEAN",
                raw_output=output,
            )

        # Return code 1 means ClamAV detected something.
        if result.returncode == 1:
            signature = "Unknown signature"

            # Example ClamAV outputs:
            # /scan/eicar_test.txt: Eicar-Test-Signature FOUND
            # /scan/clamav_custom_test.txt: Sentinel.Test.Signature FOUND
            if ": " in output and " FOUND" in output:
                signature = output.split(": ", 1)[1].replace(" FOUND", "").strip()

            return _base_av_result(
                "ClamAV Docker",
                "INFECTED",
                signature=signature,
                raw_output=output,
            )

        # Return code 2, or any other unexpected code, is treated as an error.
        return _base_av_result(
            "ClamAV Docker",
            "ERROR",
            raw_output=output or "ClamAV returned an error.",
        )

    except Exception as error:
        # Any Docker/subprocess failure becomes an antivirus error result.
        # The scan router decides whether to fall back or mark the scan incomplete.
        return _base_av_result(
            "ClamAV Docker",
            "ERROR",
            raw_output=str(error),
        )


def _find_mpcmdrun() -> Path | None:
    """Find Microsoft Defender's MpCmdRun.exe.

    MpCmdRun.exe is Microsoft's command-line scanner.
    Sentinel uses it for Local Scan Mode when running on Windows.
    """

    candidates: list[Path] = []

    # ProgramData usually contains the versioned Defender platform folders.
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")

    # Program Files may contain a fallback Defender executable path.
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")

    # Microsoft Defender commonly stores MpCmdRun.exe inside versioned folders.
    platform_dir = Path(program_data) / "Microsoft" / "Windows Defender" / "Platform"

    if platform_dir.exists():
        version_dirs = [p for p in platform_dir.iterdir() if p.is_dir()]

        # Sort newest-looking version folder first.
        # This makes Sentinel prefer the most recent Defender platform.
        version_dirs.sort(key=lambda p: p.name, reverse=True)

        for version_dir in version_dirs:
            candidates.append(version_dir / "MpCmdRun.exe")

    # Add the older/fallback Defender location.
    candidates.append(Path(program_files) / "Windows Defender" / "MpCmdRun.exe")

    # Return the first MpCmdRun.exe that exists.
    for candidate in candidates:
        if candidate.exists():
            return candidate

    # None means Microsoft Defender's command-line scanner was not found.
    return None


def scan_with_windows_defender(file_path: str) -> dict[str, Any]:
    """Scan a file using Microsoft Defender locally.

    This is Sentinel's local antivirus fallback.

    It is used when:
    - Local Scan Mode is selected
    - Docker is unavailable
    - Auto Mode falls back to local scanning
    """

    path = Path(file_path).resolve()

    # Find the Defender command-line scanner before trying to scan.
    mpcmdrun = _find_mpcmdrun()

    if mpcmdrun is None:
        return _base_av_result(
            "Microsoft Defender",
            "UNAVAILABLE",
            raw_output="MpCmdRun.exe could not be found on this computer.",
        )

    try:
        # Run Microsoft Defender against only the selected file.
        result = subprocess.run(
            [
                str(mpcmdrun),
                "-Scan",

                # ScanType 3 means custom scan.
                "-ScanType",
                "3",

                # The selected file path for the custom scan.
                "-File",
                str(path),

                # This reduces the chance that Defender deletes/remediates
                # the file before Sentinel can report what happened.
                "-DisableRemediation",
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        output = (result.stdout or result.stderr or "").strip()
        lowered = output.lower()

        # Microsoft Defender return code 0 means clean scan completed.
        if result.returncode == 0:
            return _base_av_result(
                "Microsoft Defender",
                "CLEAN",
                raw_output=output,
            )

        # Defender output can vary across Windows versions.
        # These keywords help Sentinel detect an infected result even if
        # the return code or message format is not perfectly consistent.
        infected_keywords = [
            "threat",
            "found",
            "detected",
            "malware",
            "virus",
            "eicar",
            "severe",
        ]

        if any(keyword in lowered for keyword in infected_keywords):
            signature = "Threat detected by Microsoft Defender"

            # Try to extract the most useful output line as the signature.
            for line in output.splitlines():
                line_lower = line.lower()

                if "threat" in line_lower:
                    signature = line.strip()
                    break

                if "found" in line_lower:
                    signature = line.strip()
                    break

                if "detected" in line_lower:
                    signature = line.strip()
                    break

            return _base_av_result(
                "Microsoft Defender",
                "INFECTED",
                signature=signature,
                raw_output=output,
            )

        # If Defender returned a non-zero code but no malware keywords appeared,
        # Sentinel treats it as an antivirus scan error.
        return _base_av_result(
            "Microsoft Defender",
            "ERROR",
            raw_output=output or f"Microsoft Defender returned code {result.returncode}.",
        )

    except Exception as error:
        # Any Defender/subprocess failure becomes an error result.
        return _base_av_result(
            "Microsoft Defender",
            "ERROR",
            raw_output=str(error),
        )


def add_antivirus_result(
    scan_result: dict[str, Any],
    antivirus_result: dict[str, Any],
) -> dict[str, Any]:
    """Merge an antivirus result into Sentinel's normal scan result.

    This function turns antivirus output into Sentinel findings and severity.

    Important:
        If antivirus scanning fails or is blocked, the file should NOT be
        reported as SAFE. A failed antivirus scan means the result is incomplete.
    """

    # Keep the raw normalized antivirus result in the final scan object.
    # The backend API later uses this to display a user-friendly antivirus line.
    scan_result["antivirus"] = antivirus_result

    findings = scan_result.get("findings", [])
    score = int(scan_result.get("score", 0))
    current_level = str(scan_result.get("level", "SAFE")).upper()

    # Antivirus infection is treated as the strongest signal.
    # It immediately pushes the scan result to CRITICAL.
    if antivirus_result["status"] == "INFECTED":
        score += 200
        current_level = "CRITICAL"

        findings.insert(
            0,
            {
                "rule_id": "ANTIVIRUS_MALWARE_DETECTED",
                "name": "Antivirus malware detection",
                "severity": "CRITICAL",
                "category": "Malware",
                "line_number": "-",
                "message": (
                    f"{antivirus_result.get('engine')} detected malware: "
                    f"{antivirus_result.get('signature')}"
                ),
                "evidence": antivirus_result.get("raw_output", ""),
                "matched_pattern": "antivirus signature",
            },
        )

    # Antivirus failure is not the same as clean.
    # Sentinel marks it as a medium-risk incomplete scan.
    elif antivirus_result["status"] in ["ERROR", "UNAVAILABLE"]:
        score += 25

        if current_level in ["SAFE", "LOW", "--"]:
            current_level = "MEDIUM"

        findings.insert(
            0,
            {
                "rule_id": "ANTIVIRUS_SCAN_INCOMPLETE",
                "name": "Antivirus scan incomplete",
                "severity": "MEDIUM",
                "category": "Antivirus",
                "line_number": "-",
                "message": (
                    f"{antivirus_result.get('engine')} could not complete the antivirus scan. "
                    "The file should not be considered fully verified."
                ),
                "evidence": antivirus_result.get("raw_output", ""),
                "matched_pattern": "antivirus error",
            },
        )

    # Write the merged score, findings, count, and severity back to the scan result.
    scan_result["score"] = score
    scan_result["findings"] = findings
    scan_result["finding_count"] = len(findings)
    scan_result["level"] = current_level

    return scan_result 