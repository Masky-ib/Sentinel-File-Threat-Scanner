"""Antivirus scanner integrations for Sentinel.

Docker mode:
    Uses ClamAV inside Docker.

Local mode:
    Uses Microsoft Defender through MpCmdRun.exe on Windows.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any


CLAMAV_IMAGE = "clamav/clamav:stable"


def _base_av_result(
    engine: str,
    status: str,
    signature: str | None = None,
    raw_output: str = "",
) -> dict[str, Any]:
    return {
        "engine": engine,
        "status": status,  # CLEAN, INFECTED, ERROR, UNAVAILABLE
        "signature": signature,
        "raw_output": raw_output,
    }


def _find_clamav_defs_folder() -> Path | None:
    """
    Finds the custom ClamAV definitions folder.

    Expected project structure:
        sentinel_file_scanner_v4/
            backend/
            clamav_defs/
                sentinel_test.ndb
            main.py
    """

    possible_paths = [
        Path.cwd() / "clamav_defs",
        Path(__file__).resolve().parent.parent / "clamav_defs",
    ]

    for path in possible_paths:
        if path.exists() and path.is_dir():
            return path.resolve()

    return None


def scan_with_clamav_docker(file_path: str) -> dict[str, Any]:
    """
    Scan a file using ClamAV inside Docker.

    ClamAV clamscan return codes:
        0 = clean
        1 = infected
        2 = error
    """

    path = Path(file_path).resolve()
    parent_folder = path.parent
    file_name = path.name
    defs_folder = _find_clamav_defs_folder()

    docker_command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{parent_folder}:/scan:ro",
    ]

    if defs_folder is not None:
        docker_command.extend(
            [
                "-v",
                f"{defs_folder}:/defs:ro",
            ]
        )

    docker_command.extend(
        [
            CLAMAV_IMAGE,
            "clamscan",
            "--no-summary",
        ]
    )

    if defs_folder is not None:
        docker_command.append("--database=/defs")

    docker_command.append(f"/scan/{file_name}")

    try:
        result = subprocess.run(
            docker_command,
            capture_output=True,
            text=True,
            timeout=600,
        )

        output = (result.stdout or result.stderr or "").strip()

        if result.returncode == 0:
            return _base_av_result(
                "ClamAV Docker",
                "CLEAN",
                raw_output=output,
            )

        if result.returncode == 1:
            signature = "Unknown signature"

            # Example:
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

        return _base_av_result(
            "ClamAV Docker",
            "ERROR",
            raw_output=output or "ClamAV returned an error.",
        )

    except Exception as error:
        return _base_av_result(
            "ClamAV Docker",
            "ERROR",
            raw_output=str(error),
        )


def _find_mpcmdrun() -> Path | None:
    """
    Find Microsoft Defender's MpCmdRun.exe.
    """

    candidates: list[Path] = []

    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")

    platform_dir = Path(program_data) / "Microsoft" / "Windows Defender" / "Platform"

    if platform_dir.exists():
        version_dirs = [p for p in platform_dir.iterdir() if p.is_dir()]
        version_dirs.sort(key=lambda p: p.name, reverse=True)

        for version_dir in version_dirs:
            candidates.append(version_dir / "MpCmdRun.exe")

    candidates.append(Path(program_files) / "Windows Defender" / "MpCmdRun.exe")

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def scan_with_windows_defender(file_path: str) -> dict[str, Any]:
    """
    Scan a file using Microsoft Defender locally.

    This is the local antivirus fallback used when Docker is unavailable
    or when Local Scan Mode is selected.
    """

    path = Path(file_path).resolve()
    mpcmdrun = _find_mpcmdrun()

    if mpcmdrun is None:
        return _base_av_result(
            "Microsoft Defender",
            "UNAVAILABLE",
            raw_output="MpCmdRun.exe could not be found on this computer.",
        )

    try:
        result = subprocess.run(
            [
                str(mpcmdrun),
                "-Scan",
                "-ScanType",
                "3",
                "-File",
                str(path),
                "-DisableRemediation",
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        output = (result.stdout or result.stderr or "").strip()
        lowered = output.lower()

        if result.returncode == 0:
            return _base_av_result(
                "Microsoft Defender",
                "CLEAN",
                raw_output=output,
            )

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

        return _base_av_result(
            "Microsoft Defender",
            "ERROR",
            raw_output=output or f"Microsoft Defender returned code {result.returncode}.",
        )

    except Exception as error:
        return _base_av_result(
            "Microsoft Defender",
            "ERROR",
            raw_output=str(error),
        )


def add_antivirus_result(
    scan_result: dict[str, Any],
    antivirus_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Add antivirus result into a normal Sentinel scan result.

    Important:
    If antivirus scanning fails or is blocked, the file should NOT be reported as SAFE.
    A failed antivirus scan means the result is incomplete.
    """

    scan_result["antivirus"] = antivirus_result

    findings = scan_result.get("findings", [])
    score = int(scan_result.get("score", 0))
    current_level = str(scan_result.get("level", "SAFE")).upper()

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

    scan_result["score"] = score
    scan_result["findings"] = findings
    scan_result["finding_count"] = len(findings)
    scan_result["level"] = current_level

    return scan_result