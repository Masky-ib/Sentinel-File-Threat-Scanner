"""Real Sentinel file scanner.

This module is Sentinel's local rule-based text scanner.

It accepts readable text-based files, applies regex-based security rules,
calculates a threat score, and returns structured results.

Important:
    This scanner does not execute files.
    It only reads file content as text and looks for suspicious indicators.

Binary files are handled cleanly instead of being scanned as garbage text.
Antivirus scanning is handled separately by antivirus_scanner.py.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .rules import FAILED_LOGIN_RULE_ID, SERVICE_CRASH_RULE_ID, RULES


# Maximum file size the text scanner will read.
#
# This protects the app from freezing or consuming too much memory when a very
# large file is selected.
MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024


# Maximum number of findings shown in the UI.
#
# The scanner may store more findings, but showing too many in the UI would make
# the results panel hard to read.
MAX_FINDINGS_FOR_UI = 40


# Encodings Sentinel tries when reading text files.
#
# Security logs and configuration files may not always be UTF-8.
# Trying a small set of common encodings makes the scanner more forgiving.
TEXT_ENCODINGS = ("utf-8", "utf-8-sig", "utf-16", "cp1252", "latin-1")


# Extensions Sentinel expects to be text-like.
#
# These are files the scanner can reasonably read line by line.
# They include logs, scripts, configs, structured text, and shell files.
TEXT_LIKE_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".md",
    ".py", ".js", ".ts", ".html", ".css", ".sql", ".ini", ".conf", ".cfg",
    ".ps1", ".bat", ".cmd", ".sh", ".dockerfile", ".env", ".properties",
}


# Extensions Sentinel treats as binary or non-text for the rule scanner.
#
# These files may still be scanned by antivirus, but they should not be read as
# normal text by this rule scanner.
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".bin", ".dat", ".zip", ".rar", ".7z", ".jpg", ".jpeg",
    ".png", ".gif", ".webp", ".mp3", ".mp4", ".avi", ".mov", ".pdf", ".docx",
    ".xlsx", ".pptx", ".sqlite", ".db",
}


def _looks_like_binary(sample: bytes) -> bool:
    """Estimate whether a file sample looks binary.

    Sentinel checks more than just the file extension because attackers can
    rename files.

    Example:
        malware.exe renamed to notes.txt

    This function uses two simple checks:
    1. Null bytes usually indicate binary data.
    2. A low printable-character ratio suggests non-text content.
    """

    # Empty content is not considered binary.
    if not sample:
        return False

    # Null bytes are a strong sign of binary data.
    if b"\x00" in sample:
        return True

    # Count bytes that look like normal printable text or common whitespace.
    printable = sum(byte in b"\n\r\t\b\f" or 32 <= byte <= 126 for byte in sample)

    # If less than 70% of the sample looks printable, treat it as binary.
    # This threshold is not perfect, but it prevents the scanner from trying to
    # process obvious non-text data.
    ratio = printable / len(sample)
    return ratio < 0.70


def _read_file_text(file_path: str) -> str:
    """Read a selected file as text after safety checks.

    This function validates:
    - the file exists
    - the path is a file
    - the file is not too large
    - the file does not look binary

    It then tries several common encodings and returns the text content.
    """

    path = Path(file_path)

    # Fail clearly if the user selected a file that no longer exists.
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Sentinel scans files, not folders.
    if not path.is_file():
        raise ValueError(f"Selected path is not a file: {file_path}")

    size = path.stat().st_size

    # Empty files are valid but contain no lines or findings.
    if size == 0:
        return ""

    # Avoid scanning huge files with the text scanner.
    # Large-file support can be added later with streaming, but this MVP keeps
    # scanning predictable and safe.
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError("File is too large for this scanner. Please select a file under 25 MB.")

    extension = path.suffix.lower()

    # Read a small sample first to detect binary-looking content.
    # This avoids loading the whole file before making a basic safety decision.
    sample = path.read_bytes()[:4096]

    # Reject known binary extensions and files that look binary by content.
    #
    # This rule scanner is designed for text-based indicators.
    # Binary files should be handled mainly by antivirus and future PE metadata
    # scanning instead.
    if extension in BINARY_EXTENSIONS or _looks_like_binary(sample):
        raise ValueError(
            "Unsupported binary or non-text file. Sentinel currently scans readable text-based files "
            "such as scripts, configuration files, JSON, CSV, TXT, and LOG files."
        )

    # Try strict decoding first.
    # Strict mode is useful because it helps detect when an encoding is wrong
    # instead of silently producing broken text.
    for encoding in TEXT_ENCODINGS:
        try:
            return path.read_text(encoding=encoding, errors="strict")

        except UnicodeDecodeError:
            # Try the next encoding if this one cannot decode the file.
            continue

        except Exception:
            # Some files may raise other read errors.
            # Continue to the next encoding before giving up.
            continue

    # Last-resort fallback.
    #
    # If all strict decoding attempts failed, ignore invalid UTF-8 characters so
    # Sentinel can still scan whatever readable text remains.
    return path.read_text(encoding="utf-8", errors="ignore")


def _score_to_level(score: int) -> str:
    """Convert a numeric threat score into a severity level.

    The score gives Sentinel a way to combine multiple lower-severity findings.

    Example:
        One medium finding may stay MEDIUM.
        Several medium/high findings can push the final result higher.
    """

    if score >= 170:
        return "CRITICAL"

    if score >= 55:
        return "HIGH"

    if score >= 20:
        return "MEDIUM"

    return "SAFE"


def _highest_level(levels: list[str], score: int) -> str:
    """Choose the final threat level.

    Sentinel considers both:
    - the highest individual rule severity
    - the total score

    Why both are used:
        A single CRITICAL rule should stay CRITICAL even if the score alone is
        not very high.

        Many smaller findings should also be able to raise the overall result
        if the total score becomes significant.
    """

    order = {"SAFE": 0, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    # Convert accumulated score into a severity.
    score_level = _score_to_level(score)

    # Return whichever is higher: matched rule severity or score-derived severity.
    return max(levels + [score_level], key=lambda value: order.get(str(value).upper(), 0))


def scan_file(file_path: str) -> dict[str, Any]:
    """Scan a selected file and return structured detection results.

    This function:
    1. Reads the file safely as text.
    2. Applies every detection rule to every non-empty line.
    3. Builds structured findings.
    4. Adds aggregate detections for repeated failed logins and service crashes.
    5. Calculates a final score and threat level.
    """

    # Read the file content after size, type, and encoding checks.
    text = _read_file_text(file_path)

    # Split into lines because Sentinel reports the line number for each finding.
    lines = text.splitlines()

    findings: list[dict[str, Any]] = []
    matched_levels: list[str] = []
    score = 0

    # These counters support aggregate detections.
    # A single failed login may be normal.
    # Many failed logins in one file may indicate brute-force activity.
    failed_login_count = 0

    # Repeated service crashes can indicate instability, tampering, or failed exploitation.
    service_crash_count = 0

    # Compile regex patterns once before scanning.
    # This is cleaner and faster than compiling the same patterns for every line.
    compiled_rules = [
        (rule, [re.compile(pattern, re.IGNORECASE) for pattern in rule["patterns"]])
        for rule in RULES
    ]

    # Scan the file line by line.
    for line_number, line in enumerate(lines, start=1):
        # Skip blank lines because they cannot meaningfully match detection rules.
        if not line.strip():
            continue

        for rule, patterns in compiled_rules:
            # Find the first matching pattern for this rule on this line.
            # Sentinel records one finding per rule per line, not one finding for
            # every pattern inside the same rule.
            matched_pattern = next(
                (pattern.pattern for pattern in patterns if pattern.search(line)),
                None,
            )

            if matched_pattern is None:
                continue

            # Count specific rule hits for aggregate/correlation logic.
            if rule["id"] == FAILED_LOGIN_RULE_ID:
                failed_login_count += 1

            if rule["id"] == SERVICE_CRASH_RULE_ID:
                service_crash_count += 1

            # Add the rule's score to the total threat score.
            score += int(rule["score"])

            # Track severity so one severe rule can influence the final level.
            matched_levels.append(str(rule["severity"]).upper())

            # Store a structured finding.
            #
            # The UI later converts this into readable text, while the database
            # can still store the structured data.
            findings.append(
                {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "line_number": str(line_number),
                    "message": rule["explanation"],

                    # Evidence is shortened so a huge line does not overwhelm
                    # the UI or database.
                    "evidence": line.strip()[:500],

                    # Store the regex that matched to make detections explainable.
                    "matched_pattern": matched_pattern,
                }
            )

    # Aggregate detection:
    # repeated failed login events.
    #
    # The threshold is 5 because one or two failures can be normal, but repeated
    # failures in the same file are more suspicious.
    if failed_login_count >= 5:
        score += 35
        matched_levels.append("HIGH")

        findings.insert(
            0,
            {
                "rule_id": "AUTH_FAILED_LOGIN_BURST",
                "name": "Failed login burst",
                "severity": "HIGH",
                "category": "Authentication",
                "line_number": "-",
                "message": f"{failed_login_count} failed login events were detected in one file.",
                "evidence": "Repeated authentication failures can indicate brute-force activity.",
                "matched_pattern": "aggregate count",
            },
        )

    # Aggregate detection:
    # repeated service crash or failure events.
    #
    # The threshold is 3 because repeated crashes are more meaningful than a
    # single isolated crash.
    if service_crash_count >= 3:
        score += 30
        matched_levels.append("HIGH")

        findings.insert(
            0,
            {
                "rule_id": "SERVICE_REPEATED_CRASH",
                "name": "Repeated service crash",
                "severity": "HIGH",
                "category": "System Stability",
                "line_number": "-",
                "message": f"{service_crash_count} service crash/failure events were detected in one file.",
                "evidence": "Repeated crashes can indicate instability, tampering, or failed exploitation.",
                "matched_pattern": "aggregate count",
            },
        )

    # If no findings exist, the text rule scanner considers the file SAFE.
    # Antivirus or other layers may still change the final result later.
    level = _highest_level(matched_levels, score) if findings else "SAFE"

    extension = Path(file_path).suffix.lower() or "no extension"

    # Return a structured result that other backend modules can merge, save,
    # or convert for the UI.
    return {
        "file": os.path.basename(file_path),
        "file_path": str(Path(file_path).resolve()),
        "file_type": extension,
        "level": level,
        "score": score,
        "total_lines": len(lines),
        "finding_count": len(findings),
        "findings": findings,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def format_findings_for_frontend(scan_result: dict[str, Any]) -> list[str]:
    """Convert structured scan findings into readable UI strings.

    The scanner returns structured dictionaries because they are better for:
    - storage
    - future reporting
    - debugging
    - automated processing

    The Tkinter UI needs simple readable strings.
    This function performs that conversion.
    """

    # SAFE results still include file type and scan size so the user knows the
    # scan actually happened.
    if scan_result["level"] == "SAFE" or not scan_result["findings"]:
        return [
            "No suspicious indicators detected.",
            f"File type: {scan_result.get('file_type', 'unknown')}",
            f"Scanned {scan_result['total_lines']} line(s).",
            "File scan completed successfully.",
        ]

    # Start with summary lines before showing individual findings.
    formatted = [
        f"Threat score: {scan_result['score']}",
        f"File type: {scan_result.get('file_type', 'unknown')}",
        f"Scanned {scan_result['total_lines']} line(s).",
        f"Detected {scan_result['finding_count']} finding(s).",
    ]

    # Limit displayed findings so the UI remains readable.
    # Full results can still be stored in the database.
    for finding in scan_result["findings"][:MAX_FINDINGS_FOR_UI]:
        formatted.append(
            f"[{finding['severity']}] {finding['name']} — line {finding['line_number']}: {finding['message']}"
        )

        evidence = finding.get("evidence")

        if evidence:
            formatted.append(f"Evidence: {evidence}")

    # Let the user know if the UI is showing a truncated list.
    remaining = scan_result["finding_count"] - MAX_FINDINGS_FOR_UI

    if remaining > 0:
        formatted.append(f"{remaining} additional finding(s) stored in the database.")

    return formatted