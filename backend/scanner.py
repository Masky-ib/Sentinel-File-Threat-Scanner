"""Real Sentinel file scanner.

This scanner accepts any readable text-based file, applies rule-based security
detections, calculates a threat score, and returns structured results.
Binary files are handled cleanly instead of being scanned as garbage text.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .rules import FAILED_LOGIN_RULE_ID, SERVICE_CRASH_RULE_ID, RULES

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024
MAX_FINDINGS_FOR_UI = 40
TEXT_ENCODINGS = ("utf-8", "utf-8-sig", "utf-16", "cp1252", "latin-1")

TEXT_LIKE_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".md",
    ".py", ".js", ".ts", ".html", ".css", ".sql", ".ini", ".conf", ".cfg",
    ".ps1", ".bat", ".cmd", ".sh", ".dockerfile", ".env", ".properties",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".bin", ".dat", ".zip", ".rar", ".7z", ".jpg", ".jpeg",
    ".png", ".gif", ".webp", ".mp3", ".mp4", ".avi", ".mov", ".pdf", ".docx",
    ".xlsx", ".pptx", ".sqlite", ".db",
}


def _looks_like_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    printable = sum(byte in b"\n\r\t\b\f" or 32 <= byte <= 126 for byte in sample)
    ratio = printable / len(sample)
    return ratio < 0.70


def _read_file_text(file_path: str) -> str:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Selected path is not a file: {file_path}")

    size = path.stat().st_size
    if size == 0:
        return ""
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError("File is too large for this scanner. Please select a file under 25 MB.")

    extension = path.suffix.lower()
    sample = path.read_bytes()[:4096]

    if extension in BINARY_EXTENSIONS or _looks_like_binary(sample):
        raise ValueError(
            "Unsupported binary or non-text file. Sentinel currently scans readable text-based files "
            "such as scripts, configuration files, JSON, CSV, TXT, and LOG files."
        )

    for encoding in TEXT_ENCODINGS:
        try:
            return path.read_text(encoding=encoding, errors="strict")
        except UnicodeDecodeError:
            continue
        except Exception:
            continue

    return path.read_text(encoding="utf-8", errors="ignore")


def _score_to_level(score: int) -> str:
    if score >= 170:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "SAFE"


def _highest_level(levels: list[str], score: int) -> str:
    order = {"SAFE": 0, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    score_level = _score_to_level(score)
    return max(levels + [score_level], key=lambda value: order.get(str(value).upper(), 0))


def scan_file(file_path: str) -> dict[str, Any]:
    """Scan a selected file and return structured detection results."""

    text = _read_file_text(file_path)
    lines = text.splitlines()

    findings: list[dict[str, Any]] = []
    matched_levels: list[str] = []
    score = 0
    failed_login_count = 0
    service_crash_count = 0

    compiled_rules = [
        (rule, [re.compile(pattern, re.IGNORECASE) for pattern in rule["patterns"]])
        for rule in RULES
    ]

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        for rule, patterns in compiled_rules:
            matched_pattern = next((pattern.pattern for pattern in patterns if pattern.search(line)), None)
            if matched_pattern is None:
                continue

            if rule["id"] == FAILED_LOGIN_RULE_ID:
                failed_login_count += 1
            if rule["id"] == SERVICE_CRASH_RULE_ID:
                service_crash_count += 1

            score += int(rule["score"])
            matched_levels.append(str(rule["severity"]).upper())
            findings.append(
                {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "line_number": str(line_number),
                    "message": rule["explanation"],
                    "evidence": line.strip()[:500],
                    "matched_pattern": matched_pattern,
                }
            )

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

    level = _highest_level(matched_levels, score) if findings else "SAFE"
    extension = Path(file_path).suffix.lower() or "no extension"

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
    """Convert structured findings into readable UI strings."""

    if scan_result["level"] == "SAFE" or not scan_result["findings"]:
        return [
            "No suspicious indicators detected.",
            f"File type: {scan_result.get('file_type', 'unknown')}",
            f"Scanned {scan_result['total_lines']} line(s).",
            "File scan completed successfully.",
        ]

    formatted = [
        f"Threat score: {scan_result['score']}",
        f"File type: {scan_result.get('file_type', 'unknown')}",
        f"Scanned {scan_result['total_lines']} line(s).",
        f"Detected {scan_result['finding_count']} finding(s).",
    ]

    for finding in scan_result["findings"][:MAX_FINDINGS_FOR_UI]:
        formatted.append(
            f"[{finding['severity']}] {finding['name']} — line {finding['line_number']}: {finding['message']}"
        )
        evidence = finding.get("evidence")
        if evidence:
            formatted.append(f"Evidence: {evidence}")

    remaining = scan_result["finding_count"] - MAX_FINDINGS_FOR_UI
    if remaining > 0:
        formatted.append(f"{remaining} additional finding(s) stored in the database.")

    return formatted
