"""Docker-based scanning for Sentinel.

This module runs Sentinel's Docker Sandbox Mode.

Docker Sandbox Mode uses two separate scanning layers:

1. ClamAV antivirus scan
    - Runs through the ClamAV Docker image.
    - Detects known malware signatures.

2. Sentinel rule-based scan
    - Runs through the custom sentinel-scanner Docker image.
    - Detects suspicious commands, URLs, privilege manipulation, and other
      text/script-based indicators.

The results from both layers are merged into one final scan result.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from .antivirus_scanner import add_antivirus_result, scan_with_clamav_docker


def docker_scan(file_path: str) -> dict[str, Any]:
    """Run ClamAV antivirus scanning and Sentinel rule scanning inside Docker.

    This is used when Docker Sandbox Mode is selected, or when Auto Mode chooses
    Docker because it is available.

    Important design choice:
        The antivirus scan runs first and is kept even if the Sentinel text/rule
        scanner cannot read the file.

    Why?
        Binary files, executables, PDFs, or other non-text files may be rejected
        by Sentinel's rule scanner, but antivirus scanning can still produce a
        useful result.
    """

    # Resolve the selected file path so Docker receives a stable absolute path.
    path = Path(file_path).resolve()

    # Docker mounts the parent folder into the container, not the file alone.
    # The scanner then receives the selected filename inside that mounted folder.
    parent_folder = path.parent
    file_name = path.name

    # Run the antivirus layer first.
    # This result is later merged into the final Sentinel scan result.
    antivirus_result = scan_with_clamav_docker(file_path)

    try:
        # Run Sentinel's rule-based scanner inside the custom Docker image.
        #
        # The host folder is mounted read-only as /data.
        # Read-only mode is intentional:
        # the scanner container should inspect the file, not modify it.
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",

                # Mount the selected file's folder into the container as read-only.
                "-v",
                f"{parent_folder}:/data:ro",

                # Custom image built from docker_scanner_image/Dockerfile.
                "sentinel-scanner",

                # scanner_runner.py is the Docker-safe entry point.
                # It runs the actual scanner and prints JSON to stdout.
                "python",
                "/app/scanner_runner.py",

                # Path to the selected file from inside the container.
                f"/data/{file_name}",
            ],
            capture_output=True,
            text=True,

            # The rule scanner should be fairly quick.
            # If it hangs, Sentinel treats the Docker scan as failed.
            timeout=60,
        )

        # A non-zero return code means the Sentinel rule scanner failed.
        #
        # This does not automatically mean the whole scan failed, because the
        # antivirus result may still be valid.
        if result.returncode != 0:
            # Binary or non-text files may be rejected by Sentinel's rule scanner.
            # In that case, Sentinel still returns a scan result using the
            # antivirus output instead of throwing everything away.
            scan_result = {
                "success": True,
                "file": path.name,
                "file_path": str(path),
                "file_type": path.suffix.lower() or "no extension",
                "level": "SAFE",
                "score": 0,
                "total_lines": 0,
                "finding_count": 0,
                "findings": [],
                "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_mode": "Docker Sandbox Mode",
                "isolation": "Container isolation enabled",
                "text_scanner_note": result.stderr.strip() or result.stdout.strip(),
            }

            # Merge ClamAV's result into the fallback scan result.
            # If ClamAV detected malware, this will raise the severity to CRITICAL.
            # If ClamAV failed, this will mark the scan as incomplete instead of safe.
            return add_antivirus_result(scan_result, antivirus_result)

        # The rule scanner prints JSON to stdout.
        # Convert it back into a Python dictionary so Sentinel can merge metadata.
        scan_result = json.loads(result.stdout)

        # Mark this result as successful and describe the execution environment.
        scan_result["success"] = True
        scan_result["scan_mode"] = "Docker Sandbox Mode"
        scan_result["isolation"] = "Container isolation enabled"

        # Merge the antivirus layer into the rule-based result.
        return add_antivirus_result(scan_result, antivirus_result)

    except Exception as error:
        # If Docker itself fails, return a structured failure result.
        #
        # The scan router decides what happens next:
        # - Docker-only mode will show an error-style result.
        # - Auto mode may fall back to local scanning.
        return {
            "success": False,
            "file": path.name,
            "file_path": str(path),
            "level": "--",
            "score": 0,
            "findings": [],
            "scan_mode": "Docker Sandbox Mode",
            "isolation": "Container isolation attempted",
            "error": str(error),
        }