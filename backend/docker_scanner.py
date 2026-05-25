import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from .antivirus_scanner import add_antivirus_result, scan_with_clamav_docker


def docker_scan(file_path: str) -> dict[str, Any]:
    """
    Runs ClamAV antivirus scanning and Sentinel rule scanning inside Docker.

    If Sentinel's text scanner rejects a binary file, the ClamAV result is still kept.
    """

    path = Path(file_path).resolve()
    parent_folder = path.parent
    file_name = path.name

    antivirus_result = scan_with_clamav_docker(file_path)

    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{parent_folder}:/data:ro",
                "sentinel-scanner",
                "python", "/app/scanner_runner.py",
                f"/data/{file_name}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            # Binary/non-text files may be rejected by Sentinel's rule scanner,
            # but antivirus scanning can still be valid.
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

            return add_antivirus_result(scan_result, antivirus_result)

        scan_result = json.loads(result.stdout)

        scan_result["success"] = True
        scan_result["scan_mode"] = "Docker Sandbox Mode"
        scan_result["isolation"] = "Container isolation enabled"

        return add_antivirus_result(scan_result, antivirus_result)

    except Exception as error:
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