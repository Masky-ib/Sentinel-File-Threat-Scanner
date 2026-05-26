"""Docker scanner runner for Sentinel.

This file is the entry point used inside the custom sentinel-scanner Docker image.

The host desktop app runs this container and passes in a mounted file path.

Example inside the container:
    python /app/scanner_runner.py /data/example.log

The runner then:
1. Receives the file path from Docker.
2. Calls Sentinel's rule-based scanner.
3. Prints the scan result as JSON.
4. Exits with code 0 on success or code 1 on failure.

Why this file exists:
    docker_scanner.py runs outside Docker on the host machine.
    scanner_runner.py runs inside Docker.

This separation keeps the Docker container simple and makes communication between
the host app and the container predictable.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

from backend.scanner import scan_file


def main() -> None:
    """Run the Sentinel scanner inside the Docker container.

    The selected file path is expected as the first command-line argument.

    Docker mounts the user's selected file folder into the container, so the path
    received here is usually something like:
        /data/suspicious_batch.bat

    The result must be printed as JSON because docker_scanner.py reads stdout
    and converts it back into a Python dictionary.
    """

    # The host application should always pass a file path.
    # If it does not, return a structured JSON error instead of crashing.
    if len(sys.argv) < 2:
        print(
            json.dumps(
                {
                    "success": False,
                    "error": "No file path was provided to the Docker scanner.",
                }
            )
        )
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        # Run Sentinel's normal rule-based scanner inside the container.
        # This scanner only reads the file; it does not execute it.
        result = scan_file(file_path)

        # Print JSON to stdout.
        # The host-side docker_scanner.py captures this output.
        print(json.dumps(result))

        # Exit code 0 tells the host app that the container scan succeeded.
        sys.exit(0)

    except Exception as error:
        # If the scanner fails, still return JSON.
        # This is important because the host app expects machine-readable output.
        path = Path(file_path)

        print(
            json.dumps(
                {
                    "success": False,
                    "file": os.path.basename(file_path),
                    "file_path": file_path,
                    "file_type": path.suffix.lower() or "no extension",
                    "level": "--",
                    "score": 0,
                    "total_lines": 0,
                    "finding_count": 0,
                    "findings": [],
                    "error": str(error),
                    "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
        )

        # Exit code 1 tells docker_scanner.py that the rule scanner failed.
        # The host app may still keep the ClamAV antivirus result.
        sys.exit(1)


if __name__ == "__main__":
    main()