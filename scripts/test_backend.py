"""Quick backend scan test for Sentinel.

This script is a developer/testing utility.

It runs several sample files through Sentinel's backend scan API without
opening the desktop UI.

Why this exists:
    During development, it is useful to test the scanner quickly from the
    terminal. This script confirms that backend scanning, rule detection,
    storage, and result formatting are working.

Important:
    This script is not part of the normal user workflow.
    Normal users scan files through the Sentinel desktop UI.
"""

from __future__ import annotations

from pathlib import Path
import sys


# test_backend.py lives inside:
#     scripts/test_backend.py
#
# parents[1] moves back to the main project folder:
#     sentinel_file_scanner_v4/
PROJECT_ROOT = Path(__file__).resolve().parents[1]


# Add the project root to Python's import path.
#
# This lets the script import:
#     backend.backend_api
#
# even though the script is being run from inside the scripts/ folder.
sys.path.insert(0, str(PROJECT_ROOT))

from backend.backend_api import safe_run_scan


# Sample files used to test different scan outcomes.
#
# safe_document.md:
#     Expected to be safe.
#
# suspicious_powershell.ps1:
#     Expected to trigger PowerShell-related detections.
#
# suspicious_batch.bat:
#     Expected to trigger command-line and account manipulation detections.
#
# config_with_secret.json:
#     Expected to trigger exposed secret detection.
samples = [
    PROJECT_ROOT / "sample_files" / "safe_document.md",
    PROJECT_ROOT / "sample_files" / "suspicious_powershell.ps1",
    PROJECT_ROOT / "sample_files" / "suspicious_batch.bat",
    PROJECT_ROOT / "sample_files" / "config_with_secret.json",
]


def main() -> None:
    """Run the sample files through Sentinel's backend scanner."""

    for sample in samples:
        # safe_run_scan is used instead of run_scan so the test script receives
        # a readable error result instead of crashing if one sample file is
        # missing or blocked.
        result = safe_run_scan(str(sample))

        print("=" * 70)
        print(f"File: {result['file']}")
        print(f"Level: {result['level']}")
        print(f"Score: {result.get('score')}")
        print("Findings:")

        # Only print the first few findings so terminal output stays readable.
        for finding in result["findings"][:8]:
            print(f"- {finding}")


if __name__ == "__main__":
    main()