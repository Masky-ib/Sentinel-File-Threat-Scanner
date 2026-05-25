from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.backend_api import safe_run_scan

samples = [
    PROJECT_ROOT / "sample_files" / "safe_document.md",
    PROJECT_ROOT / "sample_files" / "suspicious_powershell.ps1",
    PROJECT_ROOT / "sample_files" / "suspicious_batch.bat",
    PROJECT_ROOT / "sample_files" / "config_with_secret.json",
]

for sample in samples:
    result = safe_run_scan(str(sample))
    print("=" * 70)
    print(f"File: {result['file']}")
    print(f"Level: {result['level']}")
    print(f"Score: {result.get('score')}")
    print("Findings:")
    for finding in result["findings"][:8]:
        print(f"- {finding}")
