from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
db = PROJECT_ROOT / "data" / "sentinel.db"
if db.exists():
    db.unlink()
    print("Deleted data/sentinel.db")
else:
    print("No database found.")
