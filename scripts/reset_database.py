"""Reset Sentinel's local SQLite database.

This script is a developer/testing utility.

It deletes:
    data/sentinel.db

Why this exists:
    During testing, the scan history and alert list can become cluttered with
    old test results. This script lets the developer reset the database and
    start with a clean scan history.

Important:
    This script should not run automatically when Sentinel starts.
    It should only be run manually when the developer intentionally wants to
    clear local scan history.
"""

from __future__ import annotations

from pathlib import Path


# reset_database.py lives inside:
#     scripts/reset_database.py
#
# parents[1] moves back to the main project folder:
#     sentinel_file_scanner_v4/
PROJECT_ROOT = Path(__file__).resolve().parents[1]


# Sentinel stores runtime scan history in:
#     data/sentinel.db
#
# This matches the DB_PATH used in backend/storage.py.
DB_PATH = PROJECT_ROOT / "data" / "sentinel.db"


def main() -> None:
    """Delete Sentinel's local database if it exists."""

    # Only delete the database file if it actually exists.
    # This avoids raising an error when the project has no database yet.
    if DB_PATH.exists():
        DB_PATH.unlink()
        print("Deleted data/sentinel.db")

    else:
        print("No database found.")


if __name__ == "__main__":
    main()