from __future__ import annotations

import json
import os
import sys
from datetime import datetime

from backend.scanner import scan_file


def main() -> None:
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
        result = scan_file(file_path)
        print(json.dumps(result))
        sys.exit(0)

    except Exception as error:
        print(
            json.dumps(
                {
                    "success": False,
                    "file": os.path.basename(file_path),
                    "file_path": file_path,
                    "level": "--",
                    "score": 0,
                    "findings": [],
                    "error": str(error),
                    "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
        )
        sys.exit(1)


if __name__ == "__main__":
    main()