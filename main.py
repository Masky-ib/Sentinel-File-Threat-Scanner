"""Sentinel desktop application entry point.

This file exists so the app can be started with:

    python main.py

It imports the real UI startup function from sentinel_ui_skeleton.py and runs it.

Keeping this file small is intentional:
- main.py starts the app
- sentinel_ui_skeleton.py builds the UI
- controller.py manages state and scan flow
- backend/ handles scanning and storage
"""

from __future__ import annotations

from sentinel_ui_skeleton import main


if __name__ == "__main__":
    # Start the Sentinel Tkinter desktop application.
    main()