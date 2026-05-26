"""Application controller for the Sentinel desktop UI.

The controller sits between:
- the Tkinter user interface
- the shared AppState object
- the backend scanning API

The UI should mostly handle layout and button clicks.
The backend should handle actual scanning.
The controller connects those two sides together.

Controller responsibilities:
- remember which file the user selected
- start and finish scans
- update status/progress values
- refresh scan history and alerts from SQLite
- send optional desktop notifications for important results
- update user settings
"""

from __future__ import annotations

import os
from typing import Any

from state import AppState
from backend.backend_api import load_alerts, load_history, safe_run_scan
from backend.notifications import send_desktop_notification


class Controller:
    """Coordinate UI actions, application state, and backend scan calls."""

    def __init__(self, state: AppState) -> None:
        """Create the controller and load saved scan data.

        The state object is shared with the UI.
        The controller changes state values, and the UI reads those values when
        refreshing the screen.
        """

        self.state = state

        # Load previous scan history and alerts when the app starts.
        # This lets Sentinel remember old scans from the SQLite database.
        self.refresh_from_database()

    def refresh_from_database(self) -> None:
        """Reload scan history and recent alerts from local SQLite storage."""

        # These backend API functions return UI-friendly data.
        self.state.history = load_history()
        self.state.alerts = load_alerts()

    def select_file(self, path: str) -> None:
        """Store the selected file path and prepare the UI for scanning.

        This is called when the user chooses a file with Browse or drag-and-drop.
        """

        self.state.selected_file = path
        self.state.status = "READY"
        self.state.current_scan = os.path.basename(path)
        self.state.progress = 0

    def start_scan(self) -> bool:
        """Prepare Sentinel to start scanning.

        Returns:
            True:
                The scan can continue.

            False:
                The scan should not start.

        This function does not run the backend scan itself.
        It only validates state and marks the app as scanning.
        The UI animation/progress loop calls finish_scan() afterward.
        """

        # Prevent two scans from starting at the same time.
        # This avoids state corruption and confusing UI output.
        if self.state.is_scanning:
            return False

        # If the user pressed Scan without choosing a file, show a clean error
        # in the results panel instead of crashing or doing nothing.
        if not self.state.selected_file:
            self.state.status = "ERROR"
            self.state.current_scan = "None"
            self.state.current_result = {
                "file": None,
                "level": "--",
                "findings": [
                    "No file selected.",
                    "Choose a file with Browse or drag and drop a file into the upload area.",
                ],
                "time": "",
            }
            return False

        # Mark the app as actively scanning.
        # The UI reads these values to disable buttons and animate progress.
        self.state.status = "SCANNING"
        self.state.progress = 0
        self.state.is_scanning = True
        self.state.current_scan = os.path.basename(self.state.selected_file)

        return True

    def set_progress(self, value: int) -> None:
        """Update the scan progress value used by the UI progress bar."""

        self.state.progress = value

    def finish_scan(self) -> None:
        """Run the actual backend scan and update the UI state with the result.

        This is called after the UI progress animation completes.

        The actual scan is performed through safe_run_scan(), which prevents
        unexpected backend errors from crashing the desktop app.
        """

        # If the selected file somehow disappeared from state, stop safely.
        if not self.state.selected_file:
            self.state.is_scanning = False
            self.state.status = "ERROR"
            return

        # Read the current scan mode from settings.
        # Possible values:
        # - auto
        # - docker
        # - local
        #
        # The scan router decides what each mode actually does.
        scan_mode = self.state.settings.get("scan_mode", "auto")

        # Run the selected file through the backend API.
        # This may use Docker, local scanning, antivirus, archive scanning,
        # and SQLite storage depending on the selected mode and file type.
        result = safe_run_scan(self.state.selected_file, scan_mode=scan_mode)

        # Update application state so the UI can show the completed result.
        self.state.status = "COMPLETE"
        self.state.progress = 100
        self.state.is_scanning = False
        self.state.current_scan = f"{result['file']} (complete)"
        self.state.current_result = result

        # Reload history and alerts after saving the scan.
        # This keeps the dashboard and scan history page up to date.
        self.refresh_from_database()

        # Send a desktop notification only for results that deserve attention.
        if result["level"] in ["MEDIUM", "HIGH", "CRITICAL"]:
            self._send_notification(result)

    def update_setting(self, key: str, value: Any) -> None:
        """Update one application setting in memory.

        Settings currently live in AppState.
        This keeps the UI simple because checkboxes/radio buttons can call this
        method without needing to know how state is stored.
        """

        # Only update known settings.
        # This prevents accidental creation of misspelled setting keys.
        if key in self.state.settings:
            self.state.settings[key] = value

    def _send_notification(self, result: dict[str, Any]) -> None:
        """Send a desktop alert for suspicious scan results.

        Notifications are optional.
        If the user disables desktop notifications, Sentinel still scans and
        displays results normally inside the app.
        """

        # Respect the user's notification setting.
        if not self.state.settings.get("desktop_notifications", True):
            return

        # Notification errors are handled inside send_desktop_notification().
        # This means a notification failure cannot break scanning.
        send_desktop_notification(
            title=f"Sentinel Alert: {result['level']}",
            message=f"{result['file']} was flagged during scanning.",
        )