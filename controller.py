import os

from state import AppState
from backend.backend_api import load_alerts, load_history, safe_run_scan

try:
    from plyer import notification
except ImportError:
    notification = None


class Controller:
    def __init__(self, state: AppState) -> None:
        self.state = state
        self.refresh_from_database()

    def refresh_from_database(self) -> None:
        self.state.history = load_history()
        self.state.alerts = load_alerts()

    def select_file(self, path: str) -> None:
        self.state.selected_file = path
        self.state.status = "READY"
        self.state.current_scan = os.path.basename(path)
        self.state.progress = 0

    def start_scan(self) -> bool:
        if self.state.is_scanning:
            return False

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

        self.state.status = "SCANNING"
        self.state.progress = 0
        self.state.is_scanning = True
        self.state.current_scan = os.path.basename(self.state.selected_file)
        return True

    def set_progress(self, value: int) -> None:
        self.state.progress = value

    def finish_scan(self) -> None:
        if not self.state.selected_file:
            self.state.is_scanning = False
            self.state.status = "ERROR"
            return

        scan_mode = self.state.settings.get("scan_mode", "auto")
        result = safe_run_scan(self.state.selected_file, scan_mode=scan_mode)

        self.state.status = "COMPLETE"
        self.state.progress = 100
        self.state.is_scanning = False
        self.state.current_scan = f"{result['file']} (complete)"
        self.state.current_result = result

        self.refresh_from_database()

        if result["level"] in ["MEDIUM", "HIGH", "CRITICAL"]:
            self._send_notification(result)

    def update_setting(self, key: str, value) -> None:
        if key in self.state.settings:
            self.state.settings[key] = value

    def _send_notification(self, result: dict) -> None:
        if not self.state.settings.get("desktop_notifications", True):
            return

        if notification is None:
            return

        try:
            notification.notify(
                title=f"Sentinel Alert: {result['level']}",
                message=f"{result['file']} was flagged during scanning.",
                app_name="Sentinel",
                timeout=5,
            )
        except Exception:
            pass