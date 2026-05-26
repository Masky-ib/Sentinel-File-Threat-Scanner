"""Shared application state for Sentinel.

This module contains the AppState class.

AppState stores the values that the UI and controller share with each other.

Important:
    AppState does not scan files.
    AppState does not talk to Docker.
    AppState does not save to SQLite directly.

It only stores the current state of the application so the UI can display it.
"""


class AppState:
    """Store the current state of the Sentinel desktop application."""

    def __init__(self) -> None:
        """Create the default application state.

        These values are used when Sentinel first opens.
        The controller updates them as the user selects files, starts scans,
        finishes scans, changes settings, and loads history from SQLite.
        """

        # ===== CORE STATE =====

        # Path of the file currently selected by the user.
        # None means no file has been selected yet.
        self.selected_file = None

        # Current app status shown in the sidebar and dashboard.
        #
        # Common values:
        # - IDLE
        # - READY
        # - SCANNING
        # - COMPLETE
        # - ERROR
        self.status = "IDLE"

        # Progress bar value.
        # This is mainly used by the UI animation.
        self.progress = 0

        # Human-readable name of the file currently being scanned.
        self.current_scan = "None"

        # Most recent scan result returned by the backend.
        # None means no scan result is available yet.
        self.current_result = None

        # True while a scan is in progress.
        # This prevents the UI from starting multiple scans at the same time.
        self.is_scanning = False

        # ===== SETTINGS =====

        # User-facing settings used by the UI and controller.
        #
        # These currently live in memory only.
        # If persistent settings are needed later, this dictionary can be saved
        # to a JSON file or SQLite table.
        self.settings = {
            # Default folder shown in the file picker.
            # This can be changed later if the app gets a full settings system.
            "default_scan_folder": "C:/Sentinel/logs",

            # Current visual theme.
            # The UI currently uses the dark theme.
            "theme": "Dark",

            # Describes what kind of alerts should be shown/kept.
            "alert_retention": "Flagged scans only",

            # If enabled, Sentinel starts scanning after a file is dropped.
            "auto_scan": True,

            # If enabled, Sentinel shows desktop notifications for flagged files.
            "desktop_notifications": True,

            # Scan execution mode:
            #
            # "auto":
            #     Try Docker Sandbox Mode first.
            #     Fall back to Local Scan Mode if Docker is unavailable or fails.
            #
            # "docker":
            #     Require Docker Sandbox Mode.
            #     Do not silently fall back to local scanning.
            #
            # "local":
            #     Scan locally only.
            #     Use Microsoft Defender when available.
            "scan_mode": "auto",
        }

        # ===== DATABASE-BACKED UI DATA =====

        # Recent alert-level scans loaded from SQLite by:
        #     Controller.refresh_from_database()
        self.alerts = []

        # Recent scan history loaded from SQLite by:
        #     Controller.refresh_from_database()
        self.history = []