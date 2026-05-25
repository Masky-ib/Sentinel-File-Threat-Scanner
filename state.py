class AppState:
    def __init__(self) -> None:
        # ===== CORE STATE =====
        self.selected_file = None
        self.status = "IDLE"
        self.progress = 0
        self.current_scan = "None"
        self.current_result = None
        self.is_scanning = False

        # ===== SETTINGS =====
        self.settings = {
            "default_scan_folder": "C:/Sentinel/logs",
            "theme": "Dark",
            "alert_retention": "Flagged scans only",
            "auto_scan": True,
            "desktop_notifications": True,

            # Scan execution mode:
            # "auto"   = try Docker first, fall back to local
            # "docker" = require Docker Sandbox Mode
            # "local"  = scan locally only
            "scan_mode": "auto",
        }

        # Loaded from SQLite by Controller.refresh_from_database().
        self.alerts = []
        self.history = []