"""Tkinter desktop UI for Sentinel.

This module builds the main Sentinel desktop interface.

The UI is responsible for:
- showing the dashboard
- allowing file selection by Browse or drag-and-drop
- displaying scan results
- showing recent alerts
- showing scan history
- showing the Threat Guide page
- showing settings such as scan mode and notifications

Important separation:
    This file should not contain detection logic.

The UI talks to controller.py.
The controller talks to backend/backend_api.py.
The backend handles scanning, Docker, antivirus, archives, and storage.

This keeps the visual interface separate from the actual security logic.
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, ttk

try:
    # tkinterdnd2 adds drag-and-drop support to Tkinter.
    # Normal Tkinter does not support dragging files from Windows Explorer
    # into the app by default.
    from tkinterdnd2 import DND_FILES, TkinterDnD

    DND_AVAILABLE = True

except ImportError:
    # Drag-and-drop is optional.
    # If tkinterdnd2 is not installed, the app still works through Browse.
    DND_FILES = None
    TkinterDnD = None
    DND_AVAILABLE = False

from controller import Controller
from state import AppState


class SentinelUI:
    """Main Sentinel desktop user interface."""

    def __init__(self, root: tk.Tk, state: AppState, controller: Controller) -> None:
        """Create and initialize the Sentinel UI.

        Args:
            root:
                The Tkinter root window.

            state:
                Shared application state object.

            controller:
                Controller object that handles scan actions and state updates.
        """

        self.root = root
        self.state = state
        self.controller = controller

        # Basic app window setup.
        self.root.title("Sentinel")
        self.root.geometry("1100x700")
        self.root.minsize(1000, 650)
        self.root.configure(bg="#0f172a")

        # Track which sidebar tab is currently active.
        self.current_tab = "Dashboard"

        # Store references to dynamic widgets that need to be updated later.
        self.nav_buttons = {}
        self.content_frame = None
        self.sidebar_status_label = None
        self.dashboard_widgets = {}
        self.settings_vars = {}

        # Central color palette for the UI.
        # Keeping colors in one dictionary makes the app easier to restyle later.
        self.colors = {
            "bg": "#0f172a",
            "panel": "#1e293b",
            "panel_alt": "#273449",
            "border": "#334155",
            "text": "#e2e8f0",
            "muted": "#94a3b8",
            "accent": "#38bdf8",
            "safe": "#22c55e",
            "medium": "#f59e0b",
            "high": "#f97316",
            "critical": "#ef4444",
            "button_dark": "#223047",
            "row_bg": "#162235",
            "row_hover": "#1d2c44",
        }

        self._configure_ttk_style()
        self._build_layout()
        self._bind_shortcuts()

        # Show the dashboard first when the app opens.
        self.show_dashboard()

    def _bind_shortcuts(self) -> None:
        """Bind keyboard shortcuts for common actions."""

        # Ctrl+O opens the file picker.
        self.root.bind("<Control-o>", lambda _e: self.browse_file())

        # Ctrl+Enter starts a scan.
        self.root.bind("<Control-Return>", lambda _e: self.start_scan())

    def _configure_ttk_style(self) -> None:
        """Configure ttk widget styles used by the app.

        Tkinter has two widget systems:
        - normal tk widgets
        - themed ttk widgets

        The progress bar is a ttk widget, so its colors are configured here.
        """

        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Sentinel.Horizontal.TProgressbar",
            troughcolor=self.colors["panel_alt"],
            background=self.colors["accent"],
            bordercolor=self.colors["border"],
            lightcolor=self.colors["accent"],
            darkcolor=self.colors["accent"],
            thickness=16,
        )

    def _build_layout(self) -> None:
        """Create the main application layout.

        The app has two main areas:
        - left sidebar navigation
        - right content area
        """

        # The root window uses a grid layout:
        # column 0 = sidebar
        # column 1 = main content
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self.sidebar = tk.Frame(self.root, bg="#111827", width=220)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        # Prevent the sidebar from resizing based on its children.
        self.sidebar.grid_propagate(False)

        self.main_area = tk.Frame(self.root, bg=self.colors["bg"])
        self.main_area.grid(row=0, column=1, sticky="nsew")
        self.main_area.grid_rowconfigure(0, weight=1)
        self.main_area.grid_columnconfigure(0, weight=1)

        self._build_sidebar()

        # content_frame is where each page is drawn.
        # When switching tabs, this frame is cleared and rebuilt.
        self.content_frame = tk.Frame(self.main_area, bg=self.colors["bg"])
        self.content_frame.grid(row=0, column=0, sticky="nsew", padx=18, pady=18)

    def _build_sidebar(self) -> None:
        """Build the left navigation sidebar."""

        logo_wrap = tk.Frame(self.sidebar, bg="#111827")
        logo_wrap.pack(fill="x", padx=20, pady=(24, 14))

        tk.Label(
            logo_wrap,
            text="SENTINEL",
            bg="#111827",
            fg=self.colors["accent"],
            font=("Segoe UI", 20, "bold"),
            anchor="w",
        ).pack(fill="x")

        tk.Label(
            logo_wrap,
            text="File Threat Analysis Console",
            bg="#111827",
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x", pady=(4, 0))

        divider = tk.Frame(self.sidebar, bg="#1f2937", height=1)
        divider.pack(fill="x", padx=18, pady=(8, 18))

        # Sidebar page list.
        # Each button calls the method that rebuilds the content area.
        nav_items = [
            ("Dashboard", self.show_dashboard),
            ("Scan History", self.show_history),
            ("Threat Guide", self.show_threat_guide),
            ("Settings", self.show_settings),
        ]

        for name, command in nav_items:
            button = tk.Button(
                self.sidebar,
                text=name,
                command=command,
                relief="flat",
                bd=0,
                anchor="w",
                padx=18,
                pady=12,
                bg="#111827",
                fg=self.colors["text"],
                activebackground="#1f2937",
                activeforeground=self.colors["text"],
                font=("Segoe UI", 11),
                cursor="hand2",
            )
            button.pack(fill="x", padx=12, pady=4)

            # Save button references so active navigation styling can be updated.
            self.nav_buttons[name] = button

        bottom_status = tk.Frame(self.sidebar, bg="#111827")
        bottom_status.pack(side="bottom", fill="x", padx=18, pady=18)

        tk.Label(
            bottom_status,
            text="System Status",
            bg="#111827",
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x")

        self.sidebar_status_label = tk.Label(
            bottom_status,
            text="IDLE",
            bg="#111827",
            fg=self.colors["accent"],
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        )
        self.sidebar_status_label.pack(fill="x", pady=(4, 0))

    def _set_active_nav(self, active_name: str) -> None:
        """Update sidebar styling for the active page."""

        self.current_tab = active_name

        for name, button in self.nav_buttons.items():
            if name == active_name:
                button.configure(bg="#1e293b", fg=self.colors["accent"])
            else:
                button.configure(bg="#111827", fg=self.colors["text"])

    def _clear_content(self) -> None:
        """Remove the current page from the content area."""

        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # These dictionaries only apply to the page that is currently visible.
        self.dashboard_widgets = {}
        self.settings_vars = {}

    def _panel(self, parent: tk.Widget, title: str) -> tk.Frame:
        """Create a reusable styled panel.

        Most pages are made of panels with the same dark background, border,
        title label, and internal spacing.
        """

        panel = tk.Frame(
            parent,
            bg=self.colors["panel"],
            highlightbackground=self.colors["border"],
            highlightthickness=1,
            bd=0,
        )

        tk.Label(
            panel,
            text=title,
            bg=self.colors["panel"],
            fg=self.colors["text"],
            font=("Segoe UI", 12, "bold"),
            anchor="w",
        ).pack(fill="x", padx=14, pady=(12, 8))

        return panel

    def refresh_static_views(self) -> None:
        """Refresh whichever page is currently visible.

        This is used after state changes such as:
        - selecting a file
        - finishing a scan
        - changing a setting
        - clearing alerts
        """

        if self.sidebar_status_label:
            self.sidebar_status_label.config(text=self.state.status)

        if self.current_tab == "Dashboard":
            self.update_dashboard_widgets()
        elif self.current_tab == "Scan History":
            self.show_history()
        elif self.current_tab == "Threat Guide":
            self.show_threat_guide()
        elif self.current_tab == "Settings":
            self.show_settings()

    def clear_alerts(self) -> None:
        """Clear alerts from the in-memory UI state.

        This does not delete scan history from SQLite.
        It only clears the visible recent alerts list for the current session.
        """

        self.state.alerts.clear()

        if self.current_tab == "Dashboard":
            self.update_dashboard_widgets()

    def load_history_item(self, item: dict) -> None:
        """Load a previous scan history item into the dashboard result panel."""

        self.state.current_result = {
            "file": item["file"],
            "level": item["level"],
            "time": item["time"],
            "findings": item.get("findings", ["No findings available."]),
        }
        self.state.status = "COMPLETE"
        self.state.current_scan = item["file"]

        self.show_dashboard()

    def show_dashboard(self) -> None:
        """Build the main Dashboard page."""

        self._set_active_nav("Dashboard")
        self._clear_content()

        # Dashboard layout:
        # row 0 = active scan panel
        # row 1 = file upload + scan controls
        # row 2 = scan results + recent alerts
        self.content_frame.grid_rowconfigure(2, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)

        top_panel = self._panel(self.content_frame, "Active Scan")
        top_panel.grid(row=0, column=0, sticky="ew", pady=(0, 14))

        status_row = tk.Frame(top_panel, bg=self.colors["panel"])
        status_row.pack(fill="x", padx=14, pady=(2, 8))

        tk.Label(
            status_row,
            text="Status:",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10),
        ).pack(side="left")

        status_value = tk.Label(
            status_row,
            text="",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10, "bold"),
        )
        status_value.pack(side="left", padx=(8, 0))

        progress_frame = tk.Frame(top_panel, bg=self.colors["panel"])
        progress_frame.pack(fill="x", padx=14, pady=(0, 10))

        progressbar = ttk.Progressbar(
            progress_frame,
            maximum=100,
            style="Sentinel.Horizontal.TProgressbar",
        )
        progressbar.pack(fill="x")

        current_scan_label = tk.Label(
            top_panel,
            text="",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Consolas", 10),
            anchor="w",
        )
        current_scan_label.pack(fill="x", padx=14, pady=(0, 14))

        middle_frame = tk.Frame(self.content_frame, bg=self.colors["bg"])
        middle_frame.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        middle_frame.grid_columnconfigure(0, weight=3)
        middle_frame.grid_columnconfigure(1, weight=2)

        drag_panel = self._panel(middle_frame, "File Upload / Drag & Drop")
        drag_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 7))

        drop_zone = tk.Frame(
            drag_panel,
            bg=self.colors["panel_alt"],
            highlightbackground=self.colors["accent"],
            highlightthickness=1,
            bd=0,
            height=170,
            cursor="hand2",
        )
        drop_zone.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        drop_zone.pack_propagate(False)

        # Clicking the drop zone opens the file picker.
        drop_zone.bind("<Button-1>", lambda _event: self.browse_file())

        # Small hover effect to make the drop zone feel interactive.
        drop_zone.bind("<Enter>", lambda _event: drop_zone.config(bg="#334155"))
        drop_zone.bind("<Leave>", lambda _event: drop_zone.config(bg=self.colors["panel_alt"]))

        drop_title = tk.Label(
            drop_zone,
            text="Drop file here",
            bg=self.colors["panel_alt"],
            fg=self.colors["text"],
            font=("Segoe UI", 16, "bold"),
        )
        drop_title.pack(pady=(34, 6))

        drop_subtitle_text = "or click to browse scripts, logs, configs, archives, and security files"

        if not DND_AVAILABLE:
            drop_subtitle_text = "click to browse scripts, logs, configs, archives, and security files"

        drop_subtitle = tk.Label(
            drop_zone,
            text=drop_subtitle_text,
            bg=self.colors["panel_alt"],
            fg=self.colors["muted"],
            font=("Segoe UI", 11),
        )
        drop_subtitle.pack()

        # Register drag-and-drop handlers if tkinterdnd2 is installed.
        self._enable_drag_and_drop(drop_zone, drop_title, drop_subtitle)

        controls_panel = self._panel(middle_frame, "Scan Controls")
        controls_panel.grid(row=0, column=1, sticky="nsew", padx=(7, 0))

        tk.Label(
            controls_panel,
            text="Selected File",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 6))

        selected_file_box = tk.Label(
            controls_panel,
            text="",
            bg="#0b1220",
            fg=self.colors["text"],
            font=("Consolas", 10),
            anchor="w",
            justify="left",
            wraplength=280,
            padx=10,
            pady=10,
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        )
        selected_file_box.pack(fill="x", padx=14, pady=(0, 14))

        button_row = tk.Frame(controls_panel, bg=self.colors["panel"])
        button_row.pack(fill="x", padx=14, pady=(0, 10))

        browse_button = tk.Button(
            button_row,
            text="Browse",
            command=self.browse_file,
            relief="flat",
            bd=0,
            bg=self.colors["button_dark"],
            fg=self.colors["text"],
            activebackground="#31425f",
            activeforeground=self.colors["text"],
            font=("Segoe UI", 10, "bold"),
            padx=16,
            pady=10,
            cursor="hand2",
        )
        browse_button.pack(side="left", fill="x", expand=True, padx=(0, 6))

        scan_button = tk.Button(
            button_row,
            text="Scan",
            command=self.start_scan,
            relief="flat",
            bd=0,
            bg=self.colors["accent"],
            fg="#08111f",
            activebackground="#67d3ff",
            activeforeground="#08111f",
            font=("Segoe UI", 10, "bold"),
            padx=16,
            pady=10,
            cursor="hand2",
        )
        scan_button.pack(side="left", fill="x", expand=True, padx=(6, 0))

        auto_scan_var = tk.BooleanVar(value=self.state.settings["auto_scan"])
        auto_scan = tk.Checkbutton(
            controls_panel,
            text="Auto-scan files",
            variable=auto_scan_var,
            command=lambda: self.controller.update_setting("auto_scan", auto_scan_var.get()),
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            activebackground=self.colors["panel"],
            activeforeground=self.colors["text"],
            selectcolor=self.colors["panel"],
            font=("Segoe UI", 10),
            cursor="hand2",
        )
        auto_scan.pack(anchor="w", padx=10, pady=(4, 12))

        bottom_frame = tk.Frame(self.content_frame, bg=self.colors["bg"])
        bottom_frame.grid(row=2, column=0, sticky="nsew")
        bottom_frame.grid_columnconfigure(0, weight=3)
        bottom_frame.grid_columnconfigure(1, weight=2)
        bottom_frame.grid_rowconfigure(0, weight=1)

        results_panel = self._panel(bottom_frame, "Scan Results")
        results_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 7))

        threat_label = tk.Label(
            results_panel,
            text="",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 18, "bold"),
            anchor="w",
        )
        threat_label.pack(fill="x", padx=14, pady=(2, 8))

        tk.Label(
            results_panel,
            text="Findings",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 6))

        findings_wrap = tk.Frame(results_panel, bg=self.colors["panel"])
        findings_wrap.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        findings_wrap.grid_rowconfigure(0, weight=1)
        findings_wrap.grid_columnconfigure(0, weight=1)

        findings_text = tk.Text(
            findings_wrap,
            bg="#0b1220",
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            bd=0,
            wrap="word",
            font=("Consolas", 10),
            padx=10,
            pady=10,
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        )
        findings_text.grid(row=0, column=0, sticky="nsew")

        findings_scroll = tk.Scrollbar(findings_wrap, command=findings_text.yview)
        findings_scroll.grid(row=0, column=1, sticky="ns")
        findings_text.configure(yscrollcommand=findings_scroll.set)

        alerts_panel = self._panel(bottom_frame, "Recent Alerts")
        alerts_panel.grid(row=0, column=1, sticky="nsew", padx=(7, 0))

        clear_btn = tk.Button(
            alerts_panel,
            text="Clear Alerts",
            command=self.clear_alerts,
            bg=self.colors["button_dark"],
            fg=self.colors["text"],
            relief="flat",
            bd=0,
            cursor="hand2",
            activebackground="#31425f",
            activeforeground=self.colors["text"],
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=6,
        )
        clear_btn.pack(anchor="e", padx=14, pady=(0, 6))

        alerts_container = tk.Frame(alerts_panel, bg=self.colors["panel"])
        alerts_container.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        # Save widget references so update_dashboard_widgets() can modify them
        # without rebuilding the entire page every time.
        self.dashboard_widgets = {
            "status_value": status_value,
            "progressbar": progressbar,
            "current_scan_label": current_scan_label,
            "selected_file_box": selected_file_box,
            "threat_label": threat_label,
            "findings_text": findings_text,
            "alerts_container": alerts_container,
            "scan_button": scan_button,
            "browse_button": browse_button,
        }

        self.update_dashboard_widgets()

    def update_dashboard_widgets(self) -> None:
        """Update dashboard widgets using the current AppState values."""

        if not self.dashboard_widgets:
            return

        self.sidebar_status_label.config(text=self.state.status)

        self.dashboard_widgets["status_value"].config(
            text=self.state.status,
            fg=self._status_color(self.state.status),
        )

        self.dashboard_widgets["progressbar"]["value"] = self.state.progress

        self.dashboard_widgets["current_scan_label"].config(
            text=f"Currently Scanning: {self.state.current_scan}"
        )

        selected_file_text = self.state.selected_file if self.state.selected_file else "No file selected"
        self.dashboard_widgets["selected_file_box"].config(text=selected_file_text)

        level = "--"

        if self.state.current_result:
            level = self.state.current_result.get("level", "--")

        self.dashboard_widgets["threat_label"].config(
            text=f"Threat Level: {level}",
            fg=self._severity_color(level),
        )

        # Disable Browse/Scan while a scan animation is running.
        # This prevents the user from triggering multiple scans at the same time.
        if self.state.is_scanning:
            self.dashboard_widgets["scan_button"].config(state="disabled")
            self.dashboard_widgets["browse_button"].config(state="disabled")
        else:
            self.dashboard_widgets["scan_button"].config(state="normal")
            self.dashboard_widgets["browse_button"].config(state="normal")

        findings_text = self.dashboard_widgets["findings_text"]
        findings_text.config(state="normal")
        findings_text.delete("1.0", "end")
        findings_text.insert("1.0", self._format_findings())
        findings_text.config(state="disabled")

        alerts_container = self.dashboard_widgets["alerts_container"]

        for widget in alerts_container.winfo_children():
            widget.destroy()

        # Rebuild the recent alerts list from state.
        for alert in self.state.alerts:
            item = tk.Frame(
                alerts_container,
                bg=self.colors["panel_alt"],
                highlightbackground=self.colors["border"],
                highlightthickness=1,
            )
            item.pack(fill="x", pady=5)

            tk.Label(
                item,
                text=alert["level"],
                bg=self.colors["panel_alt"],
                fg=self._severity_color(alert["level"]),
                font=("Segoe UI", 10, "bold"),
                width=9,
                anchor="w",
            ).pack(side="left", padx=(10, 8), pady=10)

            tk.Label(
                item,
                text=alert["file"],
                bg=self.colors["panel_alt"],
                fg=self.colors["text"],
                font=("Consolas", 10),
                anchor="w",
            ).pack(side="left", fill="x", expand=True, pady=10)

            tk.Label(
                item,
                text=alert["time"],
                bg=self.colors["panel_alt"],
                fg=self.colors["muted"],
                font=("Segoe UI", 9),
                anchor="e",
            ).pack(side="right", padx=(8, 10), pady=10)

    def _add_history_row(self, parent: tk.Frame, row_data: dict) -> None:
        """Add one clickable row to the Scan History page."""

        row = tk.Frame(
            parent,
            bg=self.colors["row_bg"],
            highlightbackground=self.colors["border"],
            highlightthickness=1,
            cursor="hand2",
        )
        row.pack(fill="x", pady=4)

        def on_enter(_event):
            row.config(bg=self.colors["row_hover"])

            for child in row.winfo_children():
                child.config(bg=self.colors["row_hover"])

        def on_leave(_event):
            row.config(bg=self.colors["row_bg"])

            for child in row.winfo_children():
                child.config(bg=self.colors["row_bg"])

        # Clicking a history row loads its result back into the dashboard.
        row.bind("<Enter>", on_enter)
        row.bind("<Leave>", on_leave)
        row.bind("<Button-1>", lambda _e, item=row_data: self.load_history_item(item))

        file_label = tk.Label(
            row,
            text=row_data["file"],
            bg=self.colors["row_bg"],
            fg=self.colors["text"],
            font=("Consolas", 10),
            width=44,
            anchor="w",
            padx=10,
            pady=10,
        )
        file_label.pack(side="left")
        file_label.bind("<Enter>", on_enter)
        file_label.bind("<Leave>", on_leave)
        file_label.bind("<Button-1>", lambda _e, item=row_data: self.load_history_item(item))

        level_label = tk.Label(
            row,
            text=row_data["level"],
            bg=self.colors["row_bg"],
            fg=self._severity_color(row_data["level"]),
            font=("Segoe UI", 10, "bold"),
            width=16,
            anchor="w",
            padx=10,
            pady=10,
        )
        level_label.pack(side="left")
        level_label.bind("<Enter>", on_enter)
        level_label.bind("<Leave>", on_leave)
        level_label.bind("<Button-1>", lambda _e, item=row_data: self.load_history_item(item))

        time_label = tk.Label(
            row,
            text=row_data["time"],
            bg=self.colors["row_bg"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            width=20,
            anchor="w",
            padx=10,
            pady=10,
        )
        time_label.pack(side="left")
        time_label.bind("<Enter>", on_enter)
        time_label.bind("<Leave>", on_leave)
        time_label.bind("<Button-1>", lambda _e, item=row_data: self.load_history_item(item))

    def show_history(self) -> None:
        """Build the Scan History page."""

        self._set_active_nav("Scan History")
        self._clear_content()
        self.sidebar_status_label.config(text=self.state.status)

        header = self._panel(self.content_frame, "Scan History")
        header.pack(fill="both", expand=True)

        search_frame = tk.Frame(header, bg=self.colors["panel"])
        search_frame.pack(fill="x", padx=14, pady=(0, 10))

        table_wrap = tk.Frame(header, bg=self.colors["panel"])
        table_wrap.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        columns = [("File", 44), ("Threat", 16), ("Time", 20)]

        def build_history_table(query: str = "") -> None:
            """Build or rebuild the history table.

            This nested function keeps table-building logic close to the search
            field that controls it.
            """

            for widget in table_wrap.winfo_children():
                widget.destroy()

            head = tk.Frame(table_wrap, bg=self.colors["panel_alt"])
            head.pack(fill="x")

            for col, width in columns:
                tk.Label(
                    head,
                    text=col,
                    bg=self.colors["panel_alt"],
                    fg=self.colors["text"],
                    font=("Segoe UI", 10, "bold"),
                    width=width,
                    anchor="w",
                    padx=10,
                    pady=10,
                ).pack(side="left")

            normalized_query = query.strip().lower()

            for row_data in self.state.history:
                haystack = f"{row_data['file']} {row_data['level']} {row_data['time']}".lower()

                if not normalized_query or normalized_query in haystack:
                    self._add_history_row(table_wrap, row_data)

        search_var = tk.StringVar()

        def filter_history(*_args) -> None:
            build_history_table(search_var.get())

        # Rebuild table whenever the search input changes.
        search_var.trace_add("write", filter_history)

        search_entry = tk.Entry(
            search_frame,
            textvariable=search_var,
            bg="#0b1220",
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 10),
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        )
        search_entry.pack(fill="x", ipady=8)
        search_entry.insert(0, "")

        build_history_table()

    def _guide_section(
        self,
        parent: tk.Frame,
        title: str,
        body: str,
        accent: str | None = None,
    ) -> None:
        """Create one explanation card for the Threat Guide page."""

        card = tk.Frame(
            parent,
            bg="#0b1220",
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        )
        card.pack(fill="x", expand=True, pady=6)

        tk.Label(
            card,
            text=title,
            bg="#0b1220",
            fg=accent if accent else self.colors["text"],
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        ).pack(fill="x", padx=12, pady=(10, 3))

        tk.Label(
            card,
            text=body,
            bg="#0b1220",
            fg=self.colors["muted"],
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
            wraplength=1000,
        ).pack(fill="x", padx=12, pady=(0, 10))

    def show_threat_guide(self) -> None:
        """Build the Threat Guide page.

        This page helps beginner users understand Sentinel's scan results.

        The dissertation can explain technical details in more depth, but the
        app itself should still explain the most important result meanings.
        """

        self._set_active_nav("Threat Guide")
        self._clear_content()
        self.sidebar_status_label.config(text=self.state.status)

        guide_panel = self._panel(self.content_frame, "Threat Guide")
        guide_panel.pack(fill="both", expand=True)

        intro = tk.Label(
            guide_panel,
            text=(
                "This page explains what Sentinel results mean. "
                "It is a quick reference for understanding scan modes, threat levels, "
                "antivirus results, archive scan messages, and common detection categories."
            ),
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
            wraplength=1100,
        )
        intro.pack(fill="x", padx=14, pady=(0, 10))

        body = tk.Frame(guide_panel, bg=self.colors["panel"])
        body.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)

        # A canvas is used so the Threat Guide can scroll.
        # Normal frames do not scroll by themselves in Tkinter.
        canvas = tk.Canvas(
            body,
            bg=self.colors["panel"],
            highlightthickness=0,
            bd=0,
        )
        canvas.grid(row=0, column=0, sticky="nsew")

        scrollbar = tk.Scrollbar(body, orient="vertical", command=canvas.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")

        scroll_frame = tk.Frame(canvas, bg=self.colors["panel"])

        canvas_window = canvas.create_window(
            (0, 0),
            window=scroll_frame,
            anchor="nw",
        )

        canvas.configure(yscrollcommand=scrollbar.set)

        def update_scroll_region(_event=None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_scroll_frame(event) -> None:
            # Make the inner frame match the canvas width.
            # Without this, the guide cards stay narrow when the window expands.
            canvas.itemconfig(canvas_window, width=event.width)

        def on_mousewheel(event) -> None:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def bind_mousewheel(_event=None) -> None:
            # Bind only while the mouse is over the guide page.
            canvas.bind_all("<MouseWheel>", on_mousewheel)

        def unbind_mousewheel(_event=None) -> None:
            canvas.unbind_all("<MouseWheel>")

        scroll_frame.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_scroll_frame)
        canvas.bind("<Enter>", bind_mousewheel)
        canvas.bind("<Leave>", unbind_mousewheel)

        self._guide_section(
            scroll_frame,
            "SAFE",
            "No suspicious indicators were detected by Sentinel's rule scanner, and antivirus did not report a known threat.",
            self.colors["safe"],
        )

        self._guide_section(
            scroll_frame,
            "MEDIUM",
            "Something unusual, incomplete, or potentially risky was found. Review the file before trusting it.",
            self.colors["medium"],
        )

        self._guide_section(
            scroll_frame,
            "HIGH",
            "Suspicious behavior was detected, such as command execution, external URLs, privilege changes, suspicious scripts, repeated failed logins, or suspicious archive contents.",
            self.colors["high"],
        )

        self._guide_section(
            scroll_frame,
            "CRITICAL",
            "A malware signature was detected by an antivirus engine, or a very severe indicator was found. Treat the file as dangerous.",
            self.colors["critical"],
        )

        self._guide_section(
            scroll_frame,
            "Antivirus scan: CLEAN",
            "The antivirus engine did not recognize the file as known malware. This does not always mean the file is safe; Sentinel's rule scanner may still detect suspicious behavior.",
        )

        self._guide_section(
            scroll_frame,
            "Antivirus scan: INFECTED",
            "The antivirus engine detected a malware or test signature. Sentinel marks this as CRITICAL.",
            self.colors["critical"],
        )

        self._guide_section(
            scroll_frame,
            "Antivirus scan: ERROR / UNAVAILABLE",
            "The antivirus scan could not complete or the engine was unavailable. Sentinel marks this as an incomplete scan instead of treating the file as safe.",
            self.colors["medium"],
        )

        self._guide_section(
            scroll_frame,
            "Docker Sandbox Mode",
            "The file is scanned through Docker using ClamAV and Sentinel's rule scanner. This provides container isolation when Docker is available.",
        )

        self._guide_section(
            scroll_frame,
            "Local Scan Mode",
            "The file is scanned on the local machine. Sentinel uses Microsoft Defender when available, then applies its own rule-based checks.",
        )

        self._guide_section(
            scroll_frame,
            "Auto Mode",
            "Sentinel tries Docker Sandbox Mode first. If Docker is unavailable or fails, Sentinel falls back to Local Scan Mode.",
        )

        self._guide_section(
            scroll_frame,
            "Archive / ZIP Scan",
            "When a ZIP file is uploaded, Sentinel safely extracts its contents into a temporary folder, scans the extracted files, combines the results, and then cleans up the temporary files.",
        )

        self._guide_section(
            scroll_frame,
            "Suspicious command-line tool",
            "Sentinel found commands commonly used during intrusion activity, such as cmd.exe, PowerShell, certutil, curl, wget, or similar tools.",
        )

        self._guide_section(
            scroll_frame,
            "External network indicator",
            "Sentinel found a URL, IP address, FTP link, or external network location. These can be normal, but they are also common in malware download commands.",
        )

        self._guide_section(
            scroll_frame,
            "Account or privilege manipulation",
            "Sentinel found commands that may create users, modify groups, or change administrator-level access.",
            self.colors["high"],
        )

        self._guide_section(
            scroll_frame,
            "Failed login burst",
            "Sentinel detected repeated failed login events. This can indicate brute-force attempts or credential guessing.",
            self.colors["high"],
        )

        self._guide_section(
            scroll_frame,
            "Repeated service crash",
            "Sentinel detected repeated service failures or crashes. This may indicate system instability, tampering, or failed exploitation attempts.",
            self.colors["high"],
        )

        update_scroll_region()

    def show_settings(self) -> None:
        """Build the Settings page."""

        self._set_active_nav("Settings")
        self._clear_content()
        self.sidebar_status_label.config(text=self.state.status)

        settings_panel = self._panel(self.content_frame, "Settings")
        settings_panel.pack(fill="both", expand=True)

        form = tk.Frame(settings_panel, bg=self.colors["panel"])
        form.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        self._setting_row(form, "Default Scan Folder", self.state.settings["default_scan_folder"])
        self._setting_row(form, "Theme", self.state.settings["theme"])
        self._setting_row(form, "Alert Retention", self.state.settings["alert_retention"])

        tk.Label(
            form,
            text="Scan Execution Mode",
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(fill="x", pady=(16, 4))

        scan_mode_var = tk.StringVar(value=self.state.settings.get("scan_mode", "auto"))
        self.settings_vars["scan_mode"] = scan_mode_var

        scan_mode_frame = tk.Frame(
            form,
            bg="#0b1220",
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        )
        scan_mode_frame.pack(fill="x", pady=(0, 10), ipady=6)

        scan_modes = [
            ("auto", "Auto - Use Docker when available, otherwise local scan"),
            ("docker", "Docker Sandbox Only - Require container isolation"),
            ("local", "Local Only - Scan directly without Docker"),
        ]

        for value, label in scan_modes:
            tk.Radiobutton(
                scan_mode_frame,
                text=label,
                value=value,
                variable=scan_mode_var,
                command=lambda: self.controller.update_setting("scan_mode", scan_mode_var.get()),
                bg="#0b1220",
                fg=self.colors["text"],
                activebackground="#0b1220",
                activeforeground=self.colors["text"],
                selectcolor=self.colors["panel"],
                font=("Segoe UI", 10),
                cursor="hand2",
                anchor="w",
            ).pack(fill="x", padx=10, pady=4)

        auto_var = tk.BooleanVar(value=self.state.settings["auto_scan"])
        notify_var = tk.BooleanVar(value=self.state.settings["desktop_notifications"])

        self.settings_vars["auto_scan"] = auto_var
        self.settings_vars["desktop_notifications"] = notify_var

        tk.Checkbutton(
            form,
            text="Enable Auto Scan",
            variable=auto_var,
            command=lambda: self.controller.update_setting("auto_scan", auto_var.get()),
            bg=self.colors["panel"],
            fg=self.colors["text"],
            activebackground=self.colors["panel"],
            activeforeground=self.colors["text"],
            selectcolor=self.colors["panel"],
            font=("Segoe UI", 10),
            cursor="hand2",
        ).pack(anchor="w", pady=6)

        tk.Checkbutton(
            form,
            text="Enable Desktop Alerts",
            variable=notify_var,
            command=lambda: self.controller.update_setting("desktop_notifications", notify_var.get()),
            bg=self.colors["panel"],
            fg=self.colors["text"],
            activebackground=self.colors["panel"],
            activeforeground=self.colors["text"],
            selectcolor=self.colors["panel"],
            font=("Segoe UI", 10),
            cursor="hand2",
        ).pack(anchor="w", pady=6)

    def _setting_row(self, parent: tk.Frame, label_text: str, value_text: str) -> None:
        """Create a read-only setting display row."""

        tk.Label(
            parent,
            text=label_text,
            bg=self.colors["panel"],
            fg=self.colors["muted"],
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(fill="x", pady=(8, 4))

        tk.Label(
            parent,
            text=value_text,
            bg="#0b1220",
            fg=self.colors["text"],
            font=("Consolas", 10),
            anchor="w",
            padx=10,
            pady=10,
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        ).pack(fill="x")

    def _enable_drag_and_drop(self, *widgets: tk.Widget) -> None:
        """Enable drag-and-drop support on the provided widgets if available."""

        if not DND_AVAILABLE or DND_FILES is None:
            return

        for widget in widgets:
            try:
                widget.drop_target_register(DND_FILES)
                widget.dnd_bind("<<Drop>>", self.handle_file_drop)

            except Exception:
                # Drag-and-drop should never stop the UI from working.
                # Browse still works even if registration fails.
                pass

    def handle_file_drop(self, event) -> None:
        """Handle a file being dropped into the upload area."""

        dropped_data = event.data

        try:
            # Windows paths can arrive wrapped in braces.
            # splitlist handles paths with spaces more safely than a simple split.
            paths = self.root.tk.splitlist(dropped_data)

        except Exception:
            paths = [dropped_data]

        if not paths:
            return

        path = str(paths[0]).strip().strip("{}")

        if not os.path.isfile(path):
            self.state.status = "ERROR"
            self.state.current_result = {
                "file": None,
                "level": "--",
                "findings": [
                    "Dropped item is not a valid file.",
                    f"Path received: {path}",
                ],
                "time": "",
            }
            self.refresh_static_views()
            return

        self.controller.select_file(path)
        self.refresh_static_views()

        # If Auto-scan is enabled, start scanning shortly after the file is selected.
        if self.state.settings.get("auto_scan", False):
            self.root.after(150, self.start_scan)

    def browse_file(self) -> None:
        """Open a file picker and select a file for scanning."""

        initial_dir = self.state.settings.get("default_scan_folder", "")

        path = filedialog.askopenfilename(
            title="Select file to scan",
            initialdir=initial_dir if initial_dir else None,
            filetypes=[
                (
                    "Supported Sentinel scan files",
                    "*.txt *.log *.csv *.json *.xml *.yaml *.yml *.md "
                    "*.py *.js *.ts *.html *.css *.sql *.ini *.conf *.cfg "
                    "*.ps1 *.bat *.cmd *.sh *.env *.zip"
                ),
                (
                    "Archives",
                    "*.zip",
                ),
                (
                    "Scripts",
                    "*.ps1 *.bat *.cmd *.sh *.py *.js *.ts",
                ),
                (
                    "Logs and text files",
                    "*.txt *.log *.csv *.json *.xml *.yaml *.yml *.md *.ini *.conf *.cfg *.env",
                ),
                (
                    "All files",
                    "*.*",
                ),
            ],
        )

        if path:
            self.controller.select_file(path)
            self.refresh_static_views()

    def start_scan(self) -> None:
        """Start the scan flow from the UI.

        The controller prepares the state.
        The UI then runs a short progress animation before finish_scan() performs
        the actual backend scan.
        """

        can_scan = self.controller.start_scan()
        self.refresh_static_views()

        if can_scan:
            self._step_progress(0)

    def _step_progress(self, value: int) -> None:
        """Animate the progress bar before finishing the scan.

        This is a simple UI animation.
        It is not a real measurement of scan progress.
        """

        if value <= 100:
            self.controller.set_progress(value)

            if self.current_tab == "Dashboard":
                self.update_dashboard_widgets()
            else:
                self.sidebar_status_label.config(text=self.state.status)

            self.root.after(35, lambda: self._step_progress(value + 4))
            return

        self.controller.finish_scan()
        self.refresh_static_views()

    def _format_findings(self) -> str:
        """Format the current result findings for the text box."""

        if not self.state.current_result:
            return (
                "Awaiting scan results...\n\n"
                "Flagged findings will appear here once a file is scanned.\n"
                "This panel is reserved for detection output, rule hits, and scan notes."
            )

        findings = self.state.current_result.get("findings", [])

        if not findings:
            return "No findings available."

        return "\n".join(f"- {finding}" for finding in findings)

    def _severity_color(self, level: str) -> str:
        """Return the display color for a threat level."""

        level = str(level).upper()

        return {
            "SAFE": self.colors["safe"],
            "LOW": self.colors["safe"],
            "MEDIUM": self.colors["medium"],
            "HIGH": self.colors["high"],
            "CRITICAL": self.colors["critical"],
            "--": self.colors["muted"],
        }.get(level, self.colors["text"])

    def _status_color(self, status: str) -> str:
        """Return the display color for a scan status."""

        status = str(status).upper()

        return {
            "IDLE": self.colors["muted"],
            "READY": self.colors["accent"],
            "SCANNING": self.colors["accent"],
            "COMPLETE": self.colors["safe"],
            "ERROR": self.colors["critical"],
        }.get(status, self.colors["text"])


def main() -> None:
    """Start the Sentinel desktop app."""

    if DND_AVAILABLE and TkinterDnD is not None:
        # Use TkinterDnD root when drag-and-drop support is installed.
        root = TkinterDnD.Tk()
    else:
        # Fall back to normal Tkinter root.
        root = tk.Tk()

    state = AppState()
    controller = Controller(state)

    SentinelUI(root, state, controller)

    root.mainloop()


if __name__ == "__main__":
    main()