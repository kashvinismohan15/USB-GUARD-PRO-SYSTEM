"""USBGuard Pro GUI application."""

from __future__ import annotations

import csv
import os
import threading
import time
import tkinter as tk
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, scrolledtext, ttk

from usb_monitor import DeviceSnapshot, USBMonitor

THEMES = {
    "System Blue": {
        "root_bg": "#0f172a",
        "panel_bg": "#1e293b",
        "card_bg": "#243244",
        "text": "#e2e8f0",
        "muted": "#94a3b8",
        "accent": "#38bdf8",
        "success": "#22c55e",
        "warning": "#f59e0b",
        "danger": "#ef4444",
        "tree_bg": "#0b1220",
        "tree_fg": "#dbeafe",
    },
    "System Green": {
        "root_bg": "#0a1f17",
        "panel_bg": "#163329",
        "card_bg": "#1f4a3b",
        "text": "#e8fff3",
        "muted": "#9fd4b6",
        "accent": "#34d399",
        "success": "#22c55e",
        "warning": "#fbbf24",
        "danger": "#f87171",
        "tree_bg": "#0b2119",
        "tree_fg": "#ddffee",
    },
    "System Amber": {
        "root_bg": "#24190d",
        "panel_bg": "#3a2916",
        "card_bg": "#513920",
        "text": "#fff7e6",
        "muted": "#e6cba4",
        "accent": "#f59e0b",
        "success": "#22c55e",
        "warning": "#facc15",
        "danger": "#ef4444",
        "tree_bg": "#2a1f13",
        "tree_fg": "#fff1d4",
    },
}

WORDING_STYLES = {
    "Standard": {
        "start": "Start Monitoring",
        "stop": "Stop Monitoring",
        "refresh": "Refresh Logs",
        "block": "Manual Block",
        "alert_prefix": "Unauthorized USB detected",
    },
    "Bang": {
        "start": "Start Guard Bang",
        "stop": "Stop Guard Bang",
        "refresh": "Refresh Bang Logs",
        "block": "Block Now Bang",
        "alert_prefix": "Bang! Unauthorized USB detected",
    },
}


class USBGuardGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("USBGuard Pro - Smart USB Intrusion Prevention System")
        self.root.geometry("1360x860")

        self.monitor = USBMonitor()
        self.is_monitoring = False
        self.monitor_thread: threading.Thread | None = None
        self.monitor_started_at: float | None = None

        self.current_admin = ""
        self.current_theme_name = "System Blue"
        self.current_wording_name = "Standard"

        self.theme_var = tk.StringVar(value=self.current_theme_name)
        self.wording_var = tk.StringVar(value=self.current_wording_name)

        self.active_tree_items: dict[str, str] = {}
        self.notified_alerts: set[str] = set()

        self.root.withdraw()
        if not self.show_auth_dialog():
            self.root.destroy()
            return

        self.setup_ui()
        self.load_logs()
        self.schedule_periodic_refresh()
        self.root.deiconify()
        self.root.lift()
        try:
            self.root.focus_force()
        except tk.TclError:
            pass

    @property
    def theme(self) -> dict[str, str]:
        return THEMES[self.current_theme_name]

    @property
    def wording(self) -> dict[str, str]:
        return WORDING_STYLES[self.current_wording_name]

    def show_auth_dialog(self) -> bool:
        """Show register/login dialog backed by SQL admin table."""
        success = {"ok": False}
        admin_exists = self.monitor.admin_exists()

        self.root.update_idletasks()
        try:
            root_viewable = bool(int(self.root.tk.call("winfo", "viewable", ".")))
        except tk.TclError:
            root_viewable = False

        dialog = tk.Toplevel(self.root if root_viewable else None)
        dialog.title("USBGuard Pro - Admin Access")
        dialog.geometry("560x430")
        dialog.resizable(False, False)
        dialog.configure(bg="#0f172a")
        if root_viewable:
            dialog.transient(self.root)
        dialog.grab_set()
        dialog.lift()
        dialog.attributes("-topmost", True)
        dialog.after(250, lambda: dialog.attributes("-topmost", False))
        try:
            dialog.focus_force()
        except tk.TclError:
            pass

        mode_var = tk.StringVar(value="login" if admin_exists else "register")
        user_var = tk.StringVar()
        pass_var = tk.StringVar()
        info_var = tk.StringVar(
            value="Login with admin account" if admin_exists else "No admin found. Create first admin account."
        )

        container = tk.Frame(dialog, bg="#1e293b", padx=28, pady=24)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        tk.Label(
            container,
            text="USBGuard Pro Admin",
            font=("Segoe UI", 18, "bold"),
            bg="#1e293b",
            fg="#38bdf8",
        ).pack(anchor="w")

        tk.Label(
            container,
            textvariable=info_var,
            font=("Segoe UI", 11),
            bg="#1e293b",
            fg="#cbd5e1",
        ).pack(anchor="w", pady=(6, 18))

        mode_row = tk.Frame(container, bg="#1e293b")
        mode_row.pack(fill=tk.X)

        tk.Radiobutton(
            mode_row,
            text="Login",
            variable=mode_var,
            value="login",
            state=tk.NORMAL if admin_exists else tk.DISABLED,
            bg="#1e293b",
            fg="#e2e8f0",
            selectcolor="#334155",
            activebackground="#1e293b",
            activeforeground="#e2e8f0",
        ).pack(side=tk.LEFT)

        tk.Radiobutton(
            mode_row,
            text="Register",
            variable=mode_var,
            value="register",
            bg="#1e293b",
            fg="#e2e8f0",
            selectcolor="#334155",
            activebackground="#1e293b",
            activeforeground="#e2e8f0",
        ).pack(side=tk.LEFT, padx=(10, 0))

        form = tk.Frame(container, bg="#1e293b")
        form.pack(fill=tk.BOTH, expand=True, pady=(14, 0))

        tk.Label(form, text="Username", bg="#1e293b", fg="#e2e8f0", font=("Segoe UI", 11)).pack(anchor="w")
        user_entry = tk.Entry(
            form,
            textvariable=user_var,
            font=("Segoe UI", 12),
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground="#64748b",
            highlightcolor="#38bdf8",
            bd=6,
        )
        user_entry.pack(fill=tk.X, pady=(6, 14))

        tk.Label(form, text="Password", bg="#1e293b", fg="#e2e8f0", font=("Segoe UI", 11)).pack(anchor="w")
        pass_entry = tk.Entry(
            form,
            textvariable=pass_var,
            show="*",
            font=("Segoe UI", 12),
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground="#64748b",
            highlightcolor="#38bdf8",
            bd=6,
        )
        pass_entry.pack(fill=tk.X, pady=(6, 10))

        tk.Label(
            form,
            text="Tip: Press Enter to submit",
            bg="#1e293b",
            fg="#94a3b8",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(0, 10))

        action_row = tk.Frame(form, bg="#1e293b")
        action_row.pack(fill=tk.X, pady=(4, 0))

        def on_submit() -> None:
            username = user_var.get().strip()
            password = pass_var.get()
            if mode_var.get() == "register":
                ok, message = self.monitor.register_admin(username, password)
                if not ok:
                    messagebox.showerror("Register Failed", message, parent=dialog)
                    return
                self.current_admin = username
                success["ok"] = True
                messagebox.showinfo("Success", "Admin account created successfully.", parent=dialog)
                dialog.destroy()
                return

            if not self.monitor.authenticate_admin(username, password):
                messagebox.showerror("Login Failed", "Invalid username or password.", parent=dialog)
                return

            self.current_admin = username
            success["ok"] = True
            dialog.destroy()

        ttk.Button(action_row, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        ttk.Button(action_row, text="Submit", command=on_submit).pack(side=tk.RIGHT, padx=(0, 8))

        dialog.bind("<Return>", lambda _event: on_submit())
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        user_entry.focus_set()

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        self.root.wait_window(dialog)
        return bool(success["ok"])

    def setup_ui(self) -> None:
        for child in self.root.winfo_children():
            child.destroy()

        self.root.configure(bg=self.theme["root_bg"])
        self._configure_ttk_style()

        header = tk.Frame(self.root, bg=self.theme["panel_bg"], height=90)
        header.pack(fill=tk.X, padx=12, pady=(12, 8))
        header.pack_propagate(False)

        tk.Label(
            header,
            text="USBGuard Pro",
            font=("Segoe UI", 25, "bold"),
            bg=self.theme["panel_bg"],
            fg=self.theme["accent"],
        ).pack(side=tk.LEFT, padx=(18, 12), pady=14)

        tk.Label(
            header,
            text="Real-time USB Security Dashboard",
            font=("Segoe UI", 11),
            bg=self.theme["panel_bg"],
            fg=self.theme["muted"],
        ).pack(side=tk.LEFT, pady=20)

        right = tk.Frame(header, bg=self.theme["panel_bg"])
        right.pack(side=tk.RIGHT, padx=16)

        self.status_label = tk.Label(
            right,
            text="STOPPED",
            font=("Segoe UI", 12, "bold"),
            bg=self.theme["panel_bg"],
            fg=self.theme["danger"],
        )
        self.status_label.pack(anchor="e", pady=(10, 0))

        tk.Label(
            right,
            text=f"Admin: {self.current_admin}",
            font=("Segoe UI", 10),
            bg=self.theme["panel_bg"],
            fg=self.theme["muted"],
        ).pack(anchor="e")

        controls = tk.Frame(self.root, bg=self.theme["panel_bg"])
        controls.pack(fill=tk.X, padx=12, pady=(0, 8))

        self.start_button = tk.Button(
            controls,
            text=self.wording["start"],
            command=self.start_monitoring,
            bg=self.theme["accent"],
            fg="#001018",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=8,
            cursor="hand2",
        )
        self.start_button.pack(side=tk.LEFT, padx=(10, 6), pady=10)

        self.stop_button = tk.Button(
            controls,
            text=self.wording["stop"],
            command=self.stop_monitoring,
            bg=self.theme["danger"],
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=8,
            state=tk.DISABLED,
            cursor="hand2",
        )
        self.stop_button.pack(side=tk.LEFT, padx=6, pady=10)

        self.refresh_button = tk.Button(
            controls,
            text=self.wording["refresh"],
            command=self.load_logs,
            bg="#334155",
            fg="white",
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=14,
            pady=8,
            cursor="hand2",
        )
        self.refresh_button.pack(side=tk.LEFT, padx=6, pady=10)

        self.block_button = tk.Button(
            controls,
            text=self.wording["block"],
            command=self.block_selected_device,
            bg="#7c2d12",
            fg="white",
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=14,
            pady=8,
            cursor="hand2",
        )
        self.block_button.pack(side=tk.LEFT, padx=6, pady=10)

        self.export_button = tk.Button(
            controls,
            text="Export Report",
            command=self.export_report,
            bg="#1d4ed8",
            fg="white",
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=14,
            pady=8,
            cursor="hand2",
        )
        self.export_button.pack(side=tk.LEFT, padx=6, pady=10)

        tk.Label(
            controls,
            text="Theme",
            bg=self.theme["panel_bg"],
            fg=self.theme["muted"],
            font=("Segoe UI", 9),
        ).pack(side=tk.RIGHT, padx=(8, 4))

        theme_box = ttk.Combobox(
            controls,
            textvariable=self.theme_var,
            values=list(THEMES.keys()),
            width=14,
            state="readonly",
        )
        theme_box.pack(side=tk.RIGHT, padx=(0, 10), pady=10)
        theme_box.bind("<<ComboboxSelected>>", self.change_theme)

        tk.Label(
            controls,
            text="Wording",
            bg=self.theme["panel_bg"],
            fg=self.theme["muted"],
            font=("Segoe UI", 9),
        ).pack(side=tk.RIGHT, padx=(8, 4))

        wording_box = ttk.Combobox(
            controls,
            textvariable=self.wording_var,
            values=list(WORDING_STYLES.keys()),
            width=10,
            state="readonly",
        )
        wording_box.pack(side=tk.RIGHT, padx=(0, 6), pady=10)
        wording_box.bind("<<ComboboxSelected>>", self.change_wording)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        self.monitor_tab = tk.Frame(self.notebook, bg=self.theme["root_bg"])
        self.notebook.add(self.monitor_tab, text="Live Dashboard")
        self.setup_monitor_tab()

        self.logs_tab = tk.Frame(self.notebook, bg=self.theme["root_bg"])
        self.notebook.add(self.logs_tab, text="Activity Log")
        self.setup_logs_tab()

        self.threats_tab = tk.Frame(self.notebook, bg=self.theme["root_bg"])
        self.notebook.add(self.threats_tab, text="Threat Alerts")
        self.setup_threats_tab()

        self.events_tab = tk.Frame(self.notebook, bg=self.theme["root_bg"])
        self.notebook.add(self.events_tab, text="System Events")
        self.setup_events_tab()

        self.stats_tab = tk.Frame(self.notebook, bg=self.theme["root_bg"])
        self.notebook.add(self.stats_tab, text="Statistics")
        self.setup_stats_tab()

    def _configure_ttk_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TNotebook", background=self.theme["root_bg"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=self.theme["panel_bg"],
            foreground=self.theme["text"],
            padding=(14, 8),
            font=("Segoe UI", 10),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.theme["card_bg"])],
            foreground=[("selected", self.theme["accent"])],
        )

        style.configure(
            "Treeview",
            background=self.theme["tree_bg"],
            foreground=self.theme["tree_fg"],
            fieldbackground=self.theme["tree_bg"],
            rowheight=24,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=self.theme["card_bg"],
            foreground=self.theme["text"],
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", self.theme["accent"])], foreground=[("selected", "#041218")])

    def setup_monitor_tab(self) -> None:
        tk.Label(
            self.monitor_tab,
            text="Active USB Devices (real time)",
            font=("Segoe UI", 14, "bold"),
            bg=self.theme["root_bg"],
            fg=self.theme["text"],
        ).pack(anchor="w", padx=10, pady=(10, 6))

        tree_frame = tk.Frame(self.monitor_tab, bg=self.theme["root_bg"])
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10)

        self.devices_tree = ttk.Treeview(
            tree_frame,
            columns=("Key", "Device", "Connected", "Status", "Threat", "Unauthorized", "FileCount", "Accessed", "Actions"),
            show="headings",
            height=10,
        )

        headings = {
            "Key": "Internal Key",
            "Device": "Device Name",
            "Connected": "Connected At",
            "Status": "Status",
            "Threat": "Threat",
            "Unauthorized": "Unauthorized",
            "FileCount": "File Count",
            "Accessed": "Files Accessed",
            "Actions": "Key Actions",
        }
        for col, text in headings.items():
            self.devices_tree.heading(col, text=text)

        self.devices_tree.column("Key", width=0, stretch=False)
        self.devices_tree.column("Device", width=280)
        self.devices_tree.column("Connected", width=150)
        self.devices_tree.column("Status", width=130)
        self.devices_tree.column("Threat", width=90)
        self.devices_tree.column("Unauthorized", width=100)
        self.devices_tree.column("FileCount", width=100)
        self.devices_tree.column("Accessed", width=100)
        self.devices_tree.column("Actions", width=240)

        sb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=sb.set)
        self.devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        tk.Label(
            self.monitor_tab,
            text="Dashboard Activity Feed",
            font=("Segoe UI", 14, "bold"),
            bg=self.theme["root_bg"],
            fg=self.theme["text"],
        ).pack(anchor="w", padx=10, pady=(12, 6))

        self.activity_log = scrolledtext.ScrolledText(
            self.monitor_tab,
            height=12,
            bg=self.theme["tree_bg"],
            fg=self.theme["tree_fg"],
            font=("Consolas", 10),
            insertbackground=self.theme["text"],
            relief=tk.FLAT,
        )
        self.activity_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

    def setup_logs_tab(self) -> None:
        frame = tk.Frame(self.logs_tab, bg=self.theme["root_bg"])
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.logs_tree = ttk.Treeview(
            frame,
            columns=(
                "ID",
                "Device",
                "Connected",
                "Disconnected",
                "Duration",
                "Status",
                "Threat",
                "Unauthorized",
                "StartFiles",
                "FinalFiles",
                "Accessed",
                "Actions",
            ),
            show="headings",
            height=20,
        )

        headers = {
            "ID": "ID",
            "Device": "Device",
            "Connected": "Connected",
            "Disconnected": "Disconnected",
            "Duration": "Duration (s)",
            "Status": "Status",
            "Threat": "Threat",
            "Unauthorized": "Unauthorized",
            "StartFiles": "File Count Start",
            "FinalFiles": "File Count End",
            "Accessed": "Files Accessed",
            "Actions": "Key Actions",
        }
        for col, text in headers.items():
            self.logs_tree.heading(col, text=text)

        self.logs_tree.column("ID", width=60)
        self.logs_tree.column("Device", width=230)
        self.logs_tree.column("Connected", width=140)
        self.logs_tree.column("Disconnected", width=140)
        self.logs_tree.column("Duration", width=90)
        self.logs_tree.column("Status", width=120)
        self.logs_tree.column("Threat", width=90)
        self.logs_tree.column("Unauthorized", width=100)
        self.logs_tree.column("StartFiles", width=110)
        self.logs_tree.column("FinalFiles", width=110)
        self.logs_tree.column("Accessed", width=100)
        self.logs_tree.column("Actions", width=240)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=sb.set)
        self.logs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_threats_tab(self) -> None:
        frame = tk.Frame(self.threats_tab, bg=self.theme["root_bg"])
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.threats_tree = ttk.Treeview(
            frame,
            columns=("ID", "Device", "Time", "Type", "Description", "Action"),
            show="headings",
            height=20,
        )

        for col, text in {
            "ID": "ID",
            "Device": "Device ID",
            "Time": "Detection Time",
            "Type": "Threat Type",
            "Description": "Description",
            "Action": "Action Taken",
        }.items():
            self.threats_tree.heading(col, text=text)

        self.threats_tree.column("ID", width=60)
        self.threats_tree.column("Device", width=220)
        self.threats_tree.column("Time", width=160)
        self.threats_tree.column("Type", width=120)
        self.threats_tree.column("Description", width=520)
        self.threats_tree.column("Action", width=130)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=sb.set)
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_events_tab(self) -> None:
        frame = tk.Frame(self.events_tab, bg=self.theme["root_bg"])
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.events_tree = ttk.Treeview(
            frame,
            columns=("ID", "Time", "Event", "Device", "Details"),
            show="headings",
            height=20,
        )

        for col, text in {
            "ID": "ID",
            "Time": "Event Time",
            "Event": "Event Type",
            "Device": "Device",
            "Details": "Details",
        }.items():
            self.events_tree.heading(col, text=text)

        self.events_tree.column("ID", width=60)
        self.events_tree.column("Time", width=160)
        self.events_tree.column("Event", width=180)
        self.events_tree.column("Device", width=260)
        self.events_tree.column("Details", width=620)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=sb.set)
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_stats_tab(self) -> None:
        frame = tk.Frame(self.stats_tab, bg=self.theme["root_bg"])
        frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        self.total_devices_label = self.create_stat_card(frame, "Total Sessions", "0", 0, 0)
        self.threats_detected_label = self.create_stat_card(frame, "Threats", "0", 0, 1)
        self.blocked_devices_label = self.create_stat_card(frame, "Blocked", "0", 0, 2)

        self.safe_devices_label = self.create_stat_card(frame, "Safe Sessions", "0", 1, 0)
        self.avg_duration_label = self.create_stat_card(frame, "Avg Duration", "0s", 1, 1)
        self.files_accessed_label = self.create_stat_card(frame, "Files Accessed", "0", 1, 2)

        self.monitoring_time_label = self.create_stat_card(frame, "Monitoring Uptime", "0s", 2, 0)
        self.active_count_label = self.create_stat_card(frame, "Active Devices", "0", 2, 1)
        self.theme_label = self.create_stat_card(frame, "Theme", self.current_theme_name, 2, 2)

    def create_stat_card(self, parent: tk.Frame, title: str, value: str, row: int, col: int) -> tk.Label:
        card = tk.Frame(parent, bg=self.theme["card_bg"], highlightthickness=1, highlightbackground="#334155")
        card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")

        parent.grid_rowconfigure(row, weight=1)
        parent.grid_columnconfigure(col, weight=1)

        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 11),
            bg=self.theme["card_bg"],
            fg=self.theme["muted"],
        ).pack(pady=(16, 6))

        value_label = tk.Label(
            card,
            text=value,
            font=("Segoe UI", 20, "bold"),
            bg=self.theme["card_bg"],
            fg=self.theme["accent"],
        )
        value_label.pack(pady=(0, 18))
        return value_label

    def change_theme(self, _event: tk.Event | None = None) -> None:
        selected = self.theme_var.get()
        if selected not in THEMES:
            return
        self.current_theme_name = selected
        selected_tab = self.notebook.index("current") if hasattr(self, "notebook") else 0
        self.setup_ui()
        self.notebook.select(selected_tab)
        self.load_logs()
        self.log_activity(f"Theme switched to {self.current_theme_name}", "info")

    def change_wording(self, _event: tk.Event | None = None) -> None:
        selected = self.wording_var.get()
        if selected not in WORDING_STYLES:
            return
        self.current_wording_name = selected
        self.start_button.config(text=self.wording["start"])
        self.stop_button.config(text=self.wording["stop"])
        self.refresh_button.config(text=self.wording["refresh"])
        self.block_button.config(text=self.wording["block"])
        self.log_activity(f"Wording style switched to {self.current_wording_name}", "info")

    def start_monitoring(self) -> None:
        if self.is_monitoring:
            return
        self.is_monitoring = True
        self.monitor_started_at = time.time()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="MONITORING", fg=self.theme["success"])
        self.log_activity("USB monitoring started", "success")

        self.monitor_thread = threading.Thread(
            target=self.monitor.monitor_usb_devices,
            args=(self.device_callback,),
            daemon=True,
        )
        self.monitor_thread.start()

    def stop_monitoring(self) -> None:
        if not self.is_monitoring:
            return
        self.is_monitoring = False
        self.monitor.stop_monitoring()

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="STOPPED", fg=self.theme["danger"])
        self.log_activity("USB monitoring stopped", "danger")

    def schedule_periodic_refresh(self) -> None:
        self.root.after(3000, self.periodic_refresh)

    def periodic_refresh(self) -> None:
        try:
            self.refresh_active_device_tree()
            self.load_logs(silent=True)
        finally:
            self.schedule_periodic_refresh()

    def device_callback(
        self,
        event_type: str,
        snapshot: DeviceSnapshot,
        messages: list[str],
        threat_level: str,
        unauthorized: bool,
        status: str,
    ) -> None:
        self.root.after(
            0,
            lambda: self.handle_device_event(
                event_type,
                snapshot,
                messages,
                threat_level,
                unauthorized,
                status,
            ),
        )

    def handle_device_event(
        self,
        event_type: str,
        snapshot: DeviceSnapshot,
        messages: list[str],
        threat_level: str,
        unauthorized: bool,
        status: str,
    ) -> None:
        if event_type == "connected":
            self.log_activity(f"USB inserted: {snapshot.device_name}", "info")
            if messages:
                for msg in messages:
                    self.log_activity(f"Alert detail: {msg}", "warning")
            messagebox.showinfo("USB Inserted", f"New USB detected: {snapshot.device_name}")

        elif event_type == "disconnected":
            self.log_activity(f"USB removed: {snapshot.device_name}", "info")
            item_id = self.active_tree_items.pop(snapshot.key, None)
            if item_id and self.devices_tree.exists(item_id):
                self.devices_tree.delete(item_id)

        elif event_type == "transfer_detected":
            description = messages[0] if messages else "File transfer detected"
            self.log_activity(f"File transfer: {description}", "warning")
            messagebox.showwarning(
                "File Transfer Detected",
                f"Files are being transferred to USB!\n\nDevice: {snapshot.device_name}\nDetails: {description}",
            )

        elif event_type == "alert":
            description = messages[0] if messages else "Security alert"
            self.log_activity(f"Security alert: {description}", "warning")
            alert_key = f"{snapshot.key}|{description}|{status}"
            if unauthorized and alert_key not in self.notified_alerts:
                self.notified_alerts.add(alert_key)
                messagebox.showwarning(
                    "Unauthorized USB Alert",
                    f"{self.wording['alert_prefix']}\n\nDevice: {snapshot.device_name}\nReason: {description}",
                )

        self.refresh_active_device_tree()
        self.load_logs(silent=True)

    def refresh_active_device_tree(self) -> None:
        active = self.monitor.active_devices
        for key, info in active.items():
            snapshot: DeviceSnapshot = info["snapshot"]
            values = (
                key,
                snapshot.device_name,
                datetime.fromtimestamp(info["connected_epoch"]).strftime("%Y-%m-%d %H:%M:%S"),
                info["status"],
                info["threat_level"],
                "YES" if info["unauthorized"] else "NO",
                info["last_file_count"],
                info["files_accessed"],
                "; ".join(info["key_actions"][-3:]),
            )

            if key in self.active_tree_items and self.devices_tree.exists(self.active_tree_items[key]):
                self.devices_tree.item(self.active_tree_items[key], values=values)
            else:
                item = self.devices_tree.insert("", 0, values=values)
                self.active_tree_items[key] = item

        active_keys = set(active.keys())
        for key in list(self.active_tree_items.keys()):
            if key not in active_keys:
                item_id = self.active_tree_items.pop(key)
                if self.devices_tree.exists(item_id):
                    self.devices_tree.delete(item_id)

    def block_selected_device(self) -> None:
        selected = self.devices_tree.selection()
        if not selected:
            messagebox.showinfo("Manual Block", "Select an active USB device first.")
            return

        values = self.devices_tree.item(selected[0], "values")
        if not values:
            return

        device_key = values[0]
        device_name = values[1]
        if not messagebox.askyesno("Confirm Block", f"Block selected device?\n\n{device_name}"):
            return

        if self.monitor.block_device_by_key(device_key, reason="Manual block from dashboard"):
            self.log_activity(f"Manual block applied: {device_name}", "danger")
            messagebox.showinfo("Block Applied", f"Device marked as blocked:\n{device_name}")
        else:
            messagebox.showerror("Block Failed", "Unable to block selected device.")

        self.refresh_active_device_tree()
        self.load_logs(silent=True)

    def log_activity(self, message: str, level: str = "info") -> None:
        if not hasattr(self, "activity_log"):
            return

        colors = {
            "info": self.theme["text"],
            "success": self.theme["success"],
            "warning": self.theme["warning"],
            "danger": self.theme["danger"],
        }
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {message}\n"

        self.activity_log.insert(tk.END, line)
        tag = f"lvl_{level}"
        self.activity_log.tag_add(tag, f"end-{len(line) + 1}c", "end-1c")
        self.activity_log.tag_config(tag, foreground=colors.get(level, self.theme["text"]))
        self.activity_log.see(tk.END)

    def export_report(self) -> None:
        filter_var = tk.StringVar(value="all")

        dialog = tk.Toplevel(self.root)
        dialog.title("Export Log Report")
        dialog.geometry("360x200")
        dialog.resizable(False, False)
        dialog.configure(bg="#1e293b")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Select report period:", bg="#1e293b", fg="#e2e8f0",
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=20, pady=(18, 8))

        for label, value in [("This week (last 7 days)", "week"), ("This month (last 30 days)", "month"), ("All time", "all")]:
            tk.Radiobutton(dialog, text=label, variable=filter_var, value=value,
                           bg="#1e293b", fg="#e2e8f0", selectcolor="#334155",
                           activebackground="#1e293b", activeforeground="#e2e8f0").pack(anchor="w", padx=30)

        def do_export() -> None:
            dialog.destroy()
            period = filter_var.get()
            cutoff: datetime | None = None
            if period == "week":
                cutoff = datetime.now() - timedelta(days=7)
            elif period == "month":
                cutoff = datetime.now() - timedelta(days=30)

            default_name = f"USBGuard_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=default_name,
                title="Save Report As",
            )
            if not path:
                return

            stats = self.monitor.get_statistics()
            logs = self.monitor.get_recent_usb_logs(limit=10000)
            threats = self.monitor.get_recent_threats(limit=10000)

            def passes(timestamp_str: str | None) -> bool:
                if cutoff is None or not timestamp_str:
                    return True
                try:
                    return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S") >= cutoff
                except ValueError:
                    return True

            filtered_logs = [r for r in logs if passes(r["connection_time"])]
            filtered_threats = [r for r in threats if passes(r["detection_time"])]

            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)

                    period_label = {"week": "Last 7 Days", "month": "Last 30 Days", "all": "All Time"}[period]
                    writer.writerow(["USBGuard Pro - Log Report"])
                    writer.writerow([f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
                    writer.writerow([f"Period: {period_label}"])
                    writer.writerow([f"Admin: {self.current_admin}"])
                    writer.writerow([])

                    writer.writerow(["=== SUMMARY ==="])
                    writer.writerow(["Total Sessions", stats["total_logs"]])
                    writer.writerow(["Threats Detected", stats["total_threats"]])
                    writer.writerow(["Blocked Devices", stats["blocked"]])
                    writer.writerow(["Safe Sessions", stats["safe"]])
                    writer.writerow(["Files Accessed", stats["files_accessed"]])
                    writer.writerow(["Avg Connection Duration (s)", stats["avg_duration"]])
                    writer.writerow([])

                    writer.writerow(["=== USB SESSION LOG ==="])
                    writer.writerow(["ID", "Device", "Connected", "Disconnected", "Duration (s)",
                                     "Status", "Threat Level", "Unauthorized",
                                     "Files at Start", "Files at End", "Files Accessed", "Key Actions"])
                    for r in filtered_logs:
                        writer.writerow([
                            r["id"], r["device_name"], r["connection_time"],
                            r["disconnection_time"] or "-",
                            r["duration_seconds"] if r["duration_seconds"] is not None else "-",
                            r["status"], r["threat_level"],
                            "YES" if r["unauthorized"] else "NO",
                            r["file_count_initial"], r["file_count_final"],
                            r["files_accessed"], r["key_actions"] or "-",
                        ])
                    writer.writerow([])

                    writer.writerow(["=== THREAT DETECTIONS ==="])
                    writer.writerow(["ID", "Device ID", "Detection Time", "Threat Type", "Description", "Action Taken"])
                    for r in filtered_threats:
                        writer.writerow([r["id"], r["device_id"], r["detection_time"],
                                         r["threat_type"], r["description"], r["action_taken"]])

                self.log_activity(f"Report exported: {os.path.basename(path)}", "success")
                messagebox.showinfo("Export Successful",
                                    f"Report saved successfully!\n\nFile: {os.path.basename(path)}\n"
                                    f"Sessions exported: {len(filtered_logs)}\n"
                                    f"Threats exported: {len(filtered_threats)}")
            except Exception as exc:
                messagebox.showerror("Export Failed", f"Could not save report:\n{exc}")

        btn_row = tk.Frame(dialog, bg="#1e293b")
        btn_row.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=14)
        ttk.Button(btn_row, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        ttk.Button(btn_row, text="Export CSV", command=do_export).pack(side=tk.RIGHT, padx=(0, 8))

    def load_logs(self, silent: bool = False) -> None:
        try:
            for tree in (self.logs_tree, self.threats_tree, self.events_tree):
                for item in tree.get_children():
                    tree.delete(item)

            for row in self.monitor.get_recent_usb_logs(limit=200):
                self.logs_tree.insert(
                    "",
                    tk.END,
                    values=(
                        row["id"],
                        row["device_name"],
                        row["connection_time"],
                        row["disconnection_time"] or "-",
                        row["duration_seconds"] if row["duration_seconds"] is not None else "-",
                        row["status"],
                        row["threat_level"],
                        "YES" if row["unauthorized"] else "NO",
                        row["file_count_initial"],
                        row["file_count_final"],
                        row["files_accessed"],
                        row["key_actions"] or "-",
                    ),
                )

            for row in self.monitor.get_recent_threats(limit=200):
                self.threats_tree.insert(
                    "",
                    tk.END,
                    values=(
                        row["id"],
                        row["device_id"],
                        row["detection_time"],
                        row["threat_type"],
                        row["description"],
                        row["action_taken"],
                    ),
                )

            for row in self.monitor.get_recent_system_events(limit=200):
                self.events_tree.insert(
                    "",
                    tk.END,
                    values=(
                        row["id"],
                        row["event_time"],
                        row["event_type"],
                        row["device_name"] or "-",
                        row["details"] or "-",
                    ),
                )

            self.update_statistics()
        except Exception as exc:
            if not silent:
                messagebox.showerror("Load Error", f"Failed to load dashboard data: {exc}")

    def update_statistics(self) -> None:
        stats = self.monitor.get_statistics()

        self.total_devices_label.config(text=str(stats["total_logs"]))
        self.threats_detected_label.config(text=str(stats["total_threats"]))
        self.blocked_devices_label.config(text=str(stats["blocked"]))
        self.safe_devices_label.config(text=str(stats["safe"]))
        self.avg_duration_label.config(text=f"{stats['avg_duration']}s")
        self.files_accessed_label.config(text=str(stats["files_accessed"]))
        self.active_count_label.config(text=str(stats["active_devices"]))
        self.theme_label.config(text=self.current_theme_name)

        if self.is_monitoring and self.monitor_started_at is not None:
            uptime = int(time.time() - self.monitor_started_at)
            self.monitoring_time_label.config(text=f"{uptime}s")
        else:
            self.monitoring_time_label.config(text="0s")


def main() -> None:
    root = tk.Tk()
    USBGuardGUI(root)
    try:
        exists = bool(root.tk.call("winfo", "exists", "."))
    except tk.TclError:
        exists = False
    if exists:
        root.mainloop()


if __name__ == "__main__":
    main()
