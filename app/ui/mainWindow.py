"""
Desktop Graphical User Interface for Ransomware Detection System.
Provides a comprehensive Security Operations Center (SOC) dashboard,
live file event streaming, forensic lineage inspection, health observability,
ML model hot-swapping, automated retraining triggers, and multi-path management.
"""

import json
import logging
import os
import queue
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Optional

from app.config.configuration import (
    getDataDirectory,
    getProjectRoot,
    loadConfiguration,
    resolveMonitoringPath,
    resolveMonitoringPaths,
    validateConfiguration,
)
from app.detection.predictor import ModelPredictor, ModelValidationError
from app.detection.riskEngine import RiskDecision
from app.forensics.forensicCollector import ForensicCollector
from app.models.retrainingPipeline import RetrainingPipeline
from app.operations.backupManager import BackupManager
from app.operations.demoEngine import DemoActionType, DemoEngine
from app.operations.healthCheck import HealthChecker, HealthStatus
from app.runtime.controller import DetectionController
from app.runtime.genericWorker import MonitoringWorker
from app.storage.sqliteStore import getDatabaseStatistics, optimizeDatabase, pruneOldData

logger = logging.getLogger(__name__)


# ============================================================================
# Color Palette & Styling Constants
# ============================================================================
THEME = {
    "bg_dark": "#0b1120",        # Deep navy/black background
    "bg_surface": "#1e293b",     # Card & panel surface
    "bg_elevated": "#334155",    # Inputs, headers, elevated widgets
    "bg_input": "#0f172a",       # Textbox & input field background
    "border": "#475569",         # Subtle borders
    "accent_cyan": "#38bdf8",    # Brand accent cyan
    "accent_blue": "#3b82f6",    # Interactive button blue
    "accent_indigo": "#6366f1",  # Accent indigo
    "text_primary": "#f8fafc",   # Crisp white
    "text_secondary": "#94a3b8", # Muted slate gray
    "safe_green": "#22c55e",     # Protected / benign green
    "safe_bg": "#064e3b",        # Dark green container
    "warning_amber": "#f59e0b",  # Medium threat / warning
    "warning_bg": "#78350f",     # Dark amber container
    "danger_red": "#ef4444",     # Ransomware alert / critical
    "danger_bg": "#7f1d1d",      # Dark red container
    "font_family": "Segoe UI",
}


class ModernCard(tk.Frame):
    """Card container widget with custom dark styling."""

    def __init__(self, parent, title: str = "", **kwargs):
        super().__init__(
            parent,
            bg=THEME["bg_surface"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=12,
            **kwargs,
        )
        if title:
            title_lbl = tk.Label(
                self,
                text=title.upper(),
                font=(THEME["font_family"], 9, "bold"),
                fg=THEME["text_secondary"],
                bg=THEME["bg_surface"],
            )
            title_lbl.pack(anchor="w", pady=(0, 4))


class MetricCard(tk.Frame):
    """High-visibility dashboard metric widget."""

    def __init__(self, parent, title: str, initial_value: str = "—", badge_color: str = THEME["accent_cyan"]):
        super().__init__(
            parent,
            bg=THEME["bg_surface"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=14,
            pady=10,
        )
        self.title_label = tk.Label(
            self,
            text=title.upper(),
            font=(THEME["font_family"], 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
        )
        self.title_label.pack(anchor="w")

        self.value_label = tk.Label(
            self,
            text=initial_value,
            font=(THEME["font_family"], 16, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_surface"],
        )
        self.value_label.pack(anchor="w", pady=(2, 0))

        self.sub_label = tk.Label(
            self,
            text="",
            font=(THEME["font_family"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
        )
        self.sub_label.pack(anchor="w")

    def setValue(self, value: str, subtext: str = "", color: Optional[str] = None):
        self.value_label.config(text=value, fg=color or THEME["text_primary"])
        if subtext:
            self.sub_label.config(text=subtext)


class MainWindow(tk.Tk):
    """Main Desktop Application Window for Ransomware Detection System."""

    def __init__(self):
        super().__init__()
        self.title("Ransomware Behavior Defense Station — Desktop SOC")
        self.geometry("1160x780")
        self.minsize(980, 680)
        self.configure(bg=THEME["bg_dark"])

        # Set taskbar icon if available
        try:
            icon_path = getProjectRoot() / "assets" / "icon.ico"
            if icon_path.is_file():
                self.iconbitmap(str(icon_path))
        except Exception:
            pass

        # Internal state
        self.configuration = loadConfiguration()
        self.databasePath = getDataDirectory() / "database" / "detector.sqlite3"
        self.monitoredPaths = resolveMonitoringPaths(self.configuration["monitoring"]["paths"])
        self.modelPath = self._resolveModelPath()

        self.worker: Optional[MonitoringWorker] = None
        self.isMonitoring = False
        self.currentThreatLevel = "low"
        self.currentRiskScore = 0.0
        self.sessionStartTime: Optional[datetime] = None

        self._eventQueue: queue.Queue = queue.Queue()

        self._setupStyles()
        self._buildUi()
        self._loadInitialData()

        # Start background UI polling timer (every 500ms)
        self._pollTimerId = self.after(500, self._periodicRefresh)

        # Handle clean window close
        self.protocol("WM_DELETE_WINDOW", self.onClose)

    def _resolveModelPath(self) -> Path:
        model_str = self.configuration["model"].get("path", "")
        if not model_str:
            return getDataDirectory() / "models" / "current" / "model.joblib"
        p = Path(model_str)
        return p if p.is_absolute() else getProjectRoot() / p

    def _setupStyles(self):
        """Configure ttk styling for a modern dark cybersecurity appearance."""
        style = ttk.Style(self)
        style.theme_use("clam")

        # Global Frame and Label styling
        style.configure("TFrame", background=THEME["bg_dark"])
        style.configure("Surface.TFrame", background=THEME["bg_surface"])
        style.configure("TLabel", background=THEME["bg_dark"], foreground=THEME["text_primary"], font=(THEME["font_family"], 10))
        style.configure("Surface.TLabel", background=THEME["bg_surface"], foreground=THEME["text_primary"], font=(THEME["font_family"], 10))
        style.configure("Muted.TLabel", background=THEME["bg_surface"], foreground=THEME["text_secondary"], font=(THEME["font_family"], 9))

        # Notebook tabs
        style.configure(
            "TNotebook",
            background=THEME["bg_dark"],
            borderwidth=0,
            tabmargins=[0, 4, 0, 0],
        )
        style.configure(
            "TNotebook.Tab",
            background=THEME["bg_surface"],
            foreground=THEME["text_secondary"],
            padding=[18, 8],
            font=(THEME["font_family"], 10, "bold"),
            borderwidth=1,
            focuscolor=THEME["accent_cyan"],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", THEME["bg_elevated"]), ("active", THEME["bg_elevated"])],
            foreground=[("selected", THEME["accent_cyan"]), ("active", THEME["text_primary"])],
        )

        # Treeview (Dark Table)
        style.configure(
            "Treeview",
            background=THEME["bg_input"],
            foreground=THEME["text_primary"],
            fieldbackground=THEME["bg_input"],
            rowheight=26,
            font=(THEME["font_family"], 9),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=THEME["bg_elevated"],
            foreground=THEME["text_primary"],
            font=(THEME["font_family"], 9, "bold"),
            relief="flat",
            padding=[6, 4],
        )
        style.map(
            "Treeview",
            background=[("selected", THEME["accent_indigo"])],
            foreground=[("selected", "#ffffff")],
        )

        # Buttons
        style.configure(
            "Primary.TButton",
            background=THEME["accent_blue"],
            foreground="#ffffff",
            font=(THEME["font_family"], 9, "bold"),
            borderwidth=0,
            padding=[14, 6],
        )
        style.map("Primary.TButton", background=[("active", "#2563eb"), ("pressed", "#1d4ed8")])

        style.configure(
            "Success.TButton",
            background=THEME["safe_green"],
            foreground="#000000",
            font=(THEME["font_family"], 9, "bold"),
            borderwidth=0,
            padding=[14, 6],
        )
        style.map("Success.TButton", background=[("active", "#16a34a"), ("pressed", "#15803d")])

        style.configure(
            "Danger.TButton",
            background=THEME["danger_red"],
            foreground="#ffffff",
            font=(THEME["font_family"], 9, "bold"),
            borderwidth=0,
            padding=[14, 6],
        )
        style.map("Danger.TButton", background=[("active", "#dc2626"), ("pressed", "#b91c1c")])

        style.configure(
            "Secondary.TButton",
            background=THEME["bg_elevated"],
            foreground=THEME["text_primary"],
            font=(THEME["font_family"], 9),
            borderwidth=1,
            padding=[12, 6],
        )
        style.map("Secondary.TButton", background=[("active", THEME["border"])])

        # Progressbar
        style.configure(
            "Threat.Horizontal.TProgressbar",
            troughcolor=THEME["bg_input"],
            background=THEME["safe_green"],
            thickness=12,
            borderwidth=0,
        )

    def _buildUi(self):
        """Construct the root layout and pages."""
        # Top Header Bar
        header_frame = tk.Frame(self, bg=THEME["bg_surface"], height=64, padx=20, pady=10)
        header_frame.pack(fill="x", side="top")

        # Brand Title & Version
        brand_frame = tk.Frame(header_frame, bg=THEME["bg_surface"])
        brand_frame.pack(side="left")

        title_lbl = tk.Label(
            brand_frame,
            text="🛡️ RANSOMWARE DEFENSE STATION",
            font=(THEME["font_family"], 14, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_surface"],
        )
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(
            brand_frame,
            text="Behavioral Machine Learning & Real-Time Windows Workstation Protection • Offline Defense",
            font=(THEME["font_family"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
        )
        sub_lbl.pack(anchor="w")

        # Header Action Controls
        header_actions = tk.Frame(header_frame, bg=THEME["bg_surface"])
        header_actions.pack(side="right")

        self.statusPill = tk.Label(
            header_actions,
            text="● STOPPED",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["warning_amber"],
            bg=THEME["warning_bg"],
            padx=12,
            pady=4,
            relief="flat",
        )
        self.statusPill.pack(side="left", padx=(0, 12))

        self.btnQuickScan = ttk.Button(header_actions, text="⚡ Quick Scan", style="Secondary.TButton", command=self.actionQuickScan)
        self.btnQuickScan.pack(side="left", padx=4)

        self.btnHealth = ttk.Button(header_actions, text="🏥 Health Check", style="Secondary.TButton", command=self.actionShowHealth)
        self.btnHealth.pack(side="left", padx=4)

        self.btnToggleProtection = ttk.Button(
            header_actions,
            text="▶ Start Protection",
            style="Success.TButton",
            command=self.actionToggleProtection,
        )
        self.btnToggleProtection.pack(side="left", padx=(4, 0))

        # Metrics Bar (Overview Cards)
        metrics_container = tk.Frame(self, bg=THEME["bg_dark"], padx=18, pady=10)
        metrics_container.pack(fill="x", side="top")

        self.cardProtection = MetricCard(metrics_container, "Engine State", "IDLE")
        self.cardProtection.pack(side="left", fill="x", expand=True, padx=4)

        self.cardThreat = MetricCard(metrics_container, "Threat Level", "LOW", THEME["safe_green"])
        self.cardThreat.pack(side="left", fill="x", expand=True, padx=4)

        self.cardRisk = MetricCard(metrics_container, "Risk Score", "0.0000")
        self.cardRisk.pack(side="left", fill="x", expand=True, padx=4)

        self.cardPaths = MetricCard(metrics_container, "Monitored Paths", f"{len(self.monitoredPaths)} Folder(s)")
        self.cardPaths.pack(side="left", fill="x", expand=True, padx=4)

        self.cardEvents = MetricCard(metrics_container, "Events (Session)", "0")
        self.cardEvents.pack(side="left", fill="x", expand=True, padx=4)

        self.cardDetections = MetricCard(metrics_container, "Threat Alerts", "0")
        self.cardDetections.pack(side="left", fill="x", expand=True, padx=4)

        # Dynamic Threat Alert Banner (Hidden by default, shown during threat)
        self.threatBanner = tk.Frame(self, bg=THEME["danger_bg"], padx=16, pady=8)
        self.threatBannerLabel = tk.Label(
            self.threatBanner,
            text="⚠️ THREAT DETECTED: Ransomware-like behavior observed!",
            font=(THEME["font_family"], 10, "bold"),
            fg="#ffffff",
            bg=THEME["danger_bg"],
        )
        self.threatBannerLabel.pack(side="left")
        self.threatBannerBtn = ttk.Button(self.threatBanner, text="Inspect Forensics", style="Danger.TButton", command=lambda: self.notebook.select(self.tabForensics))
        self.threatBannerBtn.pack(side="right")

        # Main Notebook / Tabs View
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(4, 12))

        # Build Tabs
        self.tabLive = ttk.Frame(self.notebook, padding=10)
        self.tabForensics = ttk.Frame(self.notebook, padding=10)
        self.tabHealth = ttk.Frame(self.notebook, padding=10)
        self.tabModels = ttk.Frame(self.notebook, padding=10)
        self.tabDemo = ttk.Frame(self.notebook, padding=10)
        self.tabSettings = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.tabLive, text=" 🔴 Live Activity & Feed ")
        self.notebook.add(self.tabForensics, text=" 🔍 Forensic Lineage ")
        self.notebook.add(self.tabHealth, text=" 📊 Diagnostics & Observability ")
        self.notebook.add(self.tabModels, text=" 🧠 ML Model & Retraining ")
        self.notebook.add(self.tabDemo, text=" 🧪 Live Lab & Demo ")
        self.notebook.add(self.tabSettings, text=" ⚙️ Settings & Paths ")

        self._buildTabLive(self.tabLive)
        self._buildTabForensics(self.tabForensics)
        self._buildTabHealth(self.tabHealth)
        self._buildTabModels(self.tabModels)
        self._buildTabDemo(self.tabDemo)
        self._buildTabSettings(self.tabSettings)

        # Bottom Status Bar
        statusbar = tk.Frame(self, bg=THEME["bg_surface"], height=24, padx=12, pady=4)
        statusbar.pack(fill="x", side="bottom")

        self.lblStatusLeft = tk.Label(
            statusbar,
            text="System Ready • Model: AES-256-GCM Encrypted • SQLite WAL Active",
            font=(THEME["font_family"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
        )
        self.lblStatusLeft.pack(side="left")

        self.lblStatusRight = tk.Label(
            statusbar,
            text="Offline Defense Mode Active",
            font=(THEME["font_family"], 8),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_surface"],
        )
        self.lblStatusRight.pack(side="right")

    # ------------------------------------------------------------------------
    # Tab 1: Live Activity & Feed
    # ------------------------------------------------------------------------
    def _buildTabLive(self, parent):
        # Two-column layout: Left (Table of events), Right (Telemetry & Details card)
        paned = tk.PanedWindow(parent, orient="horizontal", bg=THEME["bg_dark"], sashwidth=4)
        paned.pack(fill="both", expand=True)

        left_frame = tk.Frame(paned, bg=THEME["bg_dark"])
        paned.add(left_frame, minsize=620)

        # Live Events Table
        tbl_card = ModernCard(left_frame, "Real-Time File System Events Stream")
        tbl_card.pack(fill="both", expand=True)

        columns = ("time", "action", "process", "pid", "path", "pathId")
        self.treeEvents = ttk.Treeview(tbl_card, columns=columns, show="headings", selectmode="browse")
        self.treeEvents.heading("time", text="Timestamp")
        self.treeEvents.heading("action", text="Action")
        self.treeEvents.heading("process", text="Process")
        self.treeEvents.heading("pid", text="PID")
        self.treeEvents.heading("path", text="Target File Hash / Path")
        self.treeEvents.heading("pathId", text="Path ID")

        self.treeEvents.column("time", width=140, anchor="w")
        self.treeEvents.column("action", width=90, anchor="center")
        self.treeEvents.column("process", width=120, anchor="w")
        self.treeEvents.column("pid", width=70, anchor="center")
        self.treeEvents.column("path", width=260, anchor="w")
        self.treeEvents.column("pathId", width=65, anchor="center")

        scroll_y = ttk.Scrollbar(tbl_card, orient="vertical", command=self.treeEvents.yview)
        self.treeEvents.configure(yscrollcommand=scroll_y.set)

        self.treeEvents.pack(side="left", fill="both", expand=True, pady=4)
        scroll_y.pack(side="right", fill="y", pady=4)

        # Right Panel: Telemetry & Summary
        right_frame = tk.Frame(paned, bg=THEME["bg_dark"])
        paned.add(right_frame, minsize=320)

        summary_card = ModernCard(right_frame, "Detection Context & Details")
        summary_card.pack(fill="both", expand=True)

        self.lblModelSummary = tk.Label(
            summary_card,
            text="Model: Checking...",
            font=(THEME["font_family"], 9),
            fg=THEME["text_primary"],
            bg=THEME["bg_surface"],
            justify="left",
            anchor="w",
        )
        self.lblModelSummary.pack(fill="x", pady=4)

        self.lblUptimeSummary = tk.Label(
            summary_card,
            text="Session Uptime: 00:00:00",
            font=(THEME["font_family"], 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
            justify="left",
            anchor="w",
        )
        self.lblUptimeSummary.pack(fill="x", pady=2)

        ttk.Separator(summary_card, orient="horizontal").pack(fill="x", pady=8)

        lbl_recent_hdr = tk.Label(
            summary_card,
            text="RECENT THREAT DETECTIONS",
            font=(THEME["font_family"], 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
        )
        lbl_recent_hdr.pack(anchor="w", pady=(4, 2))

        self.listRecentDetections = tk.Listbox(
            summary_card,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            highlightthickness=0,
            selectbackground=THEME["accent_indigo"],
            font=(THEME["font_family"], 8),
            height=10,
        )
        self.listRecentDetections.pack(fill="both", expand=True, pady=4)

        btn_clear_events = ttk.Button(summary_card, text="Clear Stream Table", style="Secondary.TButton", command=self.actionClearLiveTable)
        btn_clear_events.pack(anchor="w", pady=(8, 0))

    # ------------------------------------------------------------------------
    # Tab 2: Forensic Lineage & Incident Snapshots
    # ------------------------------------------------------------------------
    def _buildTabForensics(self, parent):
        paned = tk.PanedWindow(parent, orient="horizontal", bg=THEME["bg_dark"], sashwidth=4)
        paned.pack(fill="both", expand=True)

        # Left: Snapshots Table
        left = tk.Frame(paned, bg=THEME["bg_dark"])
        paned.add(left, minsize=480)

        card_snaps = ModernCard(left, "Forensic Threat Snapshots")
        card_snaps.pack(fill="both", expand=True)

        columns = ("id", "time", "severity", "process", "pid", "file")
        self.treeSnapshots = ttk.Treeview(card_snaps, columns=columns, show="headings", selectmode="browse")
        self.treeSnapshots.heading("id", text="ID")
        self.treeSnapshots.heading("time", text="Timestamp")
        self.treeSnapshots.heading("severity", text="Severity")
        self.treeSnapshots.heading("process", text="Process")
        self.treeSnapshots.heading("pid", text="PID")
        self.treeSnapshots.heading("file", text="Target File")

        self.treeSnapshots.column("id", width=45, anchor="center")
        self.treeSnapshots.column("time", width=130, anchor="w")
        self.treeSnapshots.column("severity", width=80, anchor="center")
        self.treeSnapshots.column("process", width=110, anchor="w")
        self.treeSnapshots.column("pid", width=65, anchor="center")
        self.treeSnapshots.column("file", width=150, anchor="w")

        scroll_s = ttk.Scrollbar(card_snaps, orient="vertical", command=self.treeSnapshots.yview)
        self.treeSnapshots.configure(yscrollcommand=scroll_s.set)
        self.treeSnapshots.pack(side="left", fill="both", expand=True, pady=4)
        scroll_s.pack(side="right", fill="y", pady=4)

        self.treeSnapshots.bind("<<TreeviewSelect>>", self.onSnapshotSelected)

        # Right: Forensic Hierarchy Inspector
        right = tk.Frame(paned, bg=THEME["bg_dark"])
        paned.add(right, minsize=480)

        card_detail = ModernCard(right, "Process Ancestry Tree & Artifact Evidence")
        card_detail.pack(fill="both", expand=True)

        # Ancestor Tree
        self.treeLineage = ttk.Treeview(card_detail, columns=("pid", "name", "cmd"), show="tree headings", selectmode="browse", height=6)
        self.treeLineage.heading("#0", text="Ancestry Hierarchy")
        self.treeLineage.heading("pid", text="PID")
        self.treeLineage.heading("name", text="Executable")
        self.treeLineage.heading("cmd", text="Command Line")

        self.treeLineage.column("#0", width=140)
        self.treeLineage.column("pid", width=60, anchor="center")
        self.treeLineage.column("name", width=110, anchor="w")
        self.treeLineage.column("cmd", width=220, anchor="w")

        self.treeLineage.pack(fill="x", pady=4)

        # Detail Text Box
        lbl_raw = tk.Label(card_detail, text="INCIDENT EVIDENCE & HOST DIAGNOSTICS", font=(THEME["font_family"], 8, "bold"), fg=THEME["text_secondary"], bg=THEME["bg_surface"])
        lbl_raw.pack(anchor="w", pady=(8, 2))

        self.txtForensicDetails = tk.Text(
            card_detail,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=("Consolas", 9),
            wrap="word",
            borderwidth=0,
            highlightbackground=THEME["border"],
            highlightthickness=1,
        )
        self.txtForensicDetails.pack(fill="both", expand=True, pady=4)

        btn_export = ttk.Button(card_detail, text="📄 Export Incident Evidence (JSON)", style="Secondary.TButton", command=self.actionExportForensicJson)
        btn_export.pack(anchor="w", pady=(4, 0))

    # ------------------------------------------------------------------------
    # Tab 3: System Health & Observability
    # ------------------------------------------------------------------------
    def _buildTabHealth(self, parent):
        grid_frame = tk.Frame(parent, bg=THEME["bg_dark"])
        grid_frame.pack(fill="both", expand=True)

        # Left Column: Subsystem Status
        card_components = ModernCard(grid_frame, "Subsystem Diagnostic Health Breakdown")
        card_components.pack(side="left", fill="both", expand=True, padx=4, pady=4)

        self.lblHealthSummary = tk.Label(
            card_components,
            text="Overall Health: HEALTHY",
            font=(THEME["font_family"], 12, "bold"),
            fg=THEME["safe_green"],
            bg=THEME["bg_surface"],
        )
        self.lblHealthSummary.pack(anchor="w", pady=6)

        self.treeHealth = ttk.Treeview(card_components, columns=("comp", "status", "latency", "message"), show="headings", height=8)
        self.treeHealth.heading("comp", text="Component")
        self.treeHealth.heading("status", text="Status")
        self.treeHealth.heading("latency", text="Latency")
        self.treeHealth.heading("message", text="Diagnostic Details")

        self.treeHealth.column("comp", width=120)
        self.treeHealth.column("status", width=90, anchor="center")
        self.treeHealth.column("latency", width=80, anchor="center")
        self.treeHealth.column("message", width=220)

        self.treeHealth.pack(fill="both", expand=True, pady=6)

        btn_run_health = ttk.Button(card_components, text="🔄 Re-run Deep Health Diagnostics", style="Secondary.TButton", command=self.actionRefreshHealth)
        btn_run_health.pack(anchor="w", pady=4)

        # Right Column: System Resources & Storage Statistics
        card_resources = ModernCard(grid_frame, "Host Resource Telemetry & Database Metrics")
        card_resources.pack(side="right", fill="both", expand=True, padx=4, pady=4)

        self.txtHealthTelemetry = tk.Text(
            card_resources,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=("Consolas", 9),
            wrap="word",
            borderwidth=0,
        )
        self.txtHealthTelemetry.pack(fill="both", expand=True, pady=6)

    # ------------------------------------------------------------------------
    # Tab 4: ML Model & Retraining Pipeline
    # ------------------------------------------------------------------------
    def _buildTabModels(self, parent):
        container = tk.Frame(parent, bg=THEME["bg_dark"])
        container.pack(fill="both", expand=True)

        # Active Model Info Card
        card_model = ModernCard(container, "Active Prediction Model Artifact")
        card_model.pack(fill="x", padx=4, pady=4)

        self.lblActiveModelPath = tk.Label(
            card_model,
            text="Artifact Path: ...",
            font=(THEME["font_family"], 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_surface"],
        )
        self.lblActiveModelPath.pack(anchor="w")

        self.lblModelEncryption = tk.Label(
            card_model,
            text="Encryption: AES-256-GCM Authenticated • HMAC-SHA256 Integrity Verified",
            font=(THEME["font_family"], 9),
            fg=THEME["safe_green"],
            bg=THEME["bg_surface"],
        )
        self.lblModelEncryption.pack(anchor="w", pady=2)

        # Hot-Swap Tool Frame
        swap_frame = tk.Frame(card_model, bg=THEME["bg_surface"])
        swap_frame.pack(fill="x", pady=8)

        btn_select_model = ttk.Button(swap_frame, text="Select Candidate Model...", style="Secondary.TButton", command=self.actionSelectCandidateModel)
        btn_select_model.pack(side="left", padx=(0, 6))

        self.lblCandidateModel = tk.Label(swap_frame, text="No candidate chosen", font=(THEME["font_family"], 9), fg=THEME["text_secondary"], bg=THEME["bg_surface"])
        self.lblCandidateModel.pack(side="left", padx=4)

        self.btnSwapModel = ttk.Button(swap_frame, text="⚡ Execute Atomic Zero-Downtime Hot-Swap", style="Primary.TButton", state="disabled", command=self.actionExecuteModelSwap)
        self.btnSwapModel.pack(side="right")

        # Retraining Pipeline Section
        card_retrain = ModernCard(container, "Closed-Loop Automated Retraining Pipeline")
        card_retrain.pack(fill="both", expand=True, padx=4, pady=4)

        retrain_header = tk.Frame(card_retrain, bg=THEME["bg_surface"])
        retrain_header.pack(fill="x", pady=4)

        self.lblFeedbackCount = tk.Label(
            retrain_header,
            text="Queued Feedback Samples: 0",
            font=(THEME["font_family"], 10, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_surface"],
        )
        self.lblFeedbackCount.pack(side="left")

        btn_retrain = ttk.Button(retrain_header, text="🚀 Trigger Retraining & Validation", style="Primary.TButton", command=self.actionTriggerRetraining)
        btn_retrain.pack(side="right")

        self.txtRetrainLog = tk.Text(
            card_retrain,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=("Consolas", 9),
            wrap="word",
            height=10,
        )
        self.txtRetrainLog.pack(fill="both", expand=True, pady=6)

    # ------------------------------------------------------------------------
    # Tab 5: Live Lab & Demonstration Center
    # ------------------------------------------------------------------------
    def _buildTabDemo(self, parent):
        container = tk.Frame(parent, bg=THEME["bg_dark"])
        container.pack(fill="both", expand=True)

        # Overview and Guidance Card
        card_guide = ModernCard(container, "Interactive Demonstration & Safe Lab Center")
        card_guide.pack(fill="x", padx=4, pady=4)

        lbl_desc = tk.Label(
            card_guide,
            text=(
                "Use this interactive sandbox to safely demonstrate the behavioral detection system in action.\n"
                "• Normal Mode creates benign documents (Word, Excel, PDF, CSV, JSON, Python, Images) and simulates typical office typing/saving.\n"
                "• Attack Mode executes safe rapid renames and high-entropy modifications strictly inside 'testFiles' to showcase instant detection."
            ),
            font=(THEME["font_family"], 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
            justify="left",
        )
        lbl_desc.pack(anchor="w", pady=(0, 6))

        # Demo Controls Two-Column Frame
        ctrl_frame = tk.Frame(container, bg=THEME["bg_dark"])
        ctrl_frame.pack(fill="x", padx=0, pady=2)

        # Left Column: Benign File Generation & Normal Activity
        card_benign = ModernCard(ctrl_frame, "1. Benign Files & Normal User Workload")
        card_benign.pack(side="left", fill="both", expand=True, padx=4)

        row_gen = tk.Frame(card_benign, bg=THEME["bg_surface"])
        row_gen.pack(fill="x", pady=4)
        tk.Label(row_gen, text="Document Count:", fg=THEME["text_secondary"], bg=THEME["bg_surface"]).pack(side="left")
        self.spnBenignCount = ttk.Spinbox(row_gen, from_=5, to=500, width=6)
        self.spnBenignCount.set(25)
        self.spnBenignCount.pack(side="left", padx=8)

        btn_gen = ttk.Button(row_gen, text="📄 Generate Benign Documents", style="Primary.TButton", command=self.actionDemoGenerateBenign)
        btn_gen.pack(side="right")

        row_norm = tk.Frame(card_benign, bg=THEME["bg_surface"])
        row_norm.pack(fill="x", pady=6)
        tk.Label(row_norm, text="User Action Steps:", fg=THEME["text_secondary"], bg=THEME["bg_surface"]).pack(side="left")
        self.spnNormalSteps = ttk.Spinbox(row_norm, from_=3, to=50, width=6)
        self.spnNormalSteps.set(10)
        self.spnNormalSteps.pack(side="left", padx=8)

        btn_norm = ttk.Button(row_norm, text="👤 Simulate Normal Office Work", style="Secondary.TButton", command=self.actionDemoSimulateNormal)
        btn_norm.pack(side="right")

        # Right Column: Sandboxed Ransomware Attack & Cleanup
        card_attack = ModernCard(ctrl_frame, "2. Ransomware Attack Simulation & Reset")
        card_attack.pack(side="right", fill="both", expand=True, padx=4)

        row_atk = tk.Frame(card_attack, bg=THEME["bg_surface"])
        row_atk.pack(fill="x", pady=4)
        tk.Label(row_atk, text="Target Files:", fg=THEME["text_secondary"], bg=THEME["bg_surface"]).pack(side="left")
        self.spnAttackCount = ttk.Spinbox(row_atk, from_=5, to=200, width=6)
        self.spnAttackCount.set(20)
        self.spnAttackCount.pack(side="left", padx=8)

        btn_atk = ttk.Button(row_atk, text="🚨 Simulate Ransomware Attack", style="Danger.TButton", command=self.actionDemoSimulateAttack)
        btn_atk.pack(side="right")

        row_clean = tk.Frame(card_attack, bg=THEME["bg_surface"])
        row_clean.pack(fill="x", pady=6)

        btn_open_demo = ttk.Button(row_clean, text="📂 Open Demo Folder", style="Secondary.TButton", command=self.actionDemoOpenFolder)
        btn_open_demo.pack(side="left")

        btn_clean = ttk.Button(row_clean, text="🧹 Clean Sandbox Folder", style="Secondary.TButton", command=self.actionDemoCleanSandbox)
        btn_clean.pack(side="right")

        # Bottom Progress & Console Output Card
        card_log = ModernCard(container, "Live Demonstration Progress & Output Console")
        card_log.pack(fill="both", expand=True, padx=4, pady=4)

        self.txtDemoLog = tk.Text(
            card_log,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=("Consolas", 9),
            wrap="word",
            height=8,
        )
        self.txtDemoLog.pack(fill="both", expand=True, pady=4)
        self.txtDemoLog.insert("1.0", "[*] Demonstration Lab Ready. Click 'Generate Benign Documents' or 'Simulate Normal Office Work' to begin.\n")

    # ------------------------------------------------------------------------
    # Tab 6: Settings & Paths
    # ------------------------------------------------------------------------
    def _buildTabSettings(self, parent):
        container = tk.Frame(parent, bg=THEME["bg_dark"])
        container.pack(fill="both", expand=True)

        # Monitored Paths Manager
        card_paths = ModernCard(container, "Monitored Target Directories")
        card_paths.pack(fill="x", padx=4, pady=4)

        self.listPaths = tk.Listbox(
            card_paths,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            highlightthickness=0,
            selectbackground=THEME["accent_indigo"],
            font=(THEME["font_family"], 9),
            height=4,
        )
        self.listPaths.pack(fill="x", pady=4)

        paths_btn_row = tk.Frame(card_paths, bg=THEME["bg_surface"])
        paths_btn_row.pack(fill="x", pady=4)

        btn_add_path = ttk.Button(paths_btn_row, text="➕ Add Monitored Folder...", style="Secondary.TButton", command=self.actionAddMonitoredPath)
        btn_add_path.pack(side="left", padx=(0, 6))

        btn_remove_path = ttk.Button(paths_btn_row, text="➖ Remove Selected Folder", style="Secondary.TButton", command=self.actionRemoveMonitoredPath)
        btn_remove_path.pack(side="left", padx=6)

        btn_open_folder = ttk.Button(paths_btn_row, text="📂 Open in Windows Explorer", style="Secondary.TButton", command=self.actionOpenFolderExplorer)
        btn_open_folder.pack(side="left", padx=6)

        # Operational Settings & Maintenance
        card_settings = ModernCard(container, "Detection Policy Parameters & Database Maintenance")
        card_settings.pack(fill="both", expand=True, padx=4, pady=4)

        settings_grid = tk.Frame(card_settings, bg=THEME["bg_surface"])
        settings_grid.pack(fill="x", pady=6)

        tk.Label(settings_grid, text="Alert Cooldown (Seconds):", fg=THEME["text_secondary"], bg=THEME["bg_surface"]).grid(row=0, column=0, sticky="w", pady=4)
        self.spnCooldown = ttk.Spinbox(settings_grid, from_=5, to=600, width=8)
        self.spnCooldown.set(self.configuration["monitoring"].get("alertCooldownSeconds", 45))
        self.spnCooldown.grid(row=0, column=1, sticky="w", padx=8)

        tk.Label(settings_grid, text="Monitoring Interval (Seconds):", fg=THEME["text_secondary"], bg=THEME["bg_surface"]).grid(row=0, column=2, sticky="w", padx=(20, 0), pady=4)
        self.spnInterval = ttk.Spinbox(settings_grid, from_=0.5, to=30.0, increment=0.5, width=8)
        self.spnInterval.set(self.configuration["monitoring"].get("intervalSeconds", 2.0))
        self.spnInterval.grid(row=0, column=3, sticky="w", padx=8)

        tk.Label(settings_grid, text="Detection Sensitivity:", fg=THEME["text_secondary"], bg=THEME["bg_surface"]).grid(row=1, column=0, sticky="w", pady=6)
        self.cmbSensitivity = ttk.Combobox(settings_grid, values=["conservative", "balanced", "aggressive"], state="readonly", width=14)
        self.cmbSensitivity.set(self.configuration["monitoring"].get("sensitivity", "balanced"))
        self.cmbSensitivity.grid(row=1, column=1, sticky="w", padx=8)

        btn_save_config = ttk.Button(settings_grid, text="💾 Save Configuration Changes", style="Primary.TButton", command=self.actionSaveConfiguration)
        btn_save_config.grid(row=1, column=2, columnspan=2, sticky="w", padx=(20, 0))

        ttk.Separator(card_settings, orient="horizontal").pack(fill="x", pady=10)

        maint_row = tk.Frame(card_settings, bg=THEME["bg_surface"])
        maint_row.pack(fill="x", pady=4)

        btn_backup = ttk.Button(maint_row, text="📦 Create Database Backup Snapshot", style="Secondary.TButton", command=self.actionBackupDatabase)
        btn_backup.pack(side="left", padx=(0, 6))

        btn_prune = ttk.Button(maint_row, text="🧹 Prune Data (Older than 30 days)", style="Secondary.TButton", command=self.actionPruneDatabase)
        btn_prune.pack(side="left", padx=6)

        btn_optimize = ttk.Button(maint_row, text="⚡ Optimize Database & Checkpoint WAL", style="Secondary.TButton", command=self.actionOptimizeDatabase)
        btn_optimize.pack(side="left", padx=6)

    # ========================================================================
    # Data Loading & Periodic Refresh
    # ========================================================================
    def _loadInitialData(self):
        """Populate initial UI contents from configuration and database."""
        self._refreshPathsList()
        self.lblActiveModelPath.config(text=f"Artifact Path: {self.modelPath}")
        self.actionRefreshHealth()
        self._refreshForensicsTable()

    def _refreshPathsList(self):
        self.listPaths.delete(0, tk.END)
        for p in self.monitoredPaths:
            self.listPaths.insert(tk.END, str(p))
        self.cardPaths.setValue(f"{len(self.monitoredPaths)} Folder(s)", f"Primary: {self.monitoredPaths[0].name if self.monitoredPaths else 'None'}")

    def _periodicRefresh(self):
        """Periodic background refresh (every 500ms). Reads SQLite without blocking."""
        try:
            # Drain any pending events from worker thread
            while not self._eventQueue.empty():
                decision, eventCount, summary = self._eventQueue.get_nowait()
                self._handleWorkerDecision(decision, eventCount, summary)

            if self.isMonitoring and self.sessionStartTime:
                uptime = datetime.now() - self.sessionStartTime
                hours, rem = divmod(int(uptime.total_seconds()), 3600)
                mins, secs = divmod(rem, 60)
                self.lblUptimeSummary.config(text=f"Session Uptime: {hours:02d}:{mins:02d}:{secs:02d}")

            # Query database statistics
            if self.databasePath.is_file():
                conn = sqlite3.connect(self.databasePath, timeout=1.0)
                try:
                    cur = conn.cursor()
                    # Total file events in current session
                    event_row = cur.execute(
                        "SELECT COUNT(*) FROM fileEvents WHERE sessionId = (SELECT sessionId FROM sessions ORDER BY sessionId DESC LIMIT 1)"
                    ).fetchone()
                    total_events = event_row[0] if event_row else 0
                    self.cardEvents.setValue(str(total_events))

                    # Total detections
                    det_row = cur.execute("SELECT COUNT(*) FROM detections WHERE classification != 'benign'").fetchone()
                    total_dets = det_row[0] if det_row else 0
                    self.cardDetections.setValue(str(total_dets), color=THEME["danger_red"] if total_dets > 0 else THEME["text_primary"])

                    # Feedback samples queued for retraining
                    fb_row = cur.execute("SELECT COUNT(*) FROM detectionFeedback WHERE usedInRetraining = 0").fetchone()
                    fb_count = fb_row[0] if fb_row else 0
                    self.lblFeedbackCount.config(text=f"Queued Feedback Samples: {fb_count}")

                    # Recent file events for live table
                    recent_events = cur.execute(
                        "SELECT occurredAt, action, processName, processId, pathHash, pathId FROM fileEvents ORDER BY eventId DESC LIMIT 25"
                    ).fetchall()

                    # Only update if count changed to preserve selection
                    current_items = len(self.treeEvents.get_children())
                    if len(recent_events) != current_items or current_items == 0:
                        self.treeEvents.delete(*self.treeEvents.get_children())
                        for row in recent_events:
                            t_str = row[0][:19].replace("T", " ")
                            action_str = row[1].upper()
                            proc_str = row[2] or "system"
                            pid_str = str(row[3]) if row[3] else "—"
                            hash_str = row[4] or "—"
                            p_id = str(row[5]) if row[5] else "1"
                            self.treeEvents.insert("", "end", values=(t_str, action_str, proc_str, pid_str, hash_str, p_id))

                    # Recent detections for sidebar list
                    recent_dets = cur.execute(
                        "SELECT occurredAt, classification, riskScore FROM detections ORDER BY detectionId DESC LIMIT 8"
                    ).fetchall()
                    self.listRecentDetections.delete(0, tk.END)
                    for r in recent_dets:
                        t = r[0][:19].replace("T", " ")
                        self.listRecentDetections.insert(tk.END, f"{t}  •  {r[1].upper()} (score: {float(r[2]):.2f})")

                finally:
                    conn.close()

        except Exception as error:
            logger.debug(f"Periodic refresh error: {error}")

        # Schedule next cycle
        self._pollTimerId = self.after(500, self._periodicRefresh)

    # ========================================================================
    # Actions & Handlers
    # ========================================================================
    def actionToggleProtection(self):
        """Start or stop real-time background protection."""
        if not self.isMonitoring:
            # START PROTECTION
            try:
                self.worker = MonitoringWorker(
                    monitoredPaths=self.monitoredPaths,
                    databasePath=self.databasePath,
                    modelPath=self.modelPath if self.modelPath.is_file() else None,
                    intervalSeconds=float(self.configuration["monitoring"].get("intervalSeconds", 2.0)),
                    onDecision=lambda d, c, s: self._eventQueue.put((d, c, s)),
                    onError=lambda err: self.after(0, lambda: messagebox.showerror("Monitoring Error", f"Worker failure: {err}")),
                    enableHotReload=True,
                )
                self.worker.start()
                self.isMonitoring = True
                self.sessionStartTime = datetime.now()

                self.btnToggleProtection.config(text="⏹ Stop Protection", style="Danger.TButton")
                self.statusPill.config(text="● PROTECTED", fg=THEME["safe_green"], bg=THEME["safe_bg"])
                self.cardProtection.setValue("ACTIVE", "Monitoring Folders", THEME["safe_green"])
                self.lblStatusLeft.config(text=f"Protection Active • {len(self.monitoredPaths)} path(s) watched")

            except Exception as error:
                messagebox.showerror("Protection Start Failed", str(error))
        else:
            # STOP PROTECTION
            if self.worker is not None:
                self.worker.stop()
                self.worker = None

            self.isMonitoring = False
            self.sessionStartTime = None

            self.btnToggleProtection.config(text="▶ Start Protection", style="Success.TButton")
            self.statusPill.config(text="● STOPPED", fg=THEME["warning_amber"], bg=THEME["warning_bg"])
            self.cardProtection.setValue("IDLE", "Protection Halted", THEME["warning_amber"])
            self.lblStatusLeft.config(text="Protection Stopped")

    def _handleWorkerDecision(self, decision: RiskDecision, eventCount: int, summary: str):
        """Update threat status and gauges upon receiving risk decision from engine."""
        self.currentThreatLevel = decision.level.value
        self.currentRiskScore = decision.score

        color_map = {
            "low": THEME["safe_green"],
            "medium": THEME["warning_amber"],
            "high": "#f97316",
            "critical": THEME["danger_red"],
        }
        chosen_color = color_map.get(self.currentThreatLevel, THEME["text_primary"])

        self.cardThreat.setValue(self.currentThreatLevel.upper(), f"Class: {decision.classification}", chosen_color)
        self.cardRisk.setValue(f"{self.currentRiskScore:.4f}", f"Action: {decision.action}", chosen_color)

        if self.currentThreatLevel in ("high", "critical"):
            self.threatBanner.pack(fill="x", side="top", before=self.notebook)
            self.threatBannerLabel.config(text=f"🚨 THREAT DETECTED: {decision.classification.upper()} (Risk: {self.currentRiskScore:.4f})")
        elif self.currentThreatLevel == "medium":
            self.threatBanner.pack(fill="x", side="top", before=self.notebook)
            self.threatBannerLabel.config(text=f"⚠️ SUSPICIOUS BEHAVIOR: {decision.classification} (Risk: {self.currentRiskScore:.4f})")
        else:
            self.threatBanner.pack_forget()

    def actionQuickScan(self):
        """Execute on-demand threat scan across monitored paths."""
        try:
            controller = DetectionController(
                monitoredPaths=self.monitoredPaths,
                databasePath=self.databasePath,
                modelPath=self.modelPath if self.modelPath.is_file() else None,
            )
            try:
                decision = controller.collectOnce()
            finally:
                controller.close()

            self._handleWorkerDecision(decision, controller.lastCollectedEventCount, controller.lastEventSummary)

            if decision.level.value == "low":
                messagebox.showinfo("Quick Scan Complete", f"Scan Status: CLEAN\nRisk Score: {decision.score:.4f}\nClassification: {decision.classification}")
            else:
                messagebox.showwarning("Threat Identified", f"Threat Level: {decision.level.value.upper()}\nRisk Score: {decision.score:.4f}\nClassification: {decision.classification}")

        except Exception as error:
            messagebox.showerror("Scan Failed", str(error))

    def actionShowHealth(self):
        """Switch to Health tab and run diagnostics."""
        self.notebook.select(self.tabHealth)
        self.actionRefreshHealth()

    def actionRefreshHealth(self):
        """Run deep health check diagnostics and update table & telemetry text."""
        try:
            checker = HealthChecker(
                configuration=self.configuration,
                databasePath=self.databasePath,
            )
            report = checker.runFullCheck()

            status_str = str(report.status.value).lower()
            status_color = (
                THEME["safe_green"]
                if status_str == "healthy"
                else (THEME["warning_amber"] if status_str == "degraded" else THEME["danger_red"])
            )
            self.lblHealthSummary.config(text=f"Overall Health: {status_str.upper()}", fg=status_color)

            self.treeHealth.delete(*self.treeHealth.get_children())
            for name, comp in report.components.items():
                self.treeHealth.insert("", "end", values=(name, comp.status.value.upper(), f"{comp.latencyMs:.1f} ms", comp.message))

            # Format host observability telemetry
            metrics = report.metrics
            stats = {}
            if self.databasePath.is_file():
                try:
                    conn = sqlite3.connect(self.databasePath)
                    stats = getDatabaseStatistics(conn)
                    conn.close()
                except Exception:
                    pass

            telemetry_text = (
                f"HOST SYSTEM & OBSERVABILITY TELEMETRY\n"
                f"──────────────────────────────────────────────────────────\n"
                f"CPU Utilization:       {metrics.processCpuPercent:.1f}%\n"
                f"Memory Usage (RSS):    {metrics.processMemoryRssMb:.1f} MB\n"
                f"Thread Count:          {metrics.threadCount}\n"
                f"Open File Handles:     {metrics.openFileHandles}\n"
                f"Process Uptime:        {metrics.processUptimeSeconds:.1f} s\n\n"
                f"SQLITE DATABASE STORAGE METRICS\n"
                f"──────────────────────────────────────────────────────────\n"
                f"Database File Size:    {stats.get('totalSizeBytes', 0) / 1024:.1f} KB\n"
                f"Free Freelist Space:   {stats.get('freeSizeBytes', 0) / 1024:.1f} KB\n"
                f"Page Count:            {stats.get('pageCount', 0)}\n"
                f"Page Size:             {stats.get('pageSize', 0)} bytes\n"
            )
            self.txtHealthTelemetry.delete("1.0", tk.END)
            self.txtHealthTelemetry.insert("1.0", telemetry_text)
        except Exception as error:
            logger.warning(f"Health refresh error: {error}")

    def _refreshForensicsTable(self):
        """Query and populate forensic snapshots table."""
        if not self.databasePath.is_file():
            return
        try:
            collector = ForensicCollector()
            conn = sqlite3.connect(self.databasePath)
            try:
                snapshots = collector.getRecentSnapshots(conn, limit=50)
            finally:
                conn.close()

            self.treeSnapshots.delete(*self.treeSnapshots.get_children())
            for snap in snapshots:
                t = snap.capturedAt[:19].replace("T", " ")
                self.treeSnapshots.insert(
                    "",
                    "end",
                    values=(
                        snap.snapshotId,
                        t,
                        snap.threatLevel.upper(),
                        snap.targetProcessName or "system",
                        snap.targetProcessId or "—",
                        Path(snap.targetFilePath).name if snap.targetFilePath else "—",
                    ),
                )
        except Exception as error:
            logger.debug(f"Error loading forensics: {error}")

    def onSnapshotSelected(self, event):
        """Display lineage tree and forensic evidence when snapshot row clicked."""
        selected = self.treeSnapshots.selection()
        if not selected:
            return
        item = self.treeSnapshots.item(selected[0])
        snap_id = item["values"][0]

        try:
            collector = ForensicCollector()
            conn = sqlite3.connect(self.databasePath)
            try:
                snapshot = collector.getSnapshot(conn, snapshotId=int(snap_id))
            finally:
                conn.close()

            if not snapshot:
                return

            # Populate Ancestry Tree
            self.treeLineage.delete(*self.treeLineage.get_children())
            ancestors = snapshot.processTreeAncestors or []

            parent_node = ""
            for idx, proc in enumerate(ancestors):
                p_label = f"Ancestry Level {idx + 1}" if idx < len(ancestors) - 1 else "Target Process"
                node = self.treeLineage.insert(
                    parent_node,
                    "end",
                    text=p_label,
                    values=(proc.get("pid", "—"), proc.get("name", "—"), proc.get("commandLine", "—") or "—"),
                    open=True,
                )
                parent_node = node

            # Populate Detailed Text
            report_text = collector.formatConsoleReport(snapshot)
            self.txtForensicDetails.delete("1.0", tk.END)
            self.txtForensicDetails.insert("1.0", report_text)

        except Exception as error:
            logger.error(f"Error displaying snapshot: {error}")

    def actionExportForensicJson(self):
        """Export selected forensic snapshot as structured JSON."""
        selected = self.treeSnapshots.selection()
        if not selected:
            messagebox.showwarning("No Snapshot Selected", "Please select a forensic snapshot to export.")
            return

        snap_id = self.treeSnapshots.item(selected[0])["values"][0]
        collector = ForensicCollector()
        conn = sqlite3.connect(self.databasePath)
        try:
            snapshot = collector.getSnapshot(conn, snapshotId=int(snap_id))
        finally:
            conn.close()

        if not snapshot:
            return

        out_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            initialfile=f"forensic_incident_{snap_id}.json",
            title="Save Forensic Evidence",
        )
        if out_path:
            Path(out_path).write_text(collector.formatJson(snapshot), encoding="utf-8")
            messagebox.showinfo("Export Successful", f"Saved incident evidence to:\n{out_path}")

    def actionSelectCandidateModel(self):
        """Browse and preflight test candidate ML model."""
        selected = filedialog.askopenfilename(
            title="Select Candidate .joblib Model",
            filetypes=[("Joblib Model Files", "*.joblib"), ("All Files", "*.*")],
        )
        if not selected:
            return

        cand_path = Path(selected)
        try:
            predictor = ModelPredictor(cand_path)
            self.lblCandidateModel.config(
                text=f"Valid: {cand_path.name} ({type(predictor.model).__name__})",
                fg=THEME["safe_green"],
            )
            self.btnSwapModel.config(state="normal")
            self._candidateModelPath = cand_path
        except Exception as error:
            self.lblCandidateModel.config(text=f"Invalid: {error}", fg=THEME["danger_red"])
            self.btnSwapModel.config(state="disabled")
            self._candidateModelPath = None

    def actionExecuteModelSwap(self):
        """Perform zero-downtime hot-swap to candidate model."""
        if not hasattr(self, "_candidateModelPath") or not self._candidateModelPath:
            return

        if self.worker is not None:
            success, msg = self.worker.swapModel(self._candidateModelPath)
        else:
            try:
                predictor = ModelPredictor(self._candidateModelPath)
                self.modelPath = self._candidateModelPath
                success, msg = True, f"Model successfully swapped to {self._candidateModelPath.name}"
            except Exception as error:
                success, msg = False, str(error)

        if success:
            self.modelPath = self._candidateModelPath
            self.lblActiveModelPath.config(text=f"Artifact Path: {self.modelPath}")
            messagebox.showinfo("Model Hot-Swap Complete", msg)
            self.btnSwapModel.config(state="disabled")
            self.lblCandidateModel.config(text="Model active", fg=THEME["text_secondary"])
        else:
            messagebox.showerror("Hot-Swap Rejected", msg)

    def actionTriggerRetraining(self):
        """Execute automated model retraining pipeline in background thread."""
        self.txtRetrainLog.delete("1.0", tk.END)
        self.txtRetrainLog.insert("1.0", "[*] Starting automated retraining pipeline...\n")

        def _run():
            try:
                pipeline = RetrainingPipeline(
                    databasePath=self.databasePath,
                    activeModelPath=self.modelPath,
                )
                run = pipeline.runPipeline(force=True)

                log_lines = [
                    f"[+] Retraining Run ID: {run.runId}",
                    f"[+] Timestamp: {run.startedAt}",
                    f"[+] Status: {run.status.upper()}",
                    f"[+] Candidate Accuracy: {run.candidateMetrics.get('accuracy', 0):.4f}",
                    f"[+] Candidate F1 Score: {run.candidateMetrics.get('f1', 0):.4f}",
                    f"[+] Candidate ROC-AUC:  {run.candidateMetrics.get('rocAuc', 0):.4f}",
                    f"[+] Promoted: {run.promoted}",
                    f"[+] Details: {run.details}",
                ]
                self.after(0, lambda: self._appendRetrainLog("\n".join(log_lines)))
                if run.promoted and run.candidateModelPath:
                    self.after(0, lambda: messagebox.showinfo("Retraining Success", f"New model promoted:\n{run.candidateModelPath}"))
            except Exception as error:
                self.after(0, lambda: self._appendRetrainLog(f"[-] Retraining failed: {error}"))

        threading.Thread(target=_run, daemon=True).start()

    def _appendRetrainLog(self, text: str):
        self.txtRetrainLog.insert(tk.END, text + "\n")
        self.txtRetrainLog.see(tk.END)

    def actionAddMonitoredPath(self):
        """Add a directory path to monitored folders."""
        selected = filedialog.askdirectory(title="Choose Folder to Protect")
        if not selected:
            return
        try:
            resolved = resolveMonitoringPath(selected)
            if resolved not in self.monitoredPaths:
                self.monitoredPaths.append(resolved)
                self._refreshPathsList()
                self.actionSaveConfiguration(quiet=True)
                messagebox.showinfo("Path Added", f"Now protecting:\n{resolved}")
        except Exception as error:
            messagebox.showerror("Invalid Path", str(error))

    def actionRemoveMonitoredPath(self):
        """Remove selected folder from monitoring list."""
        sel_idx = self.listPaths.curselection()
        if not sel_idx:
            return
        idx = sel_idx[0]
        if len(self.monitoredPaths) <= 1:
            messagebox.showwarning("Cannot Remove", "At least one monitored directory path is required.")
            return
        removed = self.monitoredPaths.pop(idx)
        self._refreshPathsList()
        self.actionSaveConfiguration(quiet=True)
        messagebox.showinfo("Path Removed", f"Removed folder:\n{removed}")

    def actionOpenFolderExplorer(self):
        """Open the selected directory in Windows Explorer."""
        sel_idx = self.listPaths.curselection()
        path_to_open = self.monitoredPaths[sel_idx[0]] if sel_idx else self.monitoredPaths[0]
        if path_to_open.exists():
            subprocess.Popen(f'explorer "{path_to_open}"')

    def actionSaveConfiguration(self, quiet: bool = False):
        """Save settings to settings.json and apply hot-reload."""
        try:
            cfg = dict(self.configuration)
            cfg["monitoring"]["alertCooldownSeconds"] = int(self.spnCooldown.get())
            cfg["monitoring"]["intervalSeconds"] = float(self.spnInterval.get())
            cfg["monitoring"]["sensitivity"] = self.cmbSensitivity.get()
            cfg["monitoring"]["paths"] = [str(p) for p in self.monitoredPaths]

            validateConfiguration(cfg)

            settings_path = getDataDirectory() / "settings.json"
            settings_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            self.configuration = cfg

            if self.worker is not None:
                self.worker.reloadConfiguration(settings_path)

            if not quiet:
                messagebox.showinfo("Settings Saved", "Configuration updated and applied live.")
        except Exception as error:
            messagebox.showerror("Configuration Error", str(error))

    def actionBackupDatabase(self):
        """Execute database backup snapshot."""
        try:
            bm = BackupManager(databasePath=self.databasePath)
            rec = bm.createBackup(reason="manual_ui_snapshot")
            messagebox.showinfo("Backup Created", f"Backup snapshot created:\n{rec.backupPath.name}\nSize: {rec.sizeBytes / 1024:.1f} KB")
        except Exception as error:
            messagebox.showerror("Backup Failed", str(error))

    def actionPruneDatabase(self):
        """Prune benign records older than 30 days."""
        try:
            conn = sqlite3.connect(self.databasePath)
            counts = pruneOldData(conn, retentionDays=30, preserveThreats=True)
            conn.close()
            pruned_msg = "\n".join(f"• {k}: {v} rows" for k, v in counts.items())
            messagebox.showinfo("Database Pruned", f"Pruned benign records:\n{pruned_msg}")
        except Exception as error:
            messagebox.showerror("Pruning Failed", str(error))

    def actionOptimizeDatabase(self):
        """Optimize SQLite indexes, update statistics, and checkpoint WAL."""
        try:
            conn = sqlite3.connect(self.databasePath)
            stats = optimizeDatabase(conn)
            conn.close()
            messagebox.showinfo("Database Optimized", f"SQLite Optimization & WAL Checkpoint Complete.\nDatabase Size: {stats.get('totalSizeBytes', 0) / 1024:.1f} KB")
        except Exception as error:
            messagebox.showerror("Optimization Failed", str(error))

    def _appendDemoLog(self, text: str):
        self.txtDemoLog.insert(tk.END, text + "\n")
        self.txtDemoLog.see(tk.END)

    def actionDemoGenerateBenign(self):
        """Generate benign documents in background thread."""
        try:
            count = int(self.spnBenignCount.get())
        except ValueError:
            count = 25

        self._appendDemoLog(f"[*] Generating {count} benign office documents...")

        def _run():
            try:
                engine = DemoEngine()
                report = engine.generateBenignFiles(
                    count=count,
                    callback=lambda cur, tot, name: self.after(0, lambda: self._appendDemoLog(f"  [+] ({cur}/{tot}) Created {name}")),
                )
                self.after(0, lambda: self._appendDemoLog(f"[✓] Successfully generated {report.filesCreated} files in {report.durationSeconds:.2f}s.\n"))
            except Exception as error:
                self.after(0, lambda: self._appendDemoLog(f"[-] Generation error: {error}\n"))

        threading.Thread(target=_run, daemon=True).start()

    def actionDemoSimulateNormal(self):
        """Simulate normal office workflow in background thread."""
        try:
            steps = int(self.spnNormalSteps.get())
        except ValueError:
            steps = 10

        self._appendDemoLog(f"[*] Simulating {steps} normal user activity steps (low velocity, benign edits)...")

        def _run():
            try:
                engine = DemoEngine()
                report = engine.simulateNormalActivity(
                    steps=steps,
                    delaySeconds=0.15,
                    callback=lambda cur, tot, desc: self.after(0, lambda: self._appendDemoLog(f"  [+] Step {cur}/{tot}: {desc}")),
                )
                self.after(0, lambda: self._appendDemoLog(f"[✓] Normal activity completed ({report.durationSeconds:.2f}s). Threat level remains LOW.\n"))
            except Exception as error:
                self.after(0, lambda: self._appendDemoLog(f"[-] Simulation error: {error}\n"))

        threading.Thread(target=_run, daemon=True).start()

    def actionDemoSimulateAttack(self):
        """Simulate safe sandboxed ransomware attack in background thread."""
        try:
            count = int(self.spnAttackCount.get())
        except ValueError:
            count = 20

        self._appendDemoLog(f"[!] WARNING: Simulating safe laboratory ransomware attack on {count} files in testFiles/...")

        def _run():
            try:
                engine = DemoEngine()
                report = engine.simulateRansomwareAttack(
                    fileCount=count,
                    callback=lambda cur, tot, desc: self.after(0, lambda: self._appendDemoLog(f"  [!] {cur}/{tot}: {desc}")),
                )
                self.after(0, lambda: self._appendDemoLog(f"[✓] Attack simulation completed ({report.filesRenamed} files renamed in {report.durationSeconds:.2f}s). Check Live Activity & Forensics tabs!\n"))
            except Exception as error:
                self.after(0, lambda: self._appendDemoLog(f"[-] Attack simulation error: {error}\n"))

        threading.Thread(target=_run, daemon=True).start()

    def actionDemoCleanSandbox(self):
        """Clean demo sandbox files."""
        self._appendDemoLog("[*] Cleaning demo sandbox directory...")

        def _run():
            try:
                engine = DemoEngine()
                report = engine.cleanSandbox(
                    callback=lambda desc: self.after(0, lambda: self._appendDemoLog(f"  [-] {desc}")),
                )
                self.after(0, lambda: self._appendDemoLog(f"[✓] Sandbox cleaned ({report.filesDeleted} files removed).\n"))
            except Exception as error:
                self.after(0, lambda: self._appendDemoLog(f"[-] Clean error: {error}\n"))

        threading.Thread(target=_run, daemon=True).start()

    def actionDemoOpenFolder(self):
        """Open demo folder in Windows Explorer."""
        try:
            demo_path = (getProjectRoot() / "testFiles").resolve()
            demo_path.mkdir(parents=True, exist_ok=True)
            subprocess.Popen(f'explorer "{demo_path}"')
        except Exception as error:
            messagebox.showerror("Error Opening Folder", str(error))

    def actionClearLiveTable(self):
        self.treeEvents.delete(*self.treeEvents.get_children())

    def onClose(self):
        """Clean shutdown handler."""
        if self._pollTimerId:
            self.after_cancel(self._pollTimerId)
        if self.worker is not None:
            self.worker.stop()
            self.worker = None
        self.destroy()


def runGui() -> int:
    """Entry point for launching the Desktop GUI."""
    app = MainWindow()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(runGui())
