"""Tests for Desktop GUI SOC Dashboard (app.ui.mainWindow)."""

import os
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.config.configuration import loadConfiguration
from app.detection.riskEngine import RiskDecision, ThreatLevel
from app.ui.mainWindow import MainWindow, ModernCard, MetricCard


@pytest.fixture
def desktopUiApp():
    """Create and tear down MainWindow instance."""
    app = MainWindow()
    app.update()
    yield app
    try:
        app.onClose()
    except Exception:
        pass


class TestDesktopUi:
    def test_window_initialization(self, desktopUiApp):
        assert desktopUiApp is not None
        assert "Ransomware" in desktopUiApp.title()
        assert desktopUiApp.isMonitoring is False
        assert desktopUiApp.cardProtection is not None
        assert desktopUiApp.cardThreat is not None
        assert desktopUiApp.cardRisk is not None
        assert desktopUiApp.cardPaths is not None

    def test_metric_card_updates(self, desktopUiApp):
        desktopUiApp.cardThreat.setValue("CRITICAL", "High Threat", "#ef4444")
        assert desktopUiApp.cardThreat.value_label.cget("text") == "CRITICAL"
        assert desktopUiApp.cardThreat.sub_label.cget("text") == "High Threat"

    def test_notebook_tabs_exist(self, desktopUiApp):
        tab_count = desktopUiApp.notebook.index("end")
        assert tab_count == 6

        # Check tab navigation
        desktopUiApp.notebook.select(desktopUiApp.tabLive)
        desktopUiApp.update()
        desktopUiApp.notebook.select(desktopUiApp.tabForensics)
        desktopUiApp.update()
        desktopUiApp.notebook.select(desktopUiApp.tabHealth)
        desktopUiApp.update()
        desktopUiApp.notebook.select(desktopUiApp.tabModels)
        desktopUiApp.update()
        desktopUiApp.notebook.select(desktopUiApp.tabDemo)
        desktopUiApp.update()
        desktopUiApp.notebook.select(desktopUiApp.tabSettings)
        desktopUiApp.update()

    def test_handle_worker_decision_updates_gauges(self, desktopUiApp):
        decision = RiskDecision(
            level=ThreatLevel.critical,
            score=0.9250,
            classification="ransomware",
            action="alert",
        )
        desktopUiApp._handleWorkerDecision(decision, eventCount=42, summary="Rapid mass rename")
        desktopUiApp.update()

        assert desktopUiApp.cardThreat.value_label.cget("text") == "CRITICAL"
        assert "0.9250" in desktopUiApp.cardRisk.value_label.cget("text")
        assert desktopUiApp.threatBanner.winfo_ismapped()

    def test_quick_scan_execution(self, desktopUiApp):
        with patch("tkinter.messagebox.showinfo") as mock_info:
            desktopUiApp.actionQuickScan()
            mock_info.assert_called_once()
            assert "Scan" in mock_info.call_args[0][0]

    def test_health_refresh_action(self, desktopUiApp):
        desktopUiApp.actionRefreshHealth()
        desktopUiApp.update()

        items = desktopUiApp.treeHealth.get_children()
        assert len(items) > 0
        telemetry = desktopUiApp.txtHealthTelemetry.get("1.0", "end")
        assert "HOST SYSTEM" in telemetry
        assert "CPU Utilization" in telemetry

    def test_demo_tab_logging_and_controls(self, desktopUiApp):
        desktopUiApp._appendDemoLog("Test message to demo console")
        desktopUiApp.update()

        log_content = desktopUiApp.txtDemoLog.get("1.0", "end")
        assert "Test message to demo console" in log_content
        assert desktopUiApp.spnBenignCount.get() == "25"
        assert desktopUiApp.spnAttackCount.get() == "20"

    def test_clear_live_table(self, desktopUiApp):
        desktopUiApp.treeEvents.insert("", "end", values=("2026-10-08 12:00:00", "MODIFIED", "test.exe", "1234", "hash1", "1"))
        assert len(desktopUiApp.treeEvents.get_children()) == 1

        desktopUiApp.actionClearLiveTable()
        assert len(desktopUiApp.treeEvents.get_children()) == 0
