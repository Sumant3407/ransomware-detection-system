"""Tests for Electron UI integration and main CLI JSON endpoints."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from app.main import getArguments, showDetailedStatus, showHistory, performScan, launchIntegratedDesktopUi
from app.detection.riskEngine import RiskDecision, ThreatLevel


class TestElectronUiIntegration:
    """Test suite for Electron UI launch and CLI JSON integration endpoints."""

    def test_ui_argument_parsing(self):
        with patch("sys.argv", ["main.py", "--ui"]):
            args = getArguments()
            assert args.ui is True

        with patch("sys.argv", ["main.py", "-u"]):
            args = getArguments()
            assert args.ui is True

    def test_show_detailed_status_json(self, tmp_path, capsys):
        config = {
            "monitoring": {
                "paths": [str(tmp_path)],
                "intervalSeconds": 2,
                "sensitivity": "balanced",
                "alertCooldownSeconds": 30,
            },
            "model": {"path": "dummy.joblib"},
        }
        db_path = tmp_path / "test.db"

        result = showDetailedStatus(config, db_path, jsonOutput=True)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "monitoringPaths" in data
        assert data["intervalSeconds"] == 2
        assert data["sensitivity"] == "balanced"
        assert "model" in data
        assert "database" in data

    def test_show_history_json_empty(self, tmp_path, capsys):
        import sqlite3
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE detections (detectionId INTEGER PRIMARY KEY, sessionId INTEGER, occurredAt TEXT, classification TEXT, riskScore REAL, actionTaken TEXT)")
        conn.close()

        result = showHistory(db_path, jsonOutput=True)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 0

    def test_show_history_json_with_records(self, tmp_path, capsys):
        import sqlite3
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE detections (detectionId INTEGER PRIMARY KEY, sessionId INTEGER, occurredAt TEXT, classification TEXT, riskScore REAL, actionTaken TEXT)")
        conn.execute("INSERT INTO detections (sessionId, occurredAt, classification, riskScore, actionTaken) VALUES (1, '2026-10-08 12:00:00', 'ransomwareLike', 0.95, 'alert')")
        conn.commit()
        conn.close()

        result = showHistory(db_path, jsonOutput=True)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["classification"] == "ransomwareLike"
        assert data[0]["riskScore"] == 0.95

    @patch("app.main.DetectionController")
    def test_perform_scan_json(self, mock_controller_cls, tmp_path, capsys):
        mock_controller = MagicMock()
        mock_controller.collectOnce.return_value = RiskDecision(
            level=ThreatLevel.low,
            score=0.0,
            classification="benign",
            action="logOnly",
        )
        mock_controller_cls.return_value = mock_controller

        config = {
            "monitoring": {"paths": [str(tmp_path)]},
            "model": {"path": ""},
        }
        db_path = tmp_path / "test.db"

        result = performScan(config, db_path, jsonOutput=True)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["level"] == "low"
        assert data["score"] == 0.0
        assert data["classification"] == "benign"
        assert data["action"] == "logOnly"

    @patch("shutil.which")
    def test_launch_integrated_desktop_ui_no_npm(self, mock_which, capsys):
        mock_which.return_value = None
        result = launchIntegratedDesktopUi()
        assert result == 1
        captured = capsys.readouterr()
        assert "Node.js / npm is required" in captured.out
