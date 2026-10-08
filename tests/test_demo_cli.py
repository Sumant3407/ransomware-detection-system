"""Tests for Demonstration and Safe Lab CLI integration (app.main --demo)."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.main import getArguments, performDemoAction


class TestDemoCli:
    def test_demo_generate_benign_json(self, tmp_path, capsys):
        with patch("app.operations.demoEngine.getProjectRoot", return_value=tmp_path):
            status = performDemoAction("benign", count=10, jsonOutput=True)
            assert status == 0

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["action"] == "generate_benign"
            assert data["created"] == 10

    def test_demo_simulate_normal_json(self, tmp_path, capsys):
        with patch("app.operations.demoEngine.getProjectRoot", return_value=tmp_path):
            performDemoAction("benign", count=5, jsonOutput=True)
            capsys.readouterr()  # clear buffer

            status = performDemoAction("normal", steps=5, jsonOutput=True)
            assert status == 0

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["action"] == "simulate_normal"

    def test_demo_simulate_attack_json(self, tmp_path, capsys):
        with patch("app.operations.demoEngine.getProjectRoot", return_value=tmp_path):
            performDemoAction("benign", count=8, jsonOutput=True)
            capsys.readouterr()  # clear buffer

            status = performDemoAction("attack", count=6, jsonOutput=True)
            assert status == 0

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["action"] == "simulate_ransomware"
            assert data["renamed"] == 6

    def test_demo_clean_sandbox_json(self, tmp_path, capsys):
        with patch("app.operations.demoEngine.getProjectRoot", return_value=tmp_path):
            performDemoAction("benign", count=5, jsonOutput=True)
            capsys.readouterr()  # clear buffer

            status = performDemoAction("clean", jsonOutput=True)
            assert status == 0

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["action"] == "clean_sandbox"
            assert data["deleted"] == 5

    def test_demo_argument_parsing(self):
        with patch("sys.argv", ["app.main", "--demo", "benign", "--demo-count", "50"]):
            args = getArguments()
            assert args.demo == "benign"
            assert args.demo_count == 50
