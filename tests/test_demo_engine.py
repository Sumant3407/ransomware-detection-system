"""Unit and integration tests for DemoEngine (app.operations.demoEngine)."""

import os
import tempfile
from pathlib import Path

import pytest

from app.operations.demoEngine import DemoActionType, DemoEngine, MARKER_FILE
from app.security.pathValidator import PathValidationError


@pytest.fixture
def demoSandbox(tmp_path):
    """Create a temporary sandbox for demo operations."""
    sandbox = tmp_path / "testFiles"
    sandbox.mkdir()
    return sandbox


class TestDemoEngine:
    def test_ensure_sandbox_creates_marker(self, demoSandbox):
        engine = DemoEngine(sandboxPath=demoSandbox)
        resolved = engine.ensureSandbox()

        assert resolved == demoSandbox.resolve()
        assert (resolved / MARKER_FILE).is_file()

    def test_generate_benign_files(self, demoSandbox):
        engine = DemoEngine(sandboxPath=demoSandbox)
        progressEvents = []

        def callback(cur, tot, filename):
            progressEvents.append((cur, tot, filename))

        report = engine.generateBenignFiles(count=15, callback=callback)

        assert report.success is True
        assert report.action == DemoActionType.GENERATE_BENIGN
        assert report.filesCreated == 15
        assert len(progressEvents) == 15

        files = [p for p in demoSandbox.iterdir() if p.name != MARKER_FILE]
        assert len(files) == 15

        # Verify extension variety
        extensions = {p.suffix for p in files}
        assert len(extensions) > 1

    def test_simulate_normal_activity(self, demoSandbox):
        engine = DemoEngine(sandboxPath=demoSandbox)
        engine.generateBenignFiles(count=10)

        report = engine.simulateNormalActivity(steps=5, delaySeconds=0.01)

        assert report.success is True
        assert report.action == DemoActionType.SIMULATE_NORMAL
        assert report.filesModified > 0 or report.filesCreated > 0
        assert len(report.details) == 5

    def test_simulate_ransomware_attack(self, demoSandbox):
        engine = DemoEngine(sandboxPath=demoSandbox)
        engine.generateBenignFiles(count=12)

        report = engine.simulateRansomwareAttack(fileCount=10)

        assert report.success is True
        assert report.action == DemoActionType.SIMULATE_RANSOMWARE
        assert report.filesRenamed == 10
        assert (demoSandbox / "HOW_TO_RECOVER_FILES_README.txt").is_file()

        # Check for ransomware extensions in folder
        lockedFiles = [p for p in demoSandbox.iterdir() if any(p.name.endswith(ext) for ext in [".locked", ".crypto", ".enc", ".wnry", ".darkbit"])]
        assert len(lockedFiles) == 10

    def test_clean_sandbox(self, demoSandbox):
        engine = DemoEngine(sandboxPath=demoSandbox)
        engine.generateBenignFiles(count=8)

        # Before cleaning
        filesBefore = [p for p in demoSandbox.iterdir() if p.name != MARKER_FILE]
        assert len(filesBefore) == 8

        report = engine.cleanSandbox()
        assert report.success is True
        assert report.filesDeleted == 8

        # After cleaning, only marker or empty
        filesAfter = [p for p in demoSandbox.iterdir() if p.name != MARKER_FILE]
        assert len(filesAfter) == 0

    def test_path_validator_blocks_system_paths(self):
        engine = DemoEngine(sandboxPath=Path(r"C:\Windows\System32"))
        with pytest.raises(PathValidationError):
            engine.ensureSandbox()
