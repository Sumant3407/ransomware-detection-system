"""Tests for Sprint 3.5: Configuration Hot-Reload, Live Model Swapping, and Background Watchers."""

import json
import os
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import joblib
import pytest
from sklearn.ensemble import RandomForestClassifier

from app.config.configuration import (
    ConfigurationError,
    getDataDirectory,
    getProjectRoot,
    loadConfiguration,
    validateConfiguration,
)
from app.config.configWatcher import (
    BackgroundHotReloader,
    ConfigWatcher,
    ReloadResult,
)
from app.domain.schemas import featureColumns
from app.main import (
    getArguments,
    performConfigValidation,
    performModelSwapValidation,
)
from app.runtime.controller import DetectionController
from app.runtime.genericWorker import MonitoringWorker
from app.security.modelEncryption import ModelEncryption
from app.storage.sqliteStore import initializeDatabase


@pytest.fixture
def tempEnvironment():
    """Create isolated temporary environment for testing hot-reloading."""
    tempDir = Path(tempfile.mkdtemp(prefix="hotreload_test_"))
    configDir = tempDir / "config"
    configDir.mkdir(parents=True, exist_ok=True)
    dataDir = tempDir / "data"
    dataDir.mkdir(parents=True, exist_ok=True)
    dbDir = dataDir / "database"
    dbDir.mkdir(parents=True, exist_ok=True)

    monitorDir1 = getProjectRoot() / "testFiles" / "hotreload_test_1"
    monitorDir2 = getProjectRoot() / "testFiles" / "hotreload_test_2"
    monitorDir1.mkdir(parents=True, exist_ok=True)
    monitorDir2.mkdir(parents=True, exist_ok=True)

    dbPath = dbDir / "detector.sqlite3"
    configFile = configDir / "settings.json"

    # Base valid configuration
    baseConfig = {
        "monitoring": {
            "enabled": True,
            "sensitivity": "balanced",
            "alertCooldownSeconds": 45,
            "intervalSeconds": 2,
            "paths": [
                "testFiles/hotreload_test_1"
            ]
        },
        "logging": {
            "retentionDays": 30,
            "level": "INFO"
        },
        "model": {
            "version": "current",
            "path": ""
        },
        "notifications": {
            "enabled": True
        },
        "response": {
            "mode": "alertOnly"
        },
        "startup": {
            "enabled": True
        },
        "emergencyUsb": {
            "enabled": True,
            "scanScope": "protectedFolders"
        },
        "ui": {
            "theme": "dark"
        }
    }
    configFile.write_text(json.dumps(baseConfig, indent=2), encoding="utf-8")

    # Create dummy trained RandomForest models with valid artifact schema
    model1Path = tempDir / "model_v1.joblib"
    clf1 = RandomForestClassifier(n_estimators=5, random_state=42)
    X = [[0.0] * len(featureColumns), [1.0] * len(featureColumns)]
    y = ["benign", "ransomware"]
    clf1.fit(X, y)
    artifact1 = {
        "model": clf1,
        "featureColumns": featureColumns,
        "labelMapping": {"benign": 0, "ransomware": 1},
    }
    joblib.dump(artifact1, model1Path)

    model2Path = tempDir / "model_v2.joblib"
    clf2 = RandomForestClassifier(n_estimators=10, random_state=84)
    clf2.fit(X, y)
    artifact2 = {
        "model": clf2,
        "featureColumns": featureColumns,
        "labelMapping": {"benign": 0, "ransomware": 1},
    }
    joblib.dump(artifact2, model2Path)

    yield {
        "tempDir": tempDir,
        "configDir": configDir,
        "configFile": configFile,
        "dataDir": dataDir,
        "dbPath": dbPath,
        "monitorDir1": monitorDir1,
        "monitorDir2": monitorDir2,
        "model1Path": model1Path,
        "model2Path": model2Path,
        "baseConfig": baseConfig,
    }

    shutil.rmtree(tempDir, ignore_errors=True)
    shutil.rmtree(monitorDir1, ignore_errors=True)
    shutil.rmtree(monitorDir2, ignore_errors=True)


# ============================================================================
# 1. ConfigWatcher Unit & Rollback Tests
# ============================================================================

class TestConfigWatcher:
    def test_watcher_initialization_loads_baseline(self, tempEnvironment):
        configFile = tempEnvironment["configFile"]
        watcher = ConfigWatcher(configPath=configFile)

        assert watcher._activeConfig is not None
        assert watcher._activeConfig["monitoring"]["alertCooldownSeconds"] == 45
        assert not watcher.checkConfigChanged()

    def test_watcher_detects_configuration_modification(self, tempEnvironment):
        configFile = tempEnvironment["configFile"]
        watcher = ConfigWatcher(configPath=configFile)

        assert not watcher.checkConfigChanged()

        # Modify configuration on disk
        time.sleep(0.05)
        newConfig = dict(tempEnvironment["baseConfig"])
        newConfig["monitoring"] = dict(tempEnvironment["baseConfig"]["monitoring"])
        newConfig["monitoring"]["alertCooldownSeconds"] = 90
        configFile.write_text(json.dumps(newConfig, indent=2), encoding="utf-8")

        assert watcher.checkConfigChanged()

    def test_watcher_reload_success_and_changed_sections(self, tempEnvironment):
        configFile = tempEnvironment["configFile"]
        callbackMock = MagicMock()
        watcher = ConfigWatcher(configPath=configFile, onConfigChange=callbackMock)

        # Modify configuration
        time.sleep(0.05)
        modifiedConfig = dict(tempEnvironment["baseConfig"])
        modifiedConfig["monitoring"] = dict(tempEnvironment["baseConfig"]["monitoring"])
        modifiedConfig["monitoring"]["alertCooldownSeconds"] = 120
        modifiedConfig["logging"] = dict(tempEnvironment["baseConfig"]["logging"])
        modifiedConfig["logging"]["level"] = "DEBUG"
        configFile.write_text(json.dumps(modifiedConfig, indent=2), encoding="utf-8")

        success, newConfig, report = watcher.reloadConfiguration()

        assert success is True
        assert newConfig is not None
        assert newConfig["monitoring"]["alertCooldownSeconds"] == 120
        assert report.success is True
        assert "monitoring" in report.changedSections
        assert "logging" in report.changedSections
        callbackMock.assert_called_once_with(newConfig)

        # Check history
        history = watcher.getReloadHistory()
        assert len(history) == 1
        assert history[0].success is True

    def test_watcher_rollback_on_invalid_json(self, tempEnvironment):
        configFile = tempEnvironment["configFile"]
        callbackMock = MagicMock()
        watcher = ConfigWatcher(configPath=configFile, onConfigChange=callbackMock)

        baseline = watcher._activeConfig

        # Corrupt configuration with invalid JSON
        time.sleep(0.05)
        configFile.write_text("{ broken json: [", encoding="utf-8")

        success, activeConfig, report = watcher.reloadConfiguration()

        assert success is False
        assert activeConfig == baseline  # Rollback guarantee
        assert report.success is False
        assert report.error is not None
        callbackMock.assert_not_called()

        # Check history recorded failed attempt
        history = watcher.getReloadHistory()
        assert len(history) == 1
        assert history[0].success is False

    def test_watcher_rollback_on_schema_validation_failure(self, tempEnvironment):
        configFile = tempEnvironment["configFile"]
        watcher = ConfigWatcher(configPath=configFile)

        # Write invalid schema (e.g., negative cooldown)
        time.sleep(0.05)
        invalidConfig = dict(tempEnvironment["baseConfig"])
        invalidConfig["monitoring"] = dict(tempEnvironment["baseConfig"]["monitoring"])
        invalidConfig["monitoring"]["alertCooldownSeconds"] = -500
        configFile.write_text(json.dumps(invalidConfig), encoding="utf-8")

        success, activeConfig, report = watcher.reloadConfiguration()

        assert success is False
        assert activeConfig["monitoring"]["alertCooldownSeconds"] == 45
        assert report.success is False

    def test_watcher_tracks_model_artifact_modifications(self, tempEnvironment):
        model1Path = tempEnvironment["model1Path"]
        modelCallback = MagicMock()
        watcher = ConfigWatcher(modelPath=model1Path, onModelChange=modelCallback)

        assert not watcher.checkModelChanged()

        # Modify model file
        time.sleep(0.05)
        model1Path.write_bytes(b"UPDATED_MODEL_BYTES_MOCK")

        assert watcher.checkModelChanged()

        actions = watcher.pollOnce()
        assert actions["modelReloaded"] is True
        modelCallback.assert_called_once_with(model1Path)


# ============================================================================
# 2. BackgroundHotReloader Tests
# ============================================================================

class TestBackgroundHotReloader:
    def test_background_reloader_lifecycle(self, tempEnvironment):
        configFile = tempEnvironment["configFile"]
        watcher = ConfigWatcher(configPath=configFile)
        reloader = BackgroundHotReloader(watcher, checkIntervalSeconds=0.2)

        assert not reloader.is_running()

        reloader.start()
        assert reloader.is_running()

        time.sleep(0.1)
        reloader.stop(timeout=1.0)
        assert not reloader.is_running()

    def test_background_reloader_context_manager(self, tempEnvironment):
        configFile = tempEnvironment["configFile"]
        watcher = ConfigWatcher(configPath=configFile)

        with BackgroundHotReloader(watcher, checkIntervalSeconds=0.2) as reloader:
            assert reloader.is_running()

        assert not reloader.is_running()

    def test_background_reloader_live_detection(self, tempEnvironment):
        configFile = tempEnvironment["configFile"]
        configCallback = MagicMock()
        watcher = ConfigWatcher(configPath=configFile, onConfigChange=configCallback)

        reloader = BackgroundHotReloader(watcher, checkIntervalSeconds=0.1)
        reloader.start()

        try:
            time.sleep(0.05)
            # Update configuration on disk
            newConfig = dict(tempEnvironment["baseConfig"])
            newConfig["monitoring"] = dict(tempEnvironment["baseConfig"]["monitoring"])
            newConfig["monitoring"]["alertCooldownSeconds"] = 77
            configFile.write_text(json.dumps(newConfig, indent=2), encoding="utf-8")

            # Wait for background reloader to poll and fire callback
            time.sleep(0.4)
            configCallback.assert_called_once()
            calledConfig = configCallback.call_args[0][0]
            assert calledConfig["monitoring"]["alertCooldownSeconds"] == 77
        finally:
            reloader.stop(timeout=1.0)


# ============================================================================
# 3. DetectionController Atomic Hot-Swap & Reload Tests
# ============================================================================

class TestControllerHotSwapAndReload:
    def test_controller_atomic_model_swap_success(self, tempEnvironment):
        controller = DetectionController(
            monitoredPaths=[tempEnvironment["monitorDir1"]],
            databasePath=tempEnvironment["dbPath"],
            modelPath=tempEnvironment["model1Path"],
        )

        try:
            assert controller.modelState == "ready"
            assert controller.modelPath == tempEnvironment["model1Path"].resolve()

            # Swap to model 2
            success, msg = controller.swapModel(tempEnvironment["model2Path"])

            assert success is True
            assert "model_v2.joblib" in msg
            assert controller.modelPath == tempEnvironment["model2Path"].resolve()
            assert controller.modelState == "ready"

            # Check database systemStatus record
            row = controller.connection.execute("SELECT modelState FROM systemStatus WHERE statusId = 1").fetchone()
            assert row[0] == "ready"

            # Verify collection runs cleanly with new model
            decision = controller.collectOnce()
            assert decision is not None
        finally:
            controller.close()

    def test_controller_model_swap_rejection_preserves_active_model(self, tempEnvironment):
        controller = DetectionController(
            monitoredPaths=[tempEnvironment["monitorDir1"]],
            databasePath=tempEnvironment["dbPath"],
            modelPath=tempEnvironment["model1Path"],
        )

        try:
            # Create corrupt candidate model
            corruptModel = tempEnvironment["tempDir"] / "corrupt.joblib"
            corruptModel.write_bytes(b"INVALID_HEADER_NOT_A_MODEL")

            originalPredictor = controller.modelPredictor
            originalPath = controller.modelPath

            success, msg = controller.swapModel(corruptModel)

            assert success is False
            assert "rejected" in msg
            # Active predictor must be preserved
            assert controller.modelPredictor is originalPredictor
            assert controller.modelPath == originalPath
        finally:
            controller.close()

    def test_controller_dynamic_configuration_reload(self, tempEnvironment):
        controller = DetectionController(
            monitoredPaths=[tempEnvironment["monitorDir1"]],
            databasePath=tempEnvironment["dbPath"],
            alertCooldownSeconds=45,
        )

        try:
            assert controller.alertPolicy.cooldownSeconds == 45
            assert len(controller.monitoredPaths) == 1

            # Candidate configuration with updated cooldown and additional monitored path
            candidateConfig = dict(tempEnvironment["baseConfig"])
            candidateConfig["monitoring"] = dict(tempEnvironment["baseConfig"]["monitoring"])
            candidateConfig["monitoring"]["paths"] = [
                "testFiles/hotreload_test_1",
                "testFiles/hotreload_test_2",
            ]
            candidateConfig["monitoring"]["alertCooldownSeconds"] = 99

            success, msg = controller.reloadConfiguration(configDict=candidateConfig)

            assert success is True
            assert controller.alertPolicy.cooldownSeconds == 99
            assert len(controller.monitoredPaths) == 2
            assert tempEnvironment["monitorDir2"].resolve() in controller.monitoredPaths

            # Verify collection runs across reconfigured paths
            decision = controller.collectOnce()
            assert decision is not None
        finally:
            controller.close()

    def test_controller_dynamic_configuration_reload_rejection(self, tempEnvironment):
        controller = DetectionController(
            monitoredPaths=[tempEnvironment["monitorDir1"]],
            databasePath=tempEnvironment["dbPath"],
            alertCooldownSeconds=45,
        )

        try:
            # Candidate with invalid parameters
            badConfig = dict(tempEnvironment["baseConfig"])
            badConfig["monitoring"] = dict(tempEnvironment["baseConfig"]["monitoring"])
            badConfig["monitoring"]["alertCooldownSeconds"] = -10

            success, msg = controller.reloadConfiguration(configDict=badConfig)

            assert success is False
            assert "aborted" in msg
            # Original state unchanged
            assert controller.alertPolicy.cooldownSeconds == 45
        finally:
            controller.close()

    def test_controller_enable_and_disable_hot_reloader(self, tempEnvironment):
        controller = DetectionController(
            monitoredPaths=[tempEnvironment["monitorDir1"]],
            databasePath=tempEnvironment["dbPath"],
            modelPath=tempEnvironment["model1Path"],
        )

        try:
            controller.enableHotReloader(checkIntervalSeconds=0.2, configPath=tempEnvironment["configFile"])
            assert controller.backgroundReloader is not None
            assert controller.backgroundReloader.is_running()

            controller.disableHotReloader()
            assert controller.backgroundReloader is None
        finally:
            controller.close()


# ============================================================================
# 4. MonitoringWorker Hot-Reload Integration Tests
# ============================================================================

class TestMonitoringWorkerHotReload:
    def test_worker_reload_configuration_forwarding(self, tempEnvironment):
        worker = MonitoringWorker(
            monitoredPaths=[tempEnvironment["monitorDir1"]],
            databasePath=tempEnvironment["dbPath"],
            modelPath=tempEnvironment["model1Path"],
            intervalSeconds=0.2,
            enableHotReload=False,
        )

        # Before start: controller is None
        success, msg = worker.reloadConfiguration()
        assert success is False
        assert "not running" in msg

        worker.start()
        time.sleep(0.3)

        try:
            assert worker.is_running()
            assert worker.controller is not None

            # Hot-swap model via worker
            success, msg = worker.swapModel(tempEnvironment["model2Path"])
            assert success is True
            assert "model_v2.joblib" in msg
        finally:
            worker.stop()


# ============================================================================
# 5. CLI Endpoint Tests (--validate-config, --swap-model, --hot-reload)
# ============================================================================

class TestCLIConfigAndModelEndpoints:
    def test_cli_validate_config_valid(self, tempEnvironment, capsys):
        configFile = tempEnvironment["configFile"]
        result = performConfigValidation(configFile, jsonOutput=False)
        assert result == 0
        captured = capsys.readouterr()
        assert "Configuration Validation Passed" in captured.out

    def test_cli_validate_config_json_output(self, tempEnvironment, capsys):
        configFile = tempEnvironment["configFile"]
        result = performConfigValidation(configFile, jsonOutput=True)
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["valid"] is True
        assert "monitoring" in data["sections"]

    def test_cli_validate_config_invalid_file(self, tempEnvironment, capsys):
        badFile = tempEnvironment["tempDir"] / "bad_config.json"
        badFile.write_text("{ invalid json", encoding="utf-8")

        result = performConfigValidation(badFile, jsonOutput=False)
        assert result == 1
        captured = capsys.readouterr()
        assert "Validation Failed" in captured.out

    def test_cli_validate_config_nonexistent_file(self, tempEnvironment, capsys):
        missingFile = tempEnvironment["tempDir"] / "missing.json"
        result = performConfigValidation(missingFile, jsonOutput=True)
        assert result == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["valid"] is False
        assert "not found" in data["error"].lower()

    def test_cli_model_swap_validation_valid(self, tempEnvironment, capsys):
        modelPath = tempEnvironment["model1Path"]
        result = performModelSwapValidation(modelPath, jsonOutput=False)
        assert result == 0
        captured = capsys.readouterr()
        assert "Model Preflight Validation Passed" in captured.out
        assert "RandomForestClassifier" in captured.out

    def test_cli_model_swap_validation_json_output(self, tempEnvironment, capsys):
        modelPath = tempEnvironment["model1Path"]
        result = performModelSwapValidation(modelPath, jsonOutput=True)
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["valid"] is True
        assert data["modelType"] == "RandomForestClassifier"
        assert data["featureCount"] == len(featureColumns)

    def test_cli_model_swap_validation_corrupted_model(self, tempEnvironment, capsys):
        badModel = tempEnvironment["tempDir"] / "corrupted_model.joblib"
        badModel.write_bytes(b"NOT_A_VALID_JOBLIB_MODEL")

        result = performModelSwapValidation(badModel, jsonOutput=True)
        assert result == 1
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["valid"] is False
        assert "error" in data

    def test_cli_argument_parsing_hot_reload_flags(self):
        with patch("sys.argv", ["app.main", "--validate-config", "config.json", "--hot-reload"]):
            args = getArguments()
            assert args.validate_config == "config.json"
            assert args.hot_reload is True

        with patch("sys.argv", ["app.main", "--swap-model", "model.joblib"]):
            args = getArguments()
            assert args.swap_model == "model.joblib"
