"""Unit and Integration Tests for Sprint 3.1: Health Checks & Observability Engine."""

import json
import os
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from app.domain.schemas import featureColumns
from app.models.modelRegistry import ModelRegistry
from app.operations.healthCheck import (
    ComponentHealth,
    HealthChecker,
    HealthReport,
    HealthStatus,
    SystemMetrics,
    formatHealthSummary,
    runHealthCheck,
)
from app.security.modelEncryption import ModelEncryption
from app.storage.sqliteStore import (
    initializeDatabase,
    recordDetectionFeedback,
    recordRetrainingRun,
)
from trainingModel.collection.syntheticData import generateAndSaveDataset
from trainingModel.training.trainModel import trainModel


@pytest.fixture
def testEnvironment() -> Generator[dict, None, None]:
    """Sets up a complete isolated sandbox for health check testing."""
    tempDir = Path(tempfile.mkdtemp(prefix="health_check_test_"))
    dbPath = tempDir / "database" / "detector.sqlite3"
    dbPath.parent.mkdir(parents=True, exist_ok=True)
    logsDir = tempDir / "logs"
    logsDir.mkdir(parents=True, exist_ok=True)
    modelsDir = tempDir / "models"
    modelsDir.mkdir(parents=True, exist_ok=True)
    watchDir1 = tempDir / "watch_docs"
    watchDir2 = tempDir / "watch_downloads"
    watchDir1.mkdir(parents=True, exist_ok=True)
    watchDir2.mkdir(parents=True, exist_ok=True)

    # Initialize DB
    conn = initializeDatabase(dbPath)
    conn.close()

    # Train and activate model
    datasetPath = tempDir / "dataset.csv"
    generateAndSaveDataset(datasetPath, sampleCount=40, seed=42)
    candidatePath = tempDir / "candidate.joblib"
    trainModel(
        dataset=pd.read_csv(datasetPath),
        modelPath=candidatePath,
        encrypt=False,
        cvFolds=2,
        useScaler=True,
    )

    encryption = ModelEncryption()
    registry = ModelRegistry(modelsDirectory=modelsDir, databasePath=dbPath, encryption=encryption)
    activeModel = registry.activateModel(candidatePath, encrypt=True)

    config = {
        "model": {"path": str(activeModel)},
        "storage": {"databasePath": str(dbPath)},
        "monitoring": {
            "paths": [str(watchDir1), str(watchDir2)],
            "intervalSeconds": 1,
            "sensitivity": "medium",
        },
        "logging": {"level": "DEBUG"},
    }

    yield {
        "tempDir": tempDir,
        "dbPath": dbPath,
        "logsDir": logsDir,
        "modelsDir": modelsDir,
        "watchDir1": watchDir1,
        "watchDir2": watchDir2,
        "activeModel": activeModel,
        "encryption": encryption,
        "config": config,
    }

    shutil.rmtree(tempDir, ignore_errors=True)


class TestHealthDataStructures:
    """Test data structures, enums, serialization, and summary formatting."""

    def test_health_status_enum_values(self):
        assert HealthStatus.HEALTHY == "healthy"
        assert HealthStatus.DEGRADED == "degraded"
        assert HealthStatus.UNHEALTHY == "unhealthy"

    def test_component_health_dataclass_and_serialization(self):
        comp = ComponentHealth(
            name="testComponent",
            status=HealthStatus.HEALTHY,
            message="Operational",
            latencyMs=12.34,
            details={"key": "val"},
        )
        assert comp.name == "testComponent"
        assert comp.status == HealthStatus.HEALTHY
        assert comp.latencyMs == 12.34

    def test_health_report_serialization(self):
        metrics = SystemMetrics(
            processCpuPercent=1.5,
            processMemoryRssMb=45.2,
            processMemoryVmsMb=120.0,
            threadCount=4,
            openFileHandles=10,
            processUptimeSeconds=120.5,
            totalFileEvents=100,
            totalDetections=2,
            totalAlerts=1,
            totalSessions=1,
            unconsumedFeedbackCount=3,
            lastRetrainingStatus="completed",
        )
        report = HealthReport(
            status=HealthStatus.HEALTHY,
            timestamp="2026-10-08T12:00:00Z",
            components={
                "model": ComponentHealth("model", HealthStatus.HEALTHY, "OK", 5.0),
                "database": ComponentHealth("database", HealthStatus.HEALTHY, "OK", 2.0),
            },
            metrics=metrics,
            issues=[],
        )

        asDict = report.toDict()
        assert asDict["status"] == "healthy"
        assert asDict["metrics"]["totalFileEvents"] == 100
        assert "model" in asDict["components"]

        summary = formatHealthSummary(report)
        assert "SYSTEM HEALTH STATUS" in summary
        assert "model" in summary
        assert "CPU Usage" in summary


class TestSubsystemProbes:
    """Test individual component health checks under healthy and failure conditions."""

    def test_model_probe_healthy(self, testEnvironment: dict):
        env = testEnvironment
        checker = HealthChecker(
            configuration=env["config"],
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )
        health = checker.checkModel()
        assert health.status == HealthStatus.HEALTHY
        assert health.name == "model"
        assert health.details["isEncrypted"] is True
        assert health.details["featuresCount"] == len(featureColumns)
        assert health.latencyMs is not None

    def test_model_probe_missing_file(self, testEnvironment: dict):
        env = testEnvironment
        badConfig = dict(env["config"])
        badConfig["model"] = {"path": str(env["tempDir"] / "non_existent.joblib")}

        checker = HealthChecker(
            configuration=badConfig,
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )
        health = checker.checkModel()
        assert health.status == HealthStatus.UNHEALTHY
        assert "not found" in health.message

    def test_model_probe_tampered_model(self, testEnvironment: dict):
        env = testEnvironment
        # Corrupt the model file
        modelPath = env["activeModel"]
        data = bytearray(modelPath.read_bytes())
        data[40] = (data[40] + 1) % 256
        modelPath.write_bytes(bytes(data))

        checker = HealthChecker(
            configuration=env["config"],
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )
        health = checker.checkModel()
        assert health.status == HealthStatus.UNHEALTHY
        assert "validation" in health.message.lower() or "tamper" in health.message.lower()

    def test_database_probe_healthy(self, testEnvironment: dict):
        env = testEnvironment
        checker = HealthChecker(
            configuration=env["config"],
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )
        health = checker.checkDatabase()
        assert health.status == HealthStatus.HEALTHY
        assert health.name == "database"
        assert "fileEvents" in health.details["tables"]

    def test_database_probe_missing_tables(self, testEnvironment: dict):
        env = testEnvironment
        emptyDb = env["tempDir"] / "empty.db"
        conn = sqlite3.connect(str(emptyDb))
        conn.execute("CREATE TABLE dummy (id INTEGER)")
        conn.close()

        checker = HealthChecker(
            configuration=env["config"],
            databasePath=emptyDb,
            encryption=env["encryption"],
        )
        health = checker.checkDatabase()
        assert health.status == HealthStatus.DEGRADED
        assert "missing expected tables" in health.message

    def test_monitoring_paths_probe_healthy(self, testEnvironment: dict):
        env = testEnvironment
        checker = HealthChecker(
            configuration=env["config"],
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )
        health = checker.checkMonitoringPaths()
        assert health.status == HealthStatus.HEALTHY
        assert len(health.details["accessible"]) == 2

    def test_monitoring_paths_probe_partial_failure(self, testEnvironment: dict):
        env = testEnvironment
        badConfig = dict(env["config"])
        badConfig["monitoring"] = {
            "paths": [str(env["watchDir1"]), str(env["tempDir"] / "missing_folder_123")]
        }

        checker = HealthChecker(
            configuration=badConfig,
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )
        health = checker.checkMonitoringPaths()
        assert health.status == HealthStatus.DEGRADED
        assert "inaccessible" in health.message

    def test_monitoring_paths_probe_all_inaccessible(self, testEnvironment: dict):
        env = testEnvironment
        badConfig = dict(env["config"])
        badConfig["monitoring"] = {
            "paths": [str(env["tempDir"] / "missing_1"), str(env["tempDir"] / "missing_2")]
        }

        checker = HealthChecker(
            configuration=badConfig,
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )
        health = checker.checkMonitoringPaths()
        assert health.status == HealthStatus.UNHEALTHY
        assert "All configured monitoring paths are inaccessible" in health.message

    def test_storage_probe_thresholds(self, testEnvironment: dict):
        env = testEnvironment
        checker = HealthChecker(
            configuration=env["config"],
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )

        # 1. Mock high disk space (> 10 GB) -> HEALTHY
        with patch("shutil.disk_usage") as mockUsage:
            mockUsage.return_value = MagicMock(
                total=500 * 1024 * 1024 * 1024,
                free=250 * 1024 * 1024 * 1024,
                used=250 * 1024 * 1024 * 1024,
            )
            health = checker.checkStorage()
            assert health.status == HealthStatus.HEALTHY

        # 2. Mock warning disk space (500 MB) -> DEGRADED
        with patch("shutil.disk_usage") as mockUsage:
            mockUsage.return_value = MagicMock(
                total=500 * 1024 * 1024 * 1024,
                free=500 * 1024 * 1024,
                used=499 * 1024 * 1024 * 1024,
            )
            health = checker.checkStorage()
            assert health.status == HealthStatus.DEGRADED
            assert "Low disk space warning" in health.message

        # 3. Mock critical disk space (100 MB) -> UNHEALTHY
        with patch("shutil.disk_usage") as mockUsage:
            mockUsage.return_value = MagicMock(
                total=500 * 1024 * 1024 * 1024,
                free=100 * 1024 * 1024,
                used=499 * 1024 * 1024 * 1024,
            )
            health = checker.checkStorage()
            assert health.status == HealthStatus.UNHEALTHY
            assert "Critically low disk space" in health.message


class TestTelemetryAndAggregateHealth:
    """Test full system health check run and telemetry metrics collection."""

    def test_full_health_check_execution(self, testEnvironment: dict):
        env = testEnvironment
        report = runHealthCheck(
            configuration=env["config"],
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )

        assert report.status == HealthStatus.HEALTHY
        assert len(report.components) == 5
        assert "model" in report.components
        assert "database" in report.components
        assert "monitoringPaths" in report.components
        assert "storage" in report.components
        assert "logging" in report.components
        assert len(report.issues) == 0

    def test_telemetry_metrics_collection(self, testEnvironment: dict):
        env = testEnvironment
        # Populate some telemetry data
        conn = initializeDatabase(env["dbPath"])
        conn.execute(
            "INSERT INTO sessions (startedAt) VALUES (datetime('now'))"
        )
        sessionId = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO fileEvents (sessionId, occurredAt, action, pathHash, source) VALUES (?, datetime('now'), 'CREATED', 'hash1', 'polling')",
            (sessionId,),
        )
        conn.execute(
            "INSERT INTO detections (sessionId, occurredAt, classification, riskScore, actionTaken) VALUES (?, datetime('now'), 'ransomwareLike', 0.88, 'alert')",
            (sessionId,),
        )
        conn.execute(
            "INSERT INTO alerts (detectionId, occurredAt, severity, message) VALUES (1, datetime('now'), 'high', 'Test alert')",
        )
        recordDetectionFeedback(
            conn,
            sampleValues={col: 1.0 for col in featureColumns},
            predictedClass="benign",
            actualLabel="Ransomware",
            detectionId=1,
            confidence=0.9,
        )
        recordRetrainingRun(
            connection=conn,
            startedAt="2026-10-08T12:00:00Z",
            completedAt="2026-10-08T12:05:00Z",
            triggerType="threshold",
            sampleCount=50,
            feedbackSampleCount=5,
            baselineModelVersion="1.0.0",
            candidateModelVersion="1.1.0",
            cvAccuracy=0.95,
            cvF1=0.94,
            cvRocAuc=0.98,
            baselineF1=0.91,
            promoted=True,
            status="completed",
            rollbackReady=True,
        )
        conn.commit()
        conn.close()

        checker = HealthChecker(
            configuration=env["config"],
            databasePath=env["dbPath"],
            encryption=env["encryption"],
        )
        metrics = checker.collectMetrics()

        assert metrics.totalSessions >= 1
        assert metrics.totalFileEvents >= 1
        assert metrics.totalDetections >= 1
        assert metrics.totalAlerts >= 1
        assert metrics.unconsumedFeedbackCount == 1
        assert metrics.lastRetrainingStatus == "completed"
        assert metrics.processMemoryRssMb > 0.0
        assert metrics.threadCount >= 1


class TestMainCliHealthIntegration:
    """Test CLI commands for --health and --metrics."""

    def test_cli_health_command(self, testEnvironment: dict, capsys):
        from app.main import showHealthReport
        env = testEnvironment

        # Human readable
        ret = showHealthReport(env["config"], env["dbPath"], jsonOutput=False)
        captured = capsys.readouterr()
        assert ret == 0
        assert "SYSTEM HEALTH STATUS" in captured.out
        assert "HEALTHY" in captured.out

        # JSON format
        retJson = showHealthReport(env["config"], env["dbPath"], jsonOutput=True)
        capturedJson = capsys.readouterr()
        assert retJson == 0
        parsed = json.loads(capturedJson.out)
        assert parsed["status"] == "healthy"
        assert "components" in parsed
        assert "metrics" in parsed

    def test_cli_metrics_command(self, testEnvironment: dict, capsys):
        from app.main import showMetrics
        env = testEnvironment

        # Human readable
        ret = showMetrics(env["config"], env["dbPath"], jsonOutput=False)
        captured = capsys.readouterr()
        assert ret == 0
        assert "SYSTEM & PIPELINE TELEMETRY" in captured.out
        assert "Memory (RSS)" in captured.out

        # JSON format
        retJson = showMetrics(env["config"], env["dbPath"], jsonOutput=True)
        capturedJson = capsys.readouterr()
        assert retJson == 0
        parsed = json.loads(capturedJson.out)
        assert "processMemoryRssMb" in parsed
        assert "totalFileEvents" in parsed
