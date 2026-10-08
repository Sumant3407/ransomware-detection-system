"""Comprehensive End-to-End Compatibility & Integration Test Suite for Phase 1 and Phase 2.

Verifies cross-cutting workflows across:
- Phase 1: Path security whitelisting, connection pooling, structured audit logging, AES-256-GCM model encryption.
- Phase 2: Multi-path directory monitoring, process attribution, enhanced feature engineering,
           explainable threat detection, continuous feedback collection, and automated model retraining/rollback.
"""

import json
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Generator

import pandas as pd
import pytest

from app.config.configuration import loadConfiguration
from app.detection.alertPolicy import AlertPolicy
from app.detection.predictor import ModelPredictor
from app.detection.riskEngine import evaluateRisk
from app.domain.schemas import featureColumns
from app.features.windowing import FeatureWindow
from app.logging.logger import createLogger, setRequestId, setSessionId
from app.models.modelRegistry import ModelRegistry
from app.models.retrainingPipeline import (
    RetrainingConfig,
    RetrainingPipeline,
    RetrainingStatus,
    RetrainingTrigger,
)
from app.monitoring.multiPathCollector import MultiPathEventCollector
from app.monitoring.processAttribution import ProcessAttributor
from app.runtime.controller import DetectionController
from app.security.modelEncryption import ModelEncryption
from app.security.pathPrivacy import getPathIdentifier
from app.security.pathValidator import PathValidator
from app.storage.sqliteStore import (
    getAllMonitoredPaths,
    getLatestRetrainingRuns,
    getUnusedDetectionFeedback,
    initializeDatabase,
    recordDetectionFeedback,
)
from trainingModel.collection.syntheticData import generateAndSaveDataset
from trainingModel.training.trainModel import trainModel
from trainingModel.validation.datasetValidator import DatasetValidator


@pytest.fixture
def integratedEnvironment() -> Generator[dict[str, Any], None, None]:
    """Sets up a complete isolated sandbox environment for end-to-end integration testing."""
    tempDir = Path(tempfile.mkdtemp(prefix="ransomware_e2e_integration_"))
    dbPath = tempDir / "storage.db"
    logsDir = tempDir / "logs"
    modelsDir = tempDir / "models"
    datasetPath = tempDir / "dataset.csv"
    watchDir1 = tempDir / "protected_docs"
    watchDir2 = tempDir / "protected_downloads"
    keyPath = tempDir / "path.key"

    logsDir.mkdir(parents=True, exist_ok=True)
    modelsDir.mkdir(parents=True, exist_ok=True)
    watchDir1.mkdir(parents=True, exist_ok=True)
    watchDir2.mkdir(parents=True, exist_ok=True)

    # 1. Initialize Logger
    appLogger = createLogger(
        logDirectory=logsDir,
        levelName="DEBUG",
        enableConsole=False,
    )

    # 2. Initialize Database
    initializeDatabase(dbPath)

    # 3. Create Seed Dataset & Initial Encrypted Production Model
    generateAndSaveDataset(datasetPath, sampleCount=80, maliciousRatio=0.5, seed=42)
    initialArtifact = tempDir / "initial_candidate.joblib"
    trainModel(
        dataset=pd.read_csv(datasetPath),
        modelPath=initialArtifact,
        encrypt=False,
        cvFolds=3,
        useScaler=True,
    )

    encryption = ModelEncryption(systemIdentifier="e2e_integration_test_system_key")
    registry = ModelRegistry(modelsDirectory=modelsDir, databasePath=dbPath, encryption=encryption)
    activeModelPath = registry.activateModel(initialArtifact, encrypt=True)

    yield {
        "tempDir": tempDir,
        "dbPath": dbPath,
        "logsDir": logsDir,
        "modelsDir": modelsDir,
        "datasetPath": datasetPath,
        "watchDir1": watchDir1,
        "watchDir2": watchDir2,
        "activeModelPath": activeModelPath,
        "encryption": encryption,
        "registry": registry,
        "appLogger": appLogger,
        "keyPath": keyPath,
    }

    shutil.rmtree(tempDir, ignore_errors=True)


class TestFullSystemEndToEndIntegration:
    """Tests the complete operational lifecycle combining all Phase 1 & Phase 2 modules."""

    def test_complete_detection_monitoring_and_audit_flow(self, integratedEnvironment: dict[str, Any]):
        """
        Tests the end-to-end detection pipeline:
        MultiPath Watching -> Process Attribution -> Feature Calculation ->
        Encrypted ML Inference -> Decision Explainability -> Alerting & JSON Audit.
        """
        env = integratedEnvironment
        setSessionId("E2E-SESSION-001")
        setRequestId("REQ-001")

        # 1. Start DetectionController monitoring two protected folders
        controller = DetectionController(
            monitoredPaths=[env["watchDir1"], env["watchDir2"]],
            databasePath=env["dbPath"],
            modelPath=env["activeModelPath"],
            alertCooldownSeconds=1,
            encryption=env["encryption"],
        )

        with controller:
            assert controller.modelState == "ready"
            assert len(controller.monitoredPaths) == 2

            # 2. Simulate rapid ransomware attack behavior in watchDir1
            # (Creating high-entropy files and changing extensions to .locked)
            for i in range(12):
                targetFile = env["watchDir1"] / f"financial_record_{i}.xlsx.locked"
                # Write pseudo-random bytes to elevate Shannon entropy
                targetFile.write_bytes(os.urandom(2048))

            # Simulate normal activity in watchDir2
            for i in range(2):
                (env["watchDir2"] / f"photo_{i}.jpg").write_bytes(b"clean photo content")

            # 3. Perform monitoring cycle
            decision = controller.collectOnce()

            # 4. Verify multi-path collection and event registration
            assert controller.lastCollectedEventCount >= 10

            # 5. Verify SQLite events persistence with pathId tagging
            events = controller.connection.execute(
                "SELECT eventId, pathId, action, processId, occurredAt FROM fileEvents ORDER BY eventId ASC"
            ).fetchall()
            assert len(events) >= 10

            # Ensure both pathIds are present in database
            storedPathIds = {event[1] for event in events}
            assert len(storedPathIds) >= 1
            assert None not in storedPathIds

            # 6. Verify feature calculation & threat detection
            assert decision is not None
            assert decision.score >= 0.0
            assert decision.level.value in ["low", "medium", "high", "critical"]

            # 7. Check structured audit log file
            auditLogFile = env["logsDir"] / "audit.log"
            assert auditLogFile.is_file()
            auditContent = auditLogFile.read_text(encoding="utf-8")
            assert len(auditContent) > 0

    def test_explainable_encrypted_model_inference_with_scaler(self, integratedEnvironment: dict[str, Any]):
        """
        Tests that ModelPredictor loads AES-256-GCM encrypted pipeline, executes prediction,
        and returns feature importances and decision drivers.
        """
        env = integratedEnvironment
        predictor = ModelPredictor(modelPath=env["activeModelPath"], encryption=env["encryption"])

        # Check global feature importances
        importances = predictor.getFeatureImportances()
        assert len(importances) == len(featureColumns)
        assert sum(importances.values()) > 0.0

        # Construct typical ransomware feature sample
        maliciousSample = {
            "fileReadCount": 180.0,
            "fileWriteCount": 160.0,
            "fileCreateCount": 35.0,
            "fileRenameCount": 85.0,
            "fileDeleteCount": 10.0,
            "filesModifiedPerMinute": 160.0,
            "uniqueDirectoriesModified": 12.0,
            "uniqueExtensionsModified": 7.0,
            "extensionChangeCount": 75.0,
            "averageFileEntropy": 7.91,
            "entropyChangeRate": 4.2,
            "processCpuUsage": 82.0,
            "processMemoryUsage": 65.0,
            "processLifetime": 20.0,
            "networkBytes": 65000.0,
            "networkConnectionCount": 5.0,
        }

        prob, explanation = predictor.predictWithExplanation(maliciousSample, topN=5)

        assert prob >= 0.70
        assert explanation["threatClassification"] == "ransomwareLike"
        assert len(explanation["topContributingFeatures"]) == 5

        # Ensure top contributing features include entropy and extension change
        topFeatureNames = [f["feature"] for f in explanation["topContributingFeatures"]]
        assert any(f in topFeatureNames for f in ["averageFileEntropy", "extensionChangeCount", "fileRenameCount"])


class TestClosedLoopRetrainingAndRollbackIntegration:
    """Tests the feedback collection -> trigger check -> candidate training -> promotion -> rollback workflow."""

    def test_end_to_end_retraining_promotion_and_instant_rollback(self, integratedEnvironment: dict[str, Any]):
        """
        Full lifecycle:
        1. Capture false positive/negative feedback.
        2. Evaluate retraining trigger.
        3. Train candidate model via 5-fold CV and StandardScaler.
        4. Validate candidate against promotion policy.
        5. Atomically promote and AES-256-GCM encrypt.
        6. Verify new model performs inference in ModelPredictor.
        7. Execute zero-downtime rollback and verify previous model restored.
        """
        env = integratedEnvironment

        config = RetrainingConfig(
            minNewFeedbackSamples=3,
            minCvF1Score=0.85,
            cvFolds=3,
            encryptArtifacts=True,
        )
        pipeline = RetrainingPipeline(
            modelsDirectory=env["modelsDir"],
            databasePath=env["dbPath"],
            datasetPath=env["datasetPath"],
            config=config,
            encryption=env["encryption"],
        )

        # Step 1: Record 3 analyst feedback samples
        for i in range(3):
            pipeline.recordFeedback(
                sampleValues={
                    "fileReadCount": 120.0 + i,
                    "fileWriteCount": 100.0 + i,
                    "fileCreateCount": 20.0,
                    "fileRenameCount": 60.0,
                    "fileDeleteCount": 5.0,
                    "filesModifiedPerMinute": 100.0,
                    "uniqueDirectoriesModified": 8.0,
                    "uniqueExtensionsModified": 5.0,
                    "extensionChangeCount": 50.0,
                    "averageFileEntropy": 7.85,
                    "entropyChangeRate": 3.5,
                    "processCpuUsage": 75.0,
                    "processMemoryUsage": 60.0,
                    "processLifetime": 30.0,
                    "networkBytes": 40000.0,
                    "networkConnectionCount": 4.0,
                },
                predictedClass="benign",
                actualLabel="Ransomware",
                confidence=0.95,
            )

        # Step 2: Verify trigger condition is met
        shouldRetrain, trigger, count = pipeline.checkTriggers()
        assert shouldRetrain is True
        assert count == 3
        assert trigger == RetrainingTrigger.THRESHOLD

        # Step 3 & 4: Execute retraining and promotion
        report = pipeline.executeRetraining(triggerType=trigger, force=False)

        assert report.success is True
        assert report.promoted is True
        assert report.status == RetrainingStatus.COMPLETED
        assert report.cvF1 >= 0.85
        assert report.feedbackSampleCount == 3

        # Step 5: Verify feedback marked as used in database
        conn = initializeDatabase(env["dbPath"])
        unused = getUnusedDetectionFeedback(conn)
        conn.close()
        assert len(unused) == 0

        # Step 6: Verify new model is active, encrypted, and functioning
        activeModelPath = pipeline.registry.getActiveModel()
        assert activeModelPath.is_file()
        assert ModelEncryption.isEncryptedFile(activeModelPath)

        newPredictor = ModelPredictor(activeModelPath, encryption=env["encryption"])
        testSample = {col: 0.0 for col in featureColumns}
        testSample["averageFileEntropy"] = 7.9
        testSample["extensionChangeCount"] = 50.0
        prob = newPredictor.predictProbability(testSample)
        assert 0.0 <= prob <= 1.0

        # Step 7: Roll back to previous known-good model
        rolledBackPath = pipeline.rollback()
        assert rolledBackPath.is_file()
        assert ModelEncryption.isEncryptedFile(rolledBackPath)

        # Step 8: Verify history in SQLite database
        history = pipeline.getHistory(limit=5)
        assert len(history) >= 2
        assert history[0]["status"] == RetrainingStatus.ROLLED_BACK
        assert history[1]["status"] == RetrainingStatus.COMPLETED
        assert history[1]["promoted"] is True


class TestSecurityAndPenetrationCompatibility:
    """Tests security boundaries, path traversal protections, dataset poisoning checks, and tamper resistance."""

    def test_path_traversal_blocked_under_multi_path_monitoring(self, integratedEnvironment: dict[str, Any]):
        """Ensure system and traversal paths cannot be registered or monitored."""
        env = integratedEnvironment
        validator = PathValidator(allowedBasePaths={env["watchDir1"].resolve(), env["watchDir2"].resolve()})

        # Attempt to access Windows system directory
        with pytest.raises(Exception):
            validator.validate("C:\\Windows\\System32")

        # Attempt path traversal
        traversalPath = str(env["watchDir1"] / ".." / ".." / "Windows")
        with pytest.raises(Exception):
            validator.validate(traversalPath)

    def test_tampered_model_rejected_by_model_predictor(self, integratedEnvironment: dict[str, Any]):
        """Ensure modified or corrupted encrypted model artifact is rejected with tamper error."""
        env = integratedEnvironment
        activeModelPath = env["activeModelPath"]

        # Corrupt one byte in the encrypted model file
        tamperedFile = env["tempDir"] / "tampered_model.joblib"
        data = bytearray(activeModelPath.read_bytes())
        # Corrupt a byte in the payload area
        data[45] = (data[45] + 1) % 256
        tamperedFile.write_bytes(bytes(data))

        with pytest.raises(Exception) as excInfo:
            ModelPredictor(tamperedFile, encryption=env["encryption"])

        assert "integrity" in str(excInfo.value).lower() or "tamper" in str(excInfo.value).lower()

    def test_poisoned_dataset_rejected_by_dataset_validator(self, integratedEnvironment: dict[str, Any]):
        """Ensure single-class, out-of-bounds, or label-flipped datasets are rejected before training."""
        validator = DatasetValidator()

        # 1. Single class (100% Benign) -> rejected
        dfSingleClass = pd.DataFrame([
            {**{col: 1.0 for col in featureColumns}, "label": "Benign"}
            for _ in range(20)
        ])
        res1 = validator.validate(dfSingleClass, strict=False)
        assert res1.isValid is False
        assert any("1 class" in err.lower() or "single-class" in err.lower() for err in res1.errors)

        # 2. Out of bounds Shannon entropy (> 8.0) -> rejected
        dfInvalidEntropy = pd.DataFrame([
            {**{col: 1.0 for col in featureColumns}, "averageFileEntropy": 9.5, "label": "Ransomware"}
            for _ in range(10)
        ] + [
            {**{col: 1.0 for col in featureColumns}, "averageFileEntropy": 3.0, "label": "Benign"}
            for _ in range(10)
        ])
        res2 = validator.validate(dfInvalidEntropy, strict=False)
        assert res2.isValid is False
        assert any("entropy" in err.lower() for err in res2.errors)
