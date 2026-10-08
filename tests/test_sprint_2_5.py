"""Unit and integration test suite for Sprint 2.5: Automated Model Retraining Pipeline."""

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Generator

import pandas as pd
import pytest

from app.detection.predictor import ModelPredictor
from app.models.modelRegistry import ModelRegistry
from app.models.retrainingPipeline import (
    RetrainingConfig,
    RetrainingPipeline,
    RetrainingReport,
    RetrainingStatus,
    RetrainingTrigger,
)
from app.security.modelEncryption import ModelEncryption
from app.storage.sqliteStore import (
    getLatestRetrainingRuns,
    getUnusedDetectionFeedback,
    initializeDatabase,
)
from trainingModel.collection.syntheticData import generateAndSaveDataset, generateSyntheticSample
from trainingModel.training.trainModel import trainModel


@pytest.fixture
def tempEnvironment() -> Generator[dict[str, Path], None, None]:
    """Provide a temporary directory structure for database, models, and datasets."""
    tempDir = Path(tempfile.mkdtemp(prefix="ransomware_test_sprint25_"))
    dbPath = tempDir / "test_storage.db"
    modelsDir = tempDir / "models"
    datasetPath = tempDir / "test_dataset.csv"

    modelsDir.mkdir(parents=True, exist_ok=True)
    initializeDatabase(dbPath)

    # Generate initial balanced dataset (50 samples for fast tests)
    generateAndSaveDataset(datasetPath, sampleCount=60, maliciousRatio=0.5, seed=42)

    # Train and activate an initial baseline model
    encryption = ModelEncryption(systemIdentifier="test_system_id_12345")
    initialModelPath = tempDir / "initial_model.joblib"
    trainModel(
        dataset=pd.read_csv(datasetPath),
        modelPath=initialModelPath,
        encrypt=False,
        cvFolds=3,
    )

    registry = ModelRegistry(modelsDirectory=modelsDir, databasePath=dbPath, encryption=encryption)
    registry.activateModel(initialModelPath, encrypt=True)

    yield {
        "tempDir": tempDir,
        "dbPath": dbPath,
        "modelsDir": modelsDir,
        "datasetPath": datasetPath,
        "encryption": encryption,
        "registry": registry,
    }

    shutil.rmtree(tempDir, ignore_errors=True)


class TestFeedbackStorageAndTriggers:
    """Tests for feedback capture and retraining trigger conditions."""

    def test_record_feedback_stores_sample_values_and_labels(self, tempEnvironment: dict[str, Path]):
        pipeline = RetrainingPipeline(
            modelsDirectory=tempEnvironment["modelsDir"],
            databasePath=tempEnvironment["dbPath"],
            datasetPath=tempEnvironment["datasetPath"],
            encryption=tempEnvironment["encryption"],
        )

        # Create session and detection record to satisfy foreign key
        conn = initializeDatabase(tempEnvironment["dbPath"])
        conn.execute("INSERT INTO sessions (sessionId, startedAt) VALUES (1, datetime('now'))")
        conn.execute(
            "INSERT INTO detections (detectionId, sessionId, occurredAt, classification, riskScore, actionTaken) "
            "VALUES (101, 1, datetime('now'), 'benign', 0.1, 'log')"
        )
        conn.commit()
        conn.close()

        sampleFeatures = {"averageFileEntropy": 7.85, "fileRenameCount": 45.0, "processCpuUsage": 85.0}
        feedbackId = pipeline.recordFeedback(
            sampleValues=sampleFeatures,
            predictedClass="benign",
            actualLabel="Ransomware",
            detectionId=101,
            confidence=0.92,
        )

        assert feedbackId > 0

        conn = initializeDatabase(tempEnvironment["dbPath"])
        unused = getUnusedDetectionFeedback(conn)
        conn.close()

        assert len(unused) == 1
        assert unused[0]["feedbackId"] == feedbackId
        assert unused[0]["actualLabel"] == "Ransomware"
        assert unused[0]["predictedClass"] == "benign"
        assert unused[0]["sampleValues"]["averageFileEntropy"] == 7.85

    def test_check_triggers_threshold_evaluation(self, tempEnvironment: dict[str, Path]):
        config = RetrainingConfig(minNewFeedbackSamples=3)
        pipeline = RetrainingPipeline(
            modelsDirectory=tempEnvironment["modelsDir"],
            databasePath=tempEnvironment["dbPath"],
            datasetPath=tempEnvironment["datasetPath"],
            config=config,
            encryption=tempEnvironment["encryption"],
        )

        # 0 feedback samples -> Should not trigger
        shouldRetrain, trigger, count = pipeline.checkTriggers()
        assert shouldRetrain is False
        assert count == 0

        # Add 2 feedback samples (below threshold 3)
        pipeline.recordFeedback({"averageFileEntropy": 4.0}, "benign", "Benign")
        pipeline.recordFeedback({"averageFileEntropy": 7.9}, "benign", "Ransomware")

        shouldRetrain, trigger, count = pipeline.checkTriggers()
        assert shouldRetrain is False
        assert count == 2

        # Add 3rd feedback sample (reaches threshold 3)
        pipeline.recordFeedback({"averageFileEntropy": 7.8}, "benign", "Ransomware")

        shouldRetrain, trigger, count = pipeline.checkTriggers()
        assert shouldRetrain is True
        assert trigger == RetrainingTrigger.THRESHOLD
        assert count == 3


class TestRetrainingWorkflowAndPromotion:
    """Tests for automated candidate training, cross-validation, and promotion gating."""

    def test_retraining_skipped_if_insufficient_samples_without_force(self, tempEnvironment: dict[str, Path]):
        config = RetrainingConfig(minNewFeedbackSamples=5)
        pipeline = RetrainingPipeline(
            modelsDirectory=tempEnvironment["modelsDir"],
            databasePath=tempEnvironment["dbPath"],
            datasetPath=tempEnvironment["datasetPath"],
            config=config,
            encryption=tempEnvironment["encryption"],
        )

        # Only record 1 sample
        pipeline.recordFeedback({"averageFileEntropy": 7.9}, "benign", "Ransomware")

        report = pipeline.executeRetraining(triggerType=RetrainingTrigger.THRESHOLD, force=False)

        assert report.success is False
        assert report.promoted is False
        assert report.status == RetrainingStatus.REJECTED
        assert "Insufficient new feedback samples" in report.reason

    def test_retraining_succeeds_and_promotes_candidate_model(self, tempEnvironment: dict[str, Path]):
        config = RetrainingConfig(
            minNewFeedbackSamples=2,
            minCvF1Score=0.85,
            cvFolds=3,
            encryptArtifacts=True,
        )
        pipeline = RetrainingPipeline(
            modelsDirectory=tempEnvironment["modelsDir"],
            databasePath=tempEnvironment["dbPath"],
            datasetPath=tempEnvironment["datasetPath"],
            config=config,
            encryption=tempEnvironment["encryption"],
        )

        # Add 2 high-quality feedback samples
        pipeline.recordFeedback(
            {"averageFileEntropy": 7.9, "extensionChangeCount": 40.0, "fileRenameCount": 50.0},
            predictedClass="benign",
            actualLabel="Ransomware",
        )
        pipeline.recordFeedback(
            {"averageFileEntropy": 3.5, "extensionChangeCount": 0.0, "fileRenameCount": 0.0},
            predictedClass="ransomware",
            actualLabel="Benign",
        )

        report = pipeline.executeRetraining(triggerType=RetrainingTrigger.THRESHOLD, force=False)

        assert report.success is True
        assert report.promoted is True
        assert report.status == RetrainingStatus.COMPLETED
        assert report.cvF1 >= 0.85
        assert report.cvAccuracy > 0.80
        assert report.feedbackSampleCount == 2

        # Verify feedback marked as used
        conn = initializeDatabase(tempEnvironment["dbPath"])
        unused = getUnusedDetectionFeedback(conn)
        conn.close()
        assert len(unused) == 0

        # Verify active model in registry is updated and encrypted
        activeModel = pipeline.registry.getActiveModel()
        assert activeModel.is_file()
        assert ModelEncryption.isEncryptedFile(activeModel)

        # Verify previous model backup was created
        previousModel = tempEnvironment["modelsDir"] / "current" / "previous.joblib"
        assert previousModel.is_file()

    def test_promotion_rejected_when_candidate_fails_f1_threshold(self, tempEnvironment: dict[str, Path]):
        # Set impossible F1 threshold (1.01) to force promotion rejection
        config = RetrainingConfig(
            minNewFeedbackSamples=1,
            minCvF1Score=1.01,
            cvFolds=3,
        )
        pipeline = RetrainingPipeline(
            modelsDirectory=tempEnvironment["modelsDir"],
            databasePath=tempEnvironment["dbPath"],
            datasetPath=tempEnvironment["datasetPath"],
            config=config,
            encryption=tempEnvironment["encryption"],
        )

        pipeline.recordFeedback({"averageFileEntropy": 7.9}, "benign", "Ransomware")
        report = pipeline.executeRetraining(triggerType=RetrainingTrigger.MANUAL, force=True)

        assert report.success is True
        assert report.promoted is False
        assert report.status == RetrainingStatus.REJECTED
        assert "below minimum" in report.reason

        # Feedback should NOT be marked as used on rejection
        conn = initializeDatabase(tempEnvironment["dbPath"])
        unused = getUnusedDetectionFeedback(conn)
        conn.close()
        assert len(unused) == 1


class TestRollbackAndHistory:
    """Tests for model rollback and retraining history tracking."""

    def test_model_rollback_to_previous_known_good_version(self, tempEnvironment: dict[str, Path]):
        config = RetrainingConfig(minNewFeedbackSamples=1, cvFolds=3)
        pipeline = RetrainingPipeline(
            modelsDirectory=tempEnvironment["modelsDir"],
            databasePath=tempEnvironment["dbPath"],
            datasetPath=tempEnvironment["datasetPath"],
            config=config,
            encryption=tempEnvironment["encryption"],
        )

        # Retrain and promote model 1
        pipeline.recordFeedback({"averageFileEntropy": 7.9}, "benign", "Ransomware")
        report1 = pipeline.executeRetraining(triggerType=RetrainingTrigger.MANUAL, force=True)
        assert report1.promoted is True

        # Now execute rollback
        rolledBackPath = pipeline.rollback()
        assert rolledBackPath.is_file()

        # Verify rollback record in database history
        history = pipeline.getHistory(limit=5)
        assert len(history) >= 2
        assert history[0]["status"] == RetrainingStatus.ROLLED_BACK
        assert history[0]["candidateModelVersion"] == "previous"

    def test_end_to_end_inference_after_promotion(self, tempEnvironment: dict[str, Path]):
        config = RetrainingConfig(minNewFeedbackSamples=1, cvFolds=3)
        pipeline = RetrainingPipeline(
            modelsDirectory=tempEnvironment["modelsDir"],
            databasePath=tempEnvironment["dbPath"],
            datasetPath=tempEnvironment["datasetPath"],
            config=config,
            encryption=tempEnvironment["encryption"],
        )

        # Retrain and promote
        pipeline.recordFeedback({"averageFileEntropy": 7.8, "fileRenameCount": 50.0}, "benign", "Ransomware")
        report = pipeline.executeRetraining(triggerType=RetrainingTrigger.MANUAL, force=True)
        assert report.promoted is True

        # Load newly promoted active model into ModelPredictor
        activeModelPath = pipeline.registry.getActiveModel()
        predictor = ModelPredictor(modelPath=activeModelPath, encryption=tempEnvironment["encryption"])

        # Run inference on ransomware vector
        ransomwareSample = {
            "fileReadCount": 200.0,
            "fileWriteCount": 180.0,
            "fileCreateCount": 40.0,
            "fileRenameCount": 90.0,
            "fileDeleteCount": 15.0,
            "filesModifiedPerMinute": 180.0,
            "uniqueDirectoriesModified": 15.0,
            "uniqueExtensionsModified": 8.0,
            "extensionChangeCount": 80.0,
            "averageFileEntropy": 7.92,
            "entropyChangeRate": 4.5,
            "processCpuUsage": 80.0,
            "processMemoryUsage": 65.0,
            "processLifetime": 25.0,
            "networkBytes": 80000.0,
            "networkConnectionCount": 6.0,
        }

        probability, explanation = predictor.predictWithExplanation(ransomwareSample, topN=3)
        assert probability > 0.70
        assert len(explanation["topContributingFeatures"]) == 3
        assert predictor.model is not None


class TestRetrainingEdgeCasesAndCLI:
    """Tests for edge cases, poisoning resilience, and CLI operations."""

    def test_poisoned_feedback_rejected_by_dataset_validator(self, tempEnvironment: dict[str, Path]):
        config = RetrainingConfig(minNewFeedbackSamples=1, cvFolds=3)
        pipeline = RetrainingPipeline(
            modelsDirectory=tempEnvironment["modelsDir"],
            databasePath=tempEnvironment["dbPath"],
            datasetPath=tempEnvironment["datasetPath"],
            config=config,
            encryption=tempEnvironment["encryption"],
        )

        # Inject poisoned feedback with physically impossible Shannon entropy (e.g. 15.0)
        pipeline.recordFeedback(
            {"averageFileEntropy": 15.0, "fileRenameCount": 50.0},
            predictedClass="benign",
            actualLabel="Ransomware",
        )

        report = pipeline.executeRetraining(triggerType=RetrainingTrigger.MANUAL, force=True)

        assert report.success is False
        assert report.status == RetrainingStatus.FAILED
        assert "validation failed" in report.reason.lower()

    def test_retraining_handles_missing_dataset_gracefully(self, tempEnvironment: dict[str, Path]):
        missingDatasetPath = tempEnvironment["tempDir"] / "non_existent_dataset.csv"
        pipeline = RetrainingPipeline(
            modelsDirectory=tempEnvironment["modelsDir"],
            databasePath=tempEnvironment["dbPath"],
            datasetPath=missingDatasetPath,
            encryption=tempEnvironment["encryption"],
        )

        report = pipeline.executeRetraining(triggerType=RetrainingTrigger.MANUAL, force=True)

        assert report.success is False
        assert report.status == RetrainingStatus.FAILED
        assert "not found" in report.reason.lower()

    def test_cli_pipeline_execution(self, tempEnvironment: dict[str, Path], monkeypatch):
        import subprocess
        from scripts.retrainPipeline import main as cliMain

        # Prepare valid settings file in temp directory
        settingsPath = tempEnvironment["tempDir"] / "settings.json"
        settingsData = {
            "monitoring": {
                "enabled": True,
                "sensitivity": "balanced",
                "alertCooldownSeconds": 15,
                "intervalSeconds": 2,
                "paths": ["ransomwareDemo/demo_files"],
            },
            "response": {
                "mode": "alertOnly",
            },
            "model": {
                "modelsDirectory": str(tempEnvironment["modelsDir"]),
                "datasetPath": str(tempEnvironment["datasetPath"]),
                "minFeedbackSamples": 2,
                "encryptModel": True,
                "path": str(tempEnvironment["modelsDir"] / "current" / "model.joblib"),
            },
            "storage": {
                "databasePath": str(tempEnvironment["dbPath"]),
            },
        }
        settingsPath.write_text(json.dumps(settingsData), encoding="utf-8")

        # Test CLI --check-triggers
        testArgs = ["retrainPipeline.py", "--config", str(settingsPath), "--check-triggers", "--json"]
        monkeypatch.setattr("sys.argv", testArgs)
        assert cliMain() == 0

        # Test CLI --retrain --force
        testArgs = ["retrainPipeline.py", "--config", str(settingsPath), "--retrain", "--force", "--json"]
        monkeypatch.setattr("sys.argv", testArgs)
        assert cliMain() == 0

        # Test CLI --history
        testArgs = ["retrainPipeline.py", "--config", str(settingsPath), "--history", "3", "--json"]
        monkeypatch.setattr("sys.argv", testArgs)
        assert cliMain() == 0

