"""Automated model retraining pipeline with feedback collection, performance tracking, promotion gates, and rollback."""

import json
import logging
import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Optional, Union

import pandas as pd

from app.config.configuration import getProjectRoot
from app.detection.predictor import ModelPredictor, ModelValidationError
from app.domain.schemas import featureColumns, featureSchemaVersion
from app.logging.logger import logSecurityEvent
from app.models.modelRegistry import ModelRegistry, ModelRegistryError
from app.security.modelEncryption import ModelEncryption
from app.storage.sqliteStore import (
    getLatestRetrainingRuns,
    getMonitoredPathId,
    getPooledConnection,
    getUnusedDetectionFeedback,
    initializeDatabase,
    markFeedbackUsedInRetraining,
    recordDetectionFeedback,
    recordRetrainingRun,
)
from trainingModel.training.trainModel import trainModel
from trainingModel.validation.datasetSchema import reconcileDataset
from trainingModel.validation.datasetValidator import DatasetValidationError, DatasetValidator

logger = logging.getLogger(__name__)


class RetrainingTrigger(StrEnum):
    THRESHOLD = "threshold"
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    DRIFT = "drift"


class RetrainingStatus(StrEnum):
    COMPLETED = "completed"
    REJECTED = "rejected"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class RetrainingConfig:
    """Configuration governing automated model retraining and promotion criteria."""

    minNewFeedbackSamples: int = 5
    minCvF1Score: float = 0.90
    maxF1DropTolerance: float = 0.02
    maxFalsePositiveRate: float = 0.05
    minRocAuc: float = 0.90
    cvFolds: int = 5
    tuneHyperparameters: bool = False
    useScaler: bool = True
    encryptArtifacts: bool = True


@dataclass
class RetrainingReport:
    """Detailed summary of a retraining execution."""

    success: bool
    promoted: bool
    status: RetrainingStatus
    triggerType: RetrainingTrigger
    baselineVersion: str
    candidateVersion: str
    sampleCount: int
    feedbackSampleCount: int
    cvAccuracy: float
    cvF1: float
    cvRocAuc: Optional[float]
    baselineF1: Optional[float]
    reason: str
    durationSeconds: float
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def toDict(self) -> dict[str, Any]:
        return asdict(self)


class RetrainingPipeline:
    """
    Orchestrates automated retraining of ransomware classification models based on
    continuous feedback, performs rigorous cross-validation and promotion gating,
    and enables zero-downtime activation and rollback.
    """

    def __init__(
        self,
        modelsDirectory: Union[str, Path],
        databasePath: Union[str, Path],
        datasetPath: Union[str, Path] = "data/datasets/ransomwareBehaviorDataset.csv",
        config: Optional[RetrainingConfig] = None,
        encryption: Optional[ModelEncryption] = None,
    ):
        self.modelsDirectory = Path(modelsDirectory).resolve()
        self.databasePath = Path(databasePath).resolve()
        self.datasetPath = Path(datasetPath)
        if not self.datasetPath.is_absolute():
            self.datasetPath = getProjectRoot() / self.datasetPath

        self.config = config or RetrainingConfig()
        self.encryption = encryption or ModelEncryption()
        self.registry = ModelRegistry(
            modelsDirectory=self.modelsDirectory,
            databasePath=self.databasePath,
            encryption=self.encryption,
        )

    def recordFeedback(
        self,
        sampleValues: dict[str, float],
        predictedClass: str,
        actualLabel: str,
        detectionId: Optional[int] = None,
        confidence: Optional[float] = None,
    ) -> int:
        """
        Record a labeled sample from user feedback or analyst verification into the SQLite store.
        """
        connection = initializeDatabase(self.databasePath)
        try:
            feedbackId = recordDetectionFeedback(
                connection=connection,
                sampleValues=sampleValues,
                predictedClass=predictedClass,
                actualLabel=actualLabel,
                detectionId=detectionId,
                confidence=confidence,
            )
            connection.commit()
            logger.info(
                f"Detection feedback recorded: id={feedbackId}, label={actualLabel}, predicted={predictedClass}",
                extra={"event": "feedback_recorded", "context": {"feedbackId": feedbackId, "label": actualLabel}},
            )
            return feedbackId
        finally:
            connection.close()

    def checkTriggers(self) -> tuple[bool, RetrainingTrigger, int]:
        """
        Check whether retraining conditions are met based on accumulated feedback.

        Returns:
            Tuple of (shouldRetrain: bool, triggerType: RetrainingTrigger, newSampleCount: int)
        """
        connection = initializeDatabase(self.databasePath)
        try:
            unused = getUnusedDetectionFeedback(connection)
            count = len(unused)
            if count >= self.config.minNewFeedbackSamples:
                return True, RetrainingTrigger.THRESHOLD, count
            return False, RetrainingTrigger.THRESHOLD, count
        finally:
            connection.close()

    def getActiveModelMetadata(self) -> dict[str, Any]:
        """
        Retrieve metadata and performance baseline for current active model.
        """
        activeMetadataPath = self.modelsDirectory / "current" / "metadata.json"
        if activeMetadataPath.is_file():
            try:
                return json.loads(activeMetadataPath.read_text(encoding="utf-8"))
            except Exception as error:
                logger.warning(f"Could not parse active model metadata: {error}")

        # Fallback to root model metadata if exists
        rootMetadataPath = getProjectRoot() / "ransomwareModel.metadata.json"
        if rootMetadataPath.is_file():
            try:
                return json.loads(rootMetadataPath.read_text(encoding="utf-8"))
            except Exception as error:
                logger.warning(f"Could not parse root model metadata: {error}")

        return {
            "modelVersion": "1.0.0",
            "metrics": {"f1": 0.95, "accuracy": 0.95, "falsePositiveRate": 0.0},
            "crossValidation": {"meanF1": 0.95, "meanAccuracy": 0.95, "meanFalsePositiveRate": 0.0},
        }

    def _generateCandidateVersion(self, baselineVersion: str) -> str:
        """Generate next incremental version string."""
        now = datetime.now(timezone.utc)
        clean = baselineVersion.lstrip("v")
        parts = clean.split(".")
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
            return f"v{major}.{minor}.{patch + 1}"
        return f"v1.0.{now.strftime('%Y%m%d%H%M%S')}"

    def executeRetraining(
        self,
        triggerType: RetrainingTrigger = RetrainingTrigger.MANUAL,
        force: bool = False,
    ) -> RetrainingReport:
        """
        Execute an automated retraining workflow:
        1. Fetch unused feedback samples from SQLite store.
        2. Combine with base training dataset.
        3. Validate combined dataset quality & security.
        4. Run 5-fold stratified cross-validation and hyperparameter tuning.
        5. Evaluate candidate model metrics against baseline model.
        6. Apply promotion gate (F1 score, FPR, ROC-AUC constraints).
        7. If promoted: atomically activate new model (creating rollback backup) and mark feedback used.
        8. Record full execution report in database and structured logs.

        Args:
            triggerType: Reason for retraining
            force: If True, bypasses minimum feedback sample threshold

        Returns:
            RetrainingReport instance
        """
        startTime = time.perf_counter()
        startedAt = datetime.now(timezone.utc).isoformat()
        connection = initializeDatabase(self.databasePath)

        activeMetadata = self.getActiveModelMetadata()
        baselineVersion = str(activeMetadata.get("modelVersion", "1.0.0"))
        baselineF1 = float(
            activeMetadata.get("crossValidation", {}).get("meanF1")
            or activeMetadata.get("metrics", {}).get("f1")
            or 0.90
        )

        try:
            # Step 1: Collect unused feedback
            feedbackRows = getUnusedDetectionFeedback(connection)
            feedbackCount = len(feedbackRows)

            if not force and feedbackCount < self.config.minNewFeedbackSamples and triggerType == RetrainingTrigger.THRESHOLD:
                reason = f"Insufficient new feedback samples: {feedbackCount} < {self.config.minNewFeedbackSamples}"
                logger.info(f"Retraining skipped: {reason}")
                return RetrainingReport(
                    success=False,
                    promoted=False,
                    status=RetrainingStatus.REJECTED,
                    triggerType=triggerType,
                    baselineVersion=baselineVersion,
                    candidateVersion=baselineVersion,
                    sampleCount=0,
                    feedbackSampleCount=feedbackCount,
                    cvAccuracy=0.0,
                    cvF1=0.0,
                    cvRocAuc=None,
                    baselineF1=baselineF1,
                    reason=reason,
                    durationSeconds=round(time.perf_counter() - startTime, 4),
                )

            # Step 2: Load and reconcile base dataset
            if not self.datasetPath.is_file():
                raise FileNotFoundError(f"Base dataset not found: {self.datasetPath}")

            baseDf = pd.read_csv(self.datasetPath)
            baseDf = reconcileDataset(baseDf)

            # Step 3: Integrate feedback samples
            feedbackIds: list[int] = []
            if feedbackRows:
                feedbackSamples = []
                for row in feedbackRows:
                    feedbackIds.append(row["feedbackId"])
                    sample = dict(row["sampleValues"])
                    sample["label"] = row["actualLabel"]
                    if "timestamp" not in sample:
                        sample["timestamp"] = row["feedbackAt"]
                    feedbackSamples.append(sample)

                feedbackDf = pd.DataFrame(feedbackSamples)
                feedbackDf = reconcileDataset(feedbackDf)
                combinedDf = pd.concat([baseDf, feedbackDf], ignore_index=True)
            else:
                combinedDf = baseDf.copy()

            # Step 4: Validate combined dataset
            validator = DatasetValidator()
            validationResult = validator.validate(combinedDf, strict=True)
            if not validationResult.isValid:
                raise DatasetValidationError(f"Combined dataset validation failed: {validationResult.errors}")

            # Step 5: Train candidate model artifact
            candidateVersion = self._generateCandidateVersion(baselineVersion)
            candidatesDir = self.modelsDirectory / "candidates"
            candidatesDir.mkdir(parents=True, exist_ok=True)
            candidateArtifactPath = candidatesDir / f"candidate_{candidateVersion}.joblib"

            trainingMetadata = trainModel(
                dataset=combinedDf,
                modelPath=candidateArtifactPath,
                encrypt=False,  # Keep unencrypted in staging; encrypted on activation
                cvFolds=self.config.cvFolds,
                tune=self.config.tuneHyperparameters,
                useScaler=self.config.useScaler,
                autoReconcileSchema=False,
            )

            cvMetrics = trainingMetadata.get("crossValidation", {})
            cvAccuracy = float(cvMetrics.get("meanAccuracy", 0.0))
            cvF1 = float(cvMetrics.get("meanF1", 0.0))
            cvRocAuc = cvMetrics.get("meanRocAuc")
            cvFpr = float(cvMetrics.get("meanFalsePositiveRate", 0.0))

            # Step 6: Promotion Gate Decisions
            rejectionReasons: list[str] = []
            if cvF1 < self.config.minCvF1Score:
                rejectionReasons.append(f"Candidate F1 score ({cvF1:.4f}) below minimum ({self.config.minCvF1Score:.4f})")

            if cvF1 < (baselineF1 - self.config.maxF1DropTolerance):
                rejectionReasons.append(
                    f"Candidate F1 score ({cvF1:.4f}) dropped more than {self.config.maxF1DropTolerance:.4f} below baseline ({baselineF1:.4f})"
                )

            if cvFpr > self.config.maxFalsePositiveRate:
                rejectionReasons.append(
                    f"Candidate false positive rate ({cvFpr:.4f}) exceeds threshold ({self.config.maxFalsePositiveRate:.4f})"
                )

            if cvRocAuc is not None and cvRocAuc < self.config.minRocAuc:
                rejectionReasons.append(f"Candidate ROC-AUC ({cvRocAuc:.4f}) below minimum ({self.config.minRocAuc:.4f})")

            promoted = len(rejectionReasons) == 0

            # Step 7: Apply Promotion or Rejection
            if promoted:
                # Update modelVersion in metadata sidecar before activation
                trainingMetadata["modelVersion"] = candidateVersion
                metaPath = candidateArtifactPath.with_suffix(".metadata.json")
                metaPath.write_text(json.dumps(trainingMetadata, indent=2), encoding="utf-8")

                # Activate through ModelRegistry (creates backup of previous.joblib and updates database)
                activatedPath = self.registry.activateModel(
                    candidateArtifactPath,
                    encrypt=self.config.encryptArtifacts,
                )

                # Mark feedback as used
                if feedbackIds:
                    markFeedbackUsedInRetraining(connection, feedbackIds)

                status = RetrainingStatus.COMPLETED
                reason = "Candidate model passed all validation gates and was promoted to active"

                logSecurityEvent(
                    logger,
                    action="model_retraining_promotion",
                    target=str(activatedPath),
                    status="allowed",
                    details={
                        "candidateVersion": candidateVersion,
                        "baselineVersion": baselineVersion,
                        "cvF1": cvF1,
                        "baselineF1": baselineF1,
                        "sampleCount": len(combinedDf),
                    },
                )
            else:
                status = RetrainingStatus.REJECTED
                reason = f"Model promotion rejected: {'; '.join(rejectionReasons)}"
                logger.warning(f"Candidate model {candidateVersion} rejected: {reason}")

                logSecurityEvent(
                    logger,
                    action="model_retraining_promotion",
                    target=str(candidateArtifactPath),
                    status="blocked",
                    details={"reason": reason, "candidateF1": cvF1, "baselineF1": baselineF1},
                )

            durationSeconds = round(time.perf_counter() - startTime, 4)
            completedAt = datetime.now(timezone.utc).isoformat()

            report = RetrainingReport(
                success=True,
                promoted=promoted,
                status=status,
                triggerType=triggerType,
                baselineVersion=baselineVersion,
                candidateVersion=candidateVersion if promoted else baselineVersion,
                sampleCount=len(combinedDf),
                feedbackSampleCount=feedbackCount,
                cvAccuracy=cvAccuracy,
                cvF1=cvF1,
                cvRocAuc=cvRocAuc,
                baselineF1=baselineF1,
                reason=reason,
                durationSeconds=durationSeconds,
            )

            # Step 8: Persist Retraining Run in Database
            recordRetrainingRun(
                connection=connection,
                startedAt=startedAt,
                completedAt=completedAt,
                triggerType=str(triggerType),
                sampleCount=len(combinedDf),
                feedbackSampleCount=feedbackCount,
                baselineModelVersion=baselineVersion,
                candidateModelVersion=candidateVersion,
                cvAccuracy=cvAccuracy,
                cvF1=cvF1,
                cvRocAuc=cvRocAuc,
                baselineF1=baselineF1,
                promoted=promoted,
                status=str(status),
                rollbackReady=True,
                reportJson=json.dumps(report.toDict()),
            )
            connection.commit()
            return report

        except Exception as error:
            logger.error(f"Retraining pipeline failed with error: {error}", exc_info=True)
            durationSeconds = round(time.perf_counter() - startTime, 4)
            completedAt = datetime.now(timezone.utc).isoformat()

            report = RetrainingReport(
                success=False,
                promoted=False,
                status=RetrainingStatus.FAILED,
                triggerType=triggerType,
                baselineVersion=baselineVersion,
                candidateVersion=baselineVersion,
                sampleCount=0,
                feedbackSampleCount=0,
                cvAccuracy=0.0,
                cvF1=0.0,
                cvRocAuc=None,
                baselineF1=baselineF1,
                reason=str(error),
                durationSeconds=durationSeconds,
            )

            try:
                recordRetrainingRun(
                    connection=connection,
                    startedAt=startedAt,
                    completedAt=completedAt,
                    triggerType=str(triggerType),
                    sampleCount=0,
                    feedbackSampleCount=0,
                    baselineModelVersion=baselineVersion,
                    candidateModelVersion=baselineVersion,
                    cvAccuracy=0.0,
                    cvF1=0.0,
                    cvRocAuc=None,
                    baselineF1=baselineF1,
                    promoted=False,
                    status=str(RetrainingStatus.FAILED),
                    rollbackReady=False,
                    reportJson=json.dumps({"error": str(error)}),
                )
                connection.commit()
            except Exception as dbErr:
                logger.warning(f"Could not log failed retraining run to database: {dbErr}")

            return report

        finally:
            connection.close()

    def rollback(self) -> Path:
        """
        Immediately roll back the active production model to the previous known-good model version.
        """
        logger.warning("Executing manual model rollback to previous version...")
        connection = initializeDatabase(self.databasePath)
        try:
            rolledBackModel = self.registry.rollbackModel()

            # Record rollback in database
            now = datetime.now(timezone.utc).isoformat()
            recordRetrainingRun(
                connection=connection,
                startedAt=now,
                completedAt=now,
                triggerType=str(RetrainingTrigger.MANUAL),
                sampleCount=0,
                feedbackSampleCount=0,
                baselineModelVersion="current",
                candidateModelVersion="previous",
                cvAccuracy=0.0,
                cvF1=0.0,
                cvRocAuc=None,
                baselineF1=None,
                promoted=False,
                status=str(RetrainingStatus.ROLLED_BACK),
                rollbackReady=False,
                reportJson=json.dumps({"action": "rollback", "timestamp": now}),
            )
            connection.commit()

            logSecurityEvent(
                logger,
                action="model_rollback",
                target=str(rolledBackModel),
                status="allowed",
                details={"action": "reverted_to_previous_model"},
            )
            return rolledBackModel
        finally:
            connection.close()

    def getHistory(self, limit: int = 10) -> list[dict[str, Any]]:
        """Fetch retraining run history from database."""
        connection = initializeDatabase(self.databasePath)
        try:
            return getLatestRetrainingRuns(connection, limit=limit)
        finally:
            connection.close()
