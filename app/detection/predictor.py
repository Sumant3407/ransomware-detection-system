"""Validated model prediction interface with encryption support, feature explainability, and structured logging."""

import logging
import time
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd

from app.domain.schemas import featureColumns
from app.logging.logger import logSecurityEvent
from app.security.modelEncryption import (
    ModelEncryption,
    ModelEncryptionError,
    ModelTamperError,
)

logger = logging.getLogger(__name__)


class ModelValidationError(ValueError):
    """Raised when a model artifact is missing, corrupt, tampered, or incompatible."""


class ModelPredictor:
    def __init__(self, modelPath: Path, encryption: Optional[ModelEncryption] = None):
        self.modelPath = modelPath.resolve()
        self.encryption = encryption or ModelEncryption()
        self.artifact: dict[str, Any] = {}
        self.maliciousIndexes: list[int] = []
        self.model = self._loadTrustedModel()

    def _loadTrustedModel(self) -> Any:
        if not self.modelPath.is_file():
            logger.warning(f"Model file not found: {self.modelPath}", extra={"event": "model_validation"})
            logSecurityEvent(
                logger,
                action="model_load",
                target=str(self.modelPath),
                status="blocked",
                details={"reason": "file_not_found"},
            )
            raise ModelValidationError(f"Model was not found: {self.modelPath}")

        try:
            artifact = self.encryption.loadModel(self.modelPath)
        except ModelTamperError as error:
            logger.error(
                f"Model integrity verification failed: {error}",
                extra={"event": "security_audit", "context": {"modelPath": str(self.modelPath)}},
            )
            logSecurityEvent(
                logger,
                action="model_load",
                target=str(self.modelPath),
                status="blocked",
                details={"reason": "tamper_detected", "error": str(error)},
            )
            raise ModelValidationError(f"Model integrity verification failed: {error}") from error
        except (ModelEncryptionError, Exception) as error:
            logger.error(
                f"Failed to load model artifact {self.modelPath}: {error}",
                extra={"event": "model_validation", "context": {"modelPath": str(self.modelPath)}},
            )
            logSecurityEvent(
                logger,
                action="model_load",
                target=str(self.modelPath),
                status="failed",
                details={"reason": "load_error", "error": str(error)},
            )
            raise ModelValidationError("Model validation failed") from error

        if not isinstance(artifact, dict):
            logger.error("Model artifact is not a dictionary", extra={"event": "model_validation"})
            raise ModelValidationError("Model artifact has an invalid structure")

        if tuple(artifact.get("featureColumns", ())) != featureColumns:
            logger.error(
                "Model feature schema mismatch",
                extra={
                    "event": "model_validation",
                    "context": {
                        "expected": list(featureColumns),
                        "actual": list(artifact.get("featureColumns", ())),
                    },
                },
            )
            raise ModelValidationError("Model feature schema does not match runtime schema")

        model = artifact.get("model")
        if model is None or not hasattr(model, "predict_proba"):
            logger.error("Model lacks predict_proba method", extra={"event": "model_validation"})
            raise ModelValidationError("Model does not support probability prediction")

        classes = tuple(getattr(model, "classes_", ()))
        maliciousLabels = {
            "ransomware",
            "ransomware_like",
            "ransomware-like",
            "malicious",
        }
        maliciousIndexes = [
            index for index, value in enumerate(classes)
            if str(value).strip().lower() in maliciousLabels
        ]
        if not maliciousIndexes:
            logger.error(
                f"Model has no malicious label in classes: {classes}",
                extra={"event": "model_validation", "context": {"classes": list(classes)}},
            )
            raise ModelValidationError("Model has no recognized malicious label")

        self.artifact = artifact
        self.maliciousIndexes = maliciousIndexes
        isEncrypted = ModelEncryption.isEncryptedFile(self.modelPath)

        logSecurityEvent(
            logger,
            action="model_load",
            target=str(self.modelPath),
            status="allowed",
            details={
                "isEncrypted": isEncrypted,
                "classes": list(classes),
                "maliciousIndexes": maliciousIndexes,
            },
        )

        logger.info(
            f"Model loaded successfully from {self.modelPath.name} (encrypted={isEncrypted})",
            extra={
                "event": "model_validation",
                "context": {
                    "modelPath": str(self.modelPath),
                    "classes": list(classes),
                    "maliciousIndexes": maliciousIndexes,
                    "isEncrypted": isEncrypted,
                },
            },
        )
        return model

    def predictProbability(self, values: dict[str, float]) -> float:
        """
        Calculate malicious threat probability for a dictionary of feature values.
        """
        missingColumns = [column for column in featureColumns if column not in values]
        if missingColumns:
            logger.error(f"Missing features in prediction input: {missingColumns}")
            raise ModelValidationError(
                f"Prediction is missing features: {', '.join(missingColumns)}"
            )

        startTime = time.perf_counter()
        frame = pd.DataFrame([[values[column] for column in featureColumns]], columns=featureColumns)
        probabilities = self.model.predict_proba(frame)
        probability = float(max(probabilities[0][index] for index in self.maliciousIndexes))
        elapsedMs = (time.perf_counter() - startTime) * 1000.0

        logger.debug(
            f"Prediction calculated: {probability:.4f} in {elapsedMs:.2f}ms",
            extra={
                "event": "model_prediction",
                "durationMs": elapsedMs,
                "context": {"probability": round(probability, 4)},
            },
        )
        return probability

    def getFeatureImportances(self) -> dict[str, float]:
        """
        Return the global feature importance rankings from the trained model artifact.
        """
        if "featureImportances" in self.artifact and self.artifact["featureImportances"]:
            return self.artifact["featureImportances"]

        rawImportances = None
        if hasattr(self.model, "feature_importances_"):
            rawImportances = self.model.feature_importances_
        elif hasattr(self.model, "named_steps") and "classifier" in self.model.named_steps:
            clf = self.model.named_steps["classifier"]
            if hasattr(clf, "feature_importances_"):
                rawImportances = clf.feature_importances_

        importances: dict[str, float] = {}
        if rawImportances is not None and len(rawImportances) == len(featureColumns):
            pairs = sorted(zip(featureColumns, rawImportances), key=lambda x: x[1], reverse=True)
            for col, val in pairs:
                importances[col] = round(float(val), 6)
        return importances

    def explainPrediction(self, values: dict[str, float], topN: int = 5) -> dict[str, Any]:
        """
        Explain the model prediction by identifying the top contributing features and risk drivers.
        """
        probability = self.predictProbability(values)
        importances = self.getFeatureImportances()

        contributions: list[dict[str, Any]] = []
        for col in featureColumns:
            val = float(values.get(col, 0.0))
            imp = importances.get(col, 0.0)
            contributions.append({
                "feature": col,
                "value": round(val, 4),
                "importance": round(imp, 4),
                "scoreWeight": round(val * imp, 4),
            })

        contributions.sort(key=lambda x: (x["scoreWeight"], x["importance"]), reverse=True)

        if probability >= 0.70:
            threat = "ransomwareLike"
        elif probability >= 0.35:
            threat = "suspicious"
        else:
            threat = "benign"

        return {
            "probability": round(probability, 4),
            "threatClassification": threat,
            "topContributingFeatures": contributions[:topN],
            "allContributions": contributions,
        }

    def predictWithExplanation(self, values: dict[str, float], topN: int = 5) -> tuple[float, dict[str, Any]]:
        """
        Calculate threat probability and return detailed decision explanation.
        """
        explanation = self.explainPrediction(values, topN=topN)
        return explanation["probability"], explanation
