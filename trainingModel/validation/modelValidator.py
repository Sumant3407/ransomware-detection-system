"""Model artifact security, schema compatibility, and performance validator."""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import numpy as np
import pandas as pd

from app.domain.schemas import featureColumns, featureSchemaVersion
from app.security.modelEncryption import (
    ModelEncryption,
    ModelEncryptionError,
    ModelTamperError,
)

logger = logging.getLogger(__name__)

RECOGNIZED_MALICIOUS_LABELS = {
    "ransomware",
    "ransomware_like",
    "ransomware-like",
    "malicious",
}


class ModelValidationError(ValueError):
    """Raised when a model artifact fails validation."""


@dataclass
class ModelValidationResult:
    """Detailed report of model artifact validation."""

    isValid: bool
    status: str  # "PASSED", "WARNING", "REJECTED"
    modelPath: str
    isEncrypted: bool = False
    classes: list[str] = field(default_factory=list)
    maliciousIndexes: list[int] = field(default_factory=list)
    featureSchemaVersion: str = ""
    featureColumns: list[str] = field(default_factory=list)
    averageLatencyMs: float = 0.0
    featureImportances: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        lines = [
            f"Model Validation Status: {self.status} (Valid: {self.isValid})",
            f"Artifact: {self.modelPath} (Encrypted: {self.isEncrypted})",
            f"Classes: {self.classes}",
            f"Average Latency: {self.averageLatencyMs:.3f} ms",
        ]
        if self.errors:
            lines.append("Errors (Blocking):")
            for err in self.errors:
                lines.append(f"  - [FAIL] {err}")
        if self.warnings:
            lines.append("Warnings (Non-blocking):")
            for warn in self.warnings:
                lines.append(f"  - [WARN] {warn}")
        return "\n".join(lines)


class ModelValidator:
    """
    Validates machine learning model artifacts for security integrity,
    schema compatibility, inference safety, and latency performance.
    """

    def __init__(
        self,
        encryption: Optional[ModelEncryption] = None,
        maxLatencyMs: float = 20.0,
    ):
        self.encryption = encryption or ModelEncryption()
        self.maxLatencyMs = maxLatencyMs

    def validateArtifact(
        self,
        modelPath: Union[str, Path],
        strict: bool = True,
    ) -> ModelValidationResult:
        """
        Validate a model artifact file.

        Args:
            modelPath: Path to .joblib artifact
            strict: If True, raises ModelValidationError on blocking errors

        Returns:
            ModelValidationResult instance
        """
        resolvedPath = Path(modelPath).resolve()
        errors: list[str] = []
        warnings: list[str] = []

        if not resolvedPath.is_file():
            errors.append(f"Model file does not exist: {resolvedPath}")
            result = ModelValidationResult(
                isValid=False,
                status="REJECTED",
                modelPath=str(resolvedPath),
                errors=errors,
            )
            if strict:
                raise ModelValidationError(errors[0])
            return result

        # Step 1: Check encryption and load artifact
        isEncrypted = ModelEncryption.isEncryptedFile(resolvedPath)
        try:
            artifact = self.encryption.loadModel(resolvedPath)
        except ModelTamperError as error:
            errors.append(f"Model integrity verification failed (tampering detected): {error}")
            result = ModelValidationResult(
                isValid=False,
                status="REJECTED",
                modelPath=str(resolvedPath),
                isEncrypted=isEncrypted,
                errors=errors,
            )
            if strict:
                raise ModelValidationError(errors[0]) from error
            return result
        except (ModelEncryptionError, Exception) as error:
            errors.append(f"Failed to load or decrypt model artifact: {error}")
            result = ModelValidationResult(
                isValid=False,
                status="REJECTED",
                modelPath=str(resolvedPath),
                isEncrypted=isEncrypted,
                errors=errors,
            )
            if strict:
                raise ModelValidationError(errors[0]) from error
            return result

        # Step 2: Validate artifact structure
        if not isinstance(artifact, dict):
            errors.append("Model artifact is not a dictionary")
            result = ModelValidationResult(
                isValid=False,
                status="REJECTED",
                modelPath=str(resolvedPath),
                isEncrypted=isEncrypted,
                errors=errors,
            )
            if strict:
                raise ModelValidationError(errors[0])
            return result

        # Step 3: Feature Schema Verification
        artifactCols = tuple(artifact.get("featureColumns", ()))
        schemaVer = str(artifact.get("featureSchemaVersion", ""))

        if artifactCols != featureColumns:
            errors.append(
                f"Model feature columns mismatch. Expected: {list(featureColumns)}, Found: {list(artifactCols)}"
            )

        if schemaVer != featureSchemaVersion:
            warnings.append(
                f"Model schema version '{schemaVer}' differs from current '{featureSchemaVersion}'"
            )

        # Step 4: Estimator Capabilities
        model = artifact.get("model")
        if model is None:
            errors.append("Model artifact does not contain a 'model' estimator")
        elif not hasattr(model, "predict_proba"):
            errors.append("Model estimator lacks 'predict_proba' method")

        classes = list(getattr(model, "classes_", [])) if model is not None else []
        maliciousIndexes = [
            i for i, cls in enumerate(classes)
            if str(cls).strip().lower() in RECOGNIZED_MALICIOUS_LABELS
        ]

        if not maliciousIndexes and model is not None:
            errors.append(
                f"Model has no recognized malicious class in classes: {classes}"
            )

        # Step 5: Feature Importances Extraction (if available)
        importances: dict[str, float] = {}
        rawImportances = None
        if hasattr(model, "feature_importances_"):
            rawImportances = model.feature_importances_
        elif hasattr(model, "named_steps") and "classifier" in model.named_steps:
            classifier = model.named_steps["classifier"]
            if hasattr(classifier, "feature_importances_"):
                rawImportances = classifier.feature_importances_

        if rawImportances is not None and len(rawImportances) == len(featureColumns):
            for col, val in zip(featureColumns, rawImportances):
                importances[col] = round(float(val), 6)

        # Step 6: Inference Latency and Sanity Probing
        latencyMs = 0.0
        if not errors and model is not None:
            try:
                probeInput = pd.DataFrame(
                    [[0.0] * len(featureColumns)],
                    columns=featureColumns,
                )
                # Benchmark 20 iterations
                times = []
                for _ in range(20):
                    t0 = time.perf_counter()
                    proba = model.predict_proba(probeInput)
                    times.append((time.perf_counter() - t0) * 1000.0)

                latencyMs = float(np.mean(times))
                if latencyMs > self.maxLatencyMs:
                    warnings.append(
                        f"Inference latency {latencyMs:.2f}ms exceeds threshold {self.maxLatencyMs}ms"
                    )

                # Verify probability bounds [0.0, 1.0]
                if np.any(proba < 0.0) or np.any(proba > 1.0):
                    errors.append(f"Model output probabilities out of [0, 1] range: {proba}")

            except Exception as probeError:
                errors.append(f"Model inference sanity probe failed: {probeError}")

        isValid = len(errors) == 0
        status = "PASSED" if isValid and not warnings else ("WARNING" if isValid else "REJECTED")

        result = ModelValidationResult(
            isValid=isValid,
            status=status,
            modelPath=str(resolvedPath),
            isEncrypted=isEncrypted,
            classes=[str(c) for c in classes],
            maliciousIndexes=maliciousIndexes,
            featureSchemaVersion=schemaVer,
            featureColumns=list(artifactCols),
            averageLatencyMs=round(latencyMs, 4),
            featureImportances=importances,
            errors=errors,
            warnings=warnings,
        )

        logger.info(
            f"Model artifact validation completed: status={status}, path={resolvedPath.name}",
            extra={"event": "model_artifact_validation", "context": {"status": status, "isValid": isValid}},
        )

        if strict and not isValid:
            raise ModelValidationError(f"Model artifact validation failed: {'; '.join(errors)}")

        return result
