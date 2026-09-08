"""Validated model prediction interface."""

from pathlib import Path
from typing import Any

import pandas as pd
from joblib import load

from app.domain.schemas import featureColumns


class ModelValidationError(ValueError):
    """Raised when a model artifact is missing or incompatible."""


class ModelPredictor:
    def __init__(self, modelPath: Path):
        self.modelPath = modelPath.resolve()
        self.model = self._loadTrustedModel()

    def _loadTrustedModel(self) -> Any:
        if not self.modelPath.is_file():
            raise ModelValidationError(f"Model was not found: {self.modelPath}")
        try:
            artifact = load(self.modelPath)
        except Exception as error:
            raise ModelValidationError("Model validation failed") from error
        if not isinstance(artifact, dict):
            raise ModelValidationError("Model artifact has an invalid structure")
        if tuple(artifact.get("featureColumns", ())) != featureColumns:
            raise ModelValidationError("Model feature schema does not match runtime schema")
        model = artifact.get("model")
        if model is None or not hasattr(model, "predict_proba"):
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
            raise ModelValidationError("Model has no recognized malicious label")
        self.maliciousIndexes = maliciousIndexes
        return model

    def predictProbability(self, values: dict[str, float]) -> float:
        missingColumns = [column for column in featureColumns if column not in values]
        if missingColumns:
            raise ModelValidationError(
                f"Prediction is missing features: {', '.join(missingColumns)}"
            )
        frame = pd.DataFrame([[values[column] for column in featureColumns]], columns=featureColumns)
        probabilities = self.model.predict_proba(frame)
        return float(max(probabilities[0][index] for index in self.maliciousIndexes))
