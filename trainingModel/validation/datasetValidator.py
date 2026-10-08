"""Dataset security validation and poisoning detection engine."""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np
import pandas as pd

from app.domain.schemas import featureColumns

logger = logging.getLogger(__name__)

# Recognized class labels
BENIGN_LABELS = {"benign", "normal", "safe", "clean"}
MALICIOUS_LABELS = {
    "ransomware",
    "ransomware_like",
    "ransomware-like",
    "malicious",
    "attack",
}

# Standard optional metadata columns permitted in datasets
OPTIONAL_METADATA_COLUMNS = {"timestamp", "observedAt", "pathId", "id", "sampleId"}

# Physical bounds for known domain features
FEATURE_BOUNDS: dict[str, tuple[Optional[float], Optional[float]]] = {
    "averageFileEntropy": (0.0, 8.0),  # Shannon entropy in bits per byte [0, 8]
    "fileReadCount": (0.0, None),
    "fileWriteCount": (0.0, None),
    "fileCreateCount": (0.0, None),
    "fileRenameCount": (0.0, None),
    "fileDeleteCount": (0.0, None),
    "filesModifiedPerMinute": (0.0, None),
    "uniqueDirectoriesModified": (0.0, None),
    "uniqueExtensionsModified": (0.0, None),
    "extensionChangeCount": (0.0, None),
    "entropyChangeRate": (0.0, None),
    "processCpuUsage": (0.0, 1000.0),  # Multi-core CPU % can exceed 100%, cap at 1000%
    "processMemoryUsage": (0.0, None),
    "processLifetime": (0.0, None),
    "networkBytes": (0.0, None),
    "networkConnectionCount": (0.0, None),
}


class DatasetValidationError(ValueError):
    """Raised when dataset fails security validation or poisoning checks."""


@dataclass
class DatasetValidationResult:
    """Detailed report of dataset security and quality validation."""

    isValid: bool
    status: str  # "PASSED", "WARNING", "REJECTED"
    sampleCount: int
    classDistribution: dict[str, int] = field(default_factory=dict)
    classPercentages: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    anomalousSamplesCount: int = 0
    conflictingSamplesCount: int = 0
    duplicateSamplesCount: int = 0

    @property
    def summary(self) -> str:
        """Formatted human-readable summary of the validation report."""
        lines = [
            f"Dataset Validation Status: {self.status} (Valid: {self.isValid})",
            f"Total Samples: {self.sampleCount}",
            f"Class Distribution: {self.classDistribution} ({self.classPercentages})",
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


class DatasetValidator:
    """
    Validates ML training datasets for poisoning attacks, label corruption,
    feature anomalies, and distribution anomalies.
    """

    def __init__(
        self,
        minSamplesPerClass: int = 2,
        minTotalSamples: int = 4,
        maxClassImbalanceRatio: float = 0.95,
        minClassRatio: float = 0.05,
        zScoreThreshold: float = 6.0,
    ):
        self.minSamplesPerClass = minSamplesPerClass
        self.minTotalSamples = minTotalSamples
        self.maxClassImbalanceRatio = maxClassImbalanceRatio
        self.minClassRatio = minClassRatio
        self.zScoreThreshold = zScoreThreshold

    def validate(self, dataset: pd.DataFrame, strict: bool = True) -> DatasetValidationResult:
        """
        Run full validation suite on dataset.

        Args:
            dataset: pandas DataFrame to validate
            strict: If True, raises DatasetValidationError on blocking errors

        Returns:
            DatasetValidationResult instance
        """
        errors: list[str] = []
        warnings: list[str] = []

        # 1. Structural and Empty Checks
        if not isinstance(dataset, pd.DataFrame):
            errors.append("Dataset must be a pandas DataFrame")
            result = DatasetValidationResult(
                isValid=False,
                status="REJECTED",
                sampleCount=0,
                errors=errors,
            )
            if strict:
                raise DatasetValidationError(errors[0])
            return result

        sampleCount = len(dataset)
        if sampleCount < self.minTotalSamples:
            errors.append(
                f"Dataset contains {sampleCount} samples, minimum required is {self.minTotalSamples}"
            )

        # 2. Required Columns & Types
        requiredColumns = set(featureColumns) | {"label"}
        missingColumns = sorted(requiredColumns - set(dataset.columns))
        if missingColumns:
            errors.append(f"Dataset is missing required columns: {', '.join(missingColumns)}")

        extraColumns = sorted(set(dataset.columns) - (requiredColumns | OPTIONAL_METADATA_COLUMNS))
        if extraColumns:
            warnings.append(f"Dataset contains unexpected extra columns: {', '.join(extraColumns)}")

        if errors:
            result = DatasetValidationResult(
                isValid=False,
                status="REJECTED",
                sampleCount=sampleCount,
                errors=errors,
                warnings=warnings,
            )
            if strict:
                raise DatasetValidationError("; ".join(errors))
            return result

        # 3. Label Validation & Class Balance (Poisoning Check 1: Label Monoculture)
        labels = dataset["label"].astype(str).str.strip().str.lower()
        if dataset["label"].isna().any():
            errors.append("Dataset contains null or missing labels")

        classCounts = labels.value_counts().to_dict()
        uniqueClasses = len(classCounts)

        classPercentages = {
            cls: round((count / sampleCount) * 100.0, 2)
            for cls, count in classCounts.items()
        }

        if uniqueClasses < 2:
            errors.append(
                f"Dataset contains only {uniqueClasses} class ({list(classCounts.keys())}). "
                "Training requires at least 2 distinct classes (e.g. Benign and Ransomware). "
                "Single-class dataset cannot be used for supervised classification."
            )

        # Check that we have at least one recognized benign and one recognized malicious class
        hasBenign = any(cls in BENIGN_LABELS for cls in classCounts)
        hasMalicious = any(cls in MALICIOUS_LABELS for cls in classCounts)

        if not hasBenign:
            warnings.append(f"No standard benign label detected in classes: {list(classCounts.keys())}")
        if not hasMalicious:
            warnings.append(f"No standard malicious label detected in classes: {list(classCounts.keys())}")

        for cls, count in classCounts.items():
            if count < self.minSamplesPerClass:
                errors.append(
                    f"Class '{cls}' has only {count} samples (minimum required: {self.minSamplesPerClass})"
                )

        # Imbalance check
        for cls, pct in classPercentages.items():
            if pct > (self.maxClassImbalanceRatio * 100.0) and uniqueClasses > 1:
                warnings.append(
                    f"Severe class imbalance: Class '{cls}' accounts for {pct}% of dataset"
                )
            elif pct < (self.minClassRatio * 100.0) and uniqueClasses > 1:
                warnings.append(
                    f"Severe class scarcity: Class '{cls}' accounts for only {pct}% of dataset"
                )

        # 4. Missing / Non-Numeric Values in Features
        numericFeatures = dataset[list(featureColumns)].apply(pd.to_numeric, errors="coerce")
        nanCounts = numericFeatures.isna().sum()
        colsWithNans = nanCounts[nanCounts > 0]
        if not colsWithNans.empty:
            errors.append(
                f"Feature columns contain missing, NaN, or non-numeric values: {colsWithNans.to_dict()}"
            )

        # Check for Infinite values
        infCounts = np.isinf(numericFeatures.values).sum()
        if infCounts > 0:
            errors.append(f"Feature matrix contains {infCounts} infinite (inf / -inf) values")

        # 5. Domain Bounds & Physical Constraints (Poisoning Check 2: Out of Bounds Features)
        for col, (minBound, maxBound) in FEATURE_BOUNDS.items():
            if col in numericFeatures.columns:
                series = numericFeatures[col]
                if minBound is not None:
                    belowMin = (series < minBound).sum()
                    if belowMin > 0:
                        errors.append(
                            f"Feature '{col}' has {belowMin} values below physical minimum {minBound}"
                        )
                if maxBound is not None:
                    aboveMax = (series > maxBound).sum()
                    if aboveMax > 0:
                        errors.append(
                            f"Feature '{col}' has {aboveMax} values above physical maximum {maxBound}"
                        )

        # 6. Label Flip & Conflict Detection (Poisoning Check 3: Identical features with conflicting labels)
        conflictingSamplesCount = 0
        featureMatrix = numericFeatures.copy()
        featureMatrix["_label"] = labels
        groupedByFeatures = featureMatrix.groupby(list(featureColumns))["_label"].nunique()
        conflicts = groupedByFeatures[groupedByFeatures > 1]
        if not conflicts.empty:
            conflictingSamplesCount = int(conflicts.sum())
            errors.append(
                f"Detected {conflictingSamplesCount} feature vectors with contradictory labels (Label flip attack detected)"
            )

        # 7. Exact Duplicates
        duplicateCount = int(dataset.duplicated().sum())
        if duplicateCount > 0:
            warnings.append(f"Dataset contains {duplicateCount} duplicate sample rows")

        # 8. Statistical Extreme Outlier Detection (Poisoning Check 4: Z-Score Outliers)
        anomalousSamplesCount = 0
        if sampleCount >= 10:
            for col in featureColumns:
                if col in numericFeatures.columns:
                    colValues = numericFeatures[col]
                    std = colValues.std()
                    if std > 0:
                        zScores = np.abs((colValues - colValues.mean()) / std)
                        extremeOutliers = (zScores > self.zScoreThreshold).sum()
                        if extremeOutliers > 0:
                            anomalousSamplesCount += int(extremeOutliers)
                            warnings.append(
                                f"Feature '{col}' contains {extremeOutliers} extreme statistical outliers (|z| > {self.zScoreThreshold})"
                            )

        # Final Status Decision
        isValid = len(errors) == 0
        status = "PASSED" if isValid and not warnings else ("WARNING" if isValid else "REJECTED")

        result = DatasetValidationResult(
            isValid=isValid,
            status=status,
            sampleCount=sampleCount,
            classDistribution=classCounts,
            classPercentages=classPercentages,
            errors=errors,
            warnings=warnings,
            anomalousSamplesCount=anomalousSamplesCount,
            conflictingSamplesCount=conflictingSamplesCount,
            duplicateSamplesCount=duplicateCount,
        )

        logger.info(
            f"Dataset validation completed: status={status}, valid={isValid}, samples={sampleCount}",
            extra={
                "event": "dataset_validation",
                "context": {
                    "status": status,
                    "isValid": isValid,
                    "sampleCount": sampleCount,
                    "errorCount": len(errors),
                    "warningCount": len(warnings),
                },
            },
        )

        if strict and not isValid:
            raise DatasetValidationError(f"Dataset validation failed: {'; '.join(errors)}")

        return result


def validateDatasetSecurity(dataset: pd.DataFrame, strict: bool = True) -> DatasetValidationResult:
    """Convenience helper to validate dataset security and poisoning resistance."""
    validator = DatasetValidator()
    return validator.validate(dataset, strict=strict)


def getFeatureStatistics(dataset: pd.DataFrame) -> dict[str, dict[str, float]]:
    """
    Calculate comprehensive statistical profile for each feature column in the dataset.

    Returns:
        Dictionary mapping feature name to statistics (mean, std, min, max, median, q25, q75)
    """
    stats: dict[str, dict[str, float]] = {}
    for col in featureColumns:
        if col in dataset.columns:
            series = pd.to_numeric(dataset[col], errors="coerce").dropna()
            if not series.empty:
                stats[col] = {
                    "mean": round(float(series.mean()), 4),
                    "std": round(float(series.std()), 4),
                    "min": round(float(series.min()), 4),
                    "max": round(float(series.max()), 4),
                    "median": round(float(series.median()), 4),
                    "q25": round(float(series.quantile(0.25)), 4),
                    "q75": round(float(series.quantile(0.75)), 4),
                }
    return stats

