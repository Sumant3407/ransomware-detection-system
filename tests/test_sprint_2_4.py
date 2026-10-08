"""Sprint 2.4 - Critical Dataset & Schema Fixes Test Suite.

Verifies:
1. Dataset schema reconciliation, legacy alias mapping, and missing column population.
2. Synthetic balanced behavioral dataset generation across multi-profile attack and benign traces.
3. Dataset security validation, poisoning detection, and feature statistical profiling.
4. Stratified 5-fold cross-validation with Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR.
5. Hyperparameter tuning via GridSearchCV and feature scaling with StandardScaler pipelines.
6. Comprehensive ModelValidator engine verifying structure, encryption, latency, and probing.
7. Enhanced ModelPredictor with feature importances and decision explanations.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd
import pytest
from sklearn.pipeline import Pipeline

from app.detection.predictor import ModelPredictor, ModelValidationError
from app.domain.schemas import featureColumns, featureSchemaVersion
from app.security.modelEncryption import ModelEncryption
from trainingModel.collection.syntheticData import (
    generateAndSaveDataset,
    generateSyntheticDataset,
    generateSyntheticSample,
)
from trainingModel.training.ransomwareLearner import loadDataset, trainModel as runTrainingWorkflow
from trainingModel.training.trainModel import (
    calculateMetrics,
    extractFeatureImportances,
    getDatasetFingerprint,
    runStratifiedCrossValidation,
    trainModel,
    tuneHyperparameters,
)
from trainingModel.validation.datasetSchema import (
    COLUMN_DEFAULTS,
    SCHEMA_ALIASES,
    reconcileDataset,
    reconcileDatasetFile,
)
from trainingModel.validation.datasetValidator import (
    DatasetValidationError,
    DatasetValidationResult,
    DatasetValidator,
    getFeatureStatistics,
    validateDatasetSecurity,
)
from trainingModel.validation.modelValidator import (
    ModelValidationError as ArtifactValidationError,
    ModelValidator,
)


# ============================================================================
# Section 1: Schema Reconciliation & Normalization
# ============================================================================

class TestDatasetSchemaReconciliation:
    """Test mapping legacy column aliases and missing feature columns to canonical schema."""

    def test_reconciles_legacy_column_aliases(self):
        """Legacy column names (avgFileEntropy, cpuUsage, memoryUsage) map to canonical names."""
        legacyDf = pd.DataFrame([
            {
                "timestamp": "2026-09-02T16:58:49.621979",
                "fileReadCount": 0,
                "fileWriteCount": 5,
                "fileCreateCount": 1,
                "fileRenameCount": 0,
                "fileDeleteCount": 0,
                "filesModifiedPerMinute": 5.0,
                "avgFileEntropy": 4.5,
                "cpuUsage": 12.5,
                "memoryUsage": 45.0,
                "networkBytes": 1024,
                "label": "Benign",
            }
        ])

        reconciled = reconcileDataset(legacyDf, fillDefaults=True)

        # Canonical column names present
        assert "averageFileEntropy" in reconciled.columns
        assert "processCpuUsage" in reconciled.columns
        assert "processMemoryUsage" in reconciled.columns
        assert reconciled["averageFileEntropy"].iloc[0] == 4.5
        assert reconciled["processCpuUsage"].iloc[0] == 12.5
        assert reconciled["processMemoryUsage"].iloc[0] == 45.0

        # All canonical feature columns present
        for col in featureColumns:
            assert col in reconciled.columns
            assert isinstance(reconciled[col].iloc[0], (float, np.floating))

    def test_populates_missing_canonical_columns_with_defaults(self):
        """Missing feature columns are populated with standard safe defaults (0.0)."""
        sparseDf = pd.DataFrame([
            {
                "averageFileEntropy": 7.8,
                "fileWriteCount": 50.0,
                "label": "Ransomware",
            }
        ])

        reconciled = reconcileDataset(sparseDf, fillDefaults=True)
        assert len(reconciled.columns) >= len(featureColumns) + 1  # features + label
        assert reconciled["extensionChangeCount"].iloc[0] == 0.0
        assert reconciled["processLifetime"].iloc[0] == 0.0
        assert reconciled["fileWriteCount"].iloc[0] == 50.0

    def test_reconcile_dataset_file_roundtrip(self):
        """reconcileDatasetFile reads CSV, normalizes schema, and writes clean output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inputCsv = Path(tmpdir) / "raw_legacy.csv"
            outputCsv = Path(tmpdir) / "clean_canonical.csv"

            legacyDf = pd.DataFrame([
                {
                    "timestamp": "2026-09-02T16:58:49.000",
                    "fileWriteCount": 10,
                    "avgFileEntropy": 6.5,
                    "cpuUsage": 25.0,
                    "memoryUsage": 55.0,
                    "label": "Benign",
                },
                {
                    "timestamp": "2026-09-02T16:58:50.000",
                    "fileWriteCount": 150,
                    "avgFileEntropy": 7.9,
                    "cpuUsage": 85.0,
                    "memoryUsage": 70.0,
                    "label": "Ransomware",
                },
            ])
            legacyDf.to_csv(inputCsv, index=False)

            reconciled = reconcileDatasetFile(inputCsv, outputCsv)
            assert outputCsv.is_file()
            assert len(reconciled) == 2
            assert "averageFileEntropy" in reconciled.columns
            assert "label" in reconciled.columns


# ============================================================================
# Section 2: Synthetic Malicious & Balanced Dataset Generation
# ============================================================================

class TestSyntheticDatasetGeneration:
    """Test generation of balanced, diverse synthetic ransomware and benign datasets."""

    def test_generates_balanced_dataset(self):
        """generateSyntheticDataset produces exact requested count and 50/50 balance."""
        df = generateSyntheticDataset(sampleCount=100, maliciousRatio=0.5, seed=123)
        assert len(df) == 100
        labels = df["label"].value_counts().to_dict()
        assert labels.get("Benign") == 50
        assert labels.get("Ransomware") == 50

    def test_samples_respect_physical_domain_bounds(self):
        """All generated features strictly respect physical constraints (entropy <= 8.0, non-negative)."""
        df = generateSyntheticDataset(sampleCount=150, seed=42)
        for col in featureColumns:
            assert (df[col] >= 0.0).all(), f"Negative values found in {col}"
        assert (df["averageFileEntropy"] <= 8.0).all()
        assert (df["processCpuUsage"] <= 1000.0).all()

    def test_attack_profiles_exhibit_ransomware_characteristics(self):
        """Ransomware profiles have significantly higher write velocity, entropy, and renames than benign."""
        df = generateSyntheticDataset(sampleCount=200, maliciousRatio=0.5, seed=99)
        benign = df[df["label"] == "Benign"]
        ransomware = df[df["label"] == "Ransomware"]

        assert ransomware["averageFileEntropy"].mean() > benign["averageFileEntropy"].mean()
        assert ransomware["fileWriteCount"].mean() > benign["fileWriteCount"].mean()
        assert ransomware["extensionChangeCount"].mean() > benign["extensionChangeCount"].mean()
        assert ransomware["averageFileEntropy"].mean() > 7.3

    def test_deterministic_generation_with_seed(self):
        """Same random seed generates identical dataset DataFrames."""
        df1 = generateSyntheticDataset(sampleCount=50, seed=42)
        df2 = generateSyntheticDataset(sampleCount=50, seed=42)
        pd.testing.assert_frame_equal(df1, df2)

    def test_generate_and_save_dataset_file(self):
        """generateAndSaveDataset writes valid CSV to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csvPath = Path(tmpdir) / "synthetic.csv"
            df = generateAndSaveDataset(csvPath, sampleCount=60, seed=7)
            assert csvPath.is_file()
            loaded = pd.read_csv(csvPath)
            assert len(loaded) == 60
            assert set(featureColumns).issubset(set(loaded.columns))


# ============================================================================
# Section 3: Dataset Security & Quality Validation
# ============================================================================

class TestDatasetSecurityValidation:
    """Test dataset security guards, poisoning detection, and statistical profiling."""

    def test_valid_balanced_dataset_passes_validation(self):
        """A clean balanced synthetic dataset passes validation with status PASSED."""
        df = generateSyntheticDataset(sampleCount=100, maliciousRatio=0.5, seed=42)
        result = validateDatasetSecurity(df, strict=True)
        assert result.isValid is True
        assert result.status == "PASSED"
        assert len(result.errors) == 0

    def test_single_class_dataset_fails_validation(self):
        """Single-class dataset (e.g. 100% Benign) is rejected with clear error."""
        df = generateSyntheticDataset(sampleCount=50, seed=42)
        df["label"] = "Benign"  # Force single class

        validator = DatasetValidator()
        result = validator.validate(df, strict=False)
        assert result.isValid is False
        assert result.status == "REJECTED"
        assert any("only 1 class" in err for err in result.errors)

        with pytest.raises(DatasetValidationError):
            validator.validate(df, strict=True)

    def test_out_of_bounds_entropy_rejected(self):
        """Entropy > 8.0 bits/byte is physically impossible and rejected as poisoning."""
        df = generateSyntheticDataset(sampleCount=50, seed=42)
        df.loc[0, "averageFileEntropy"] = 9.5  # Impossible entropy

        validator = DatasetValidator()
        result = validator.validate(df, strict=False)
        assert result.isValid is False
        assert any("averageFileEntropy" in err and "physical maximum" in err for err in result.errors)

    def test_label_flip_attack_conflict_detected(self):
        """Identical feature vectors with conflicting labels trigger label flip detection."""
        df = generateSyntheticDataset(sampleCount=50, seed=42)
        # Duplicate row 0 but flip its label
        flippedRow = df.iloc[0].copy()
        flippedRow["label"] = "Ransomware" if flippedRow["label"] == "Benign" else "Benign"
        df = pd.concat([df, pd.DataFrame([flippedRow])], ignore_index=True)

        validator = DatasetValidator()
        result = validator.validate(df, strict=False)
        assert result.isValid is False
        assert any("contradictory labels" in err or "Label flip" in err for err in result.errors)

    def test_feature_statistics_calculation(self):
        """getFeatureStatistics computes min, max, mean, std, median per feature."""
        df = generateSyntheticDataset(sampleCount=80, seed=42)
        stats = getFeatureStatistics(df)

        for col in featureColumns:
            assert col in stats
            assert "mean" in stats[col]
            assert "std" in stats[col]
            assert "min" in stats[col]
            assert "max" in stats[col]
            assert stats[col]["min"] <= stats[col]["max"]


# ============================================================================
# Section 4: Stratified 5-Fold Cross-Validation & Metric Calculation
# ============================================================================

class TestStratifiedCrossValidation:
    """Test 5-fold stratified cross-validation and comprehensive metric extraction."""

    def test_5_fold_cv_computes_accuracy_f1_and_roc_auc(self):
        """Stratified 5-fold cross validation computes mean/std across folds."""
        df = generateSyntheticDataset(sampleCount=100, maliciousRatio=0.5, seed=42)
        X = df[list(featureColumns)].astype(float)
        y = df["label"].astype(str)

        from sklearn.ensemble import RandomForestClassifier

        cv = runStratifiedCrossValidation(
            X=X,
            y=y,
            estimatorFactory=lambda: RandomForestClassifier(n_estimators=30, random_state=42),
            cvFolds=5,
            seed=42,
        )

        assert cv["folds"] == 5
        assert cv["meanAccuracy"] >= 0.95
        assert cv["meanF1"] >= 0.95
        assert cv["meanRocAuc"] is not None and cv["meanRocAuc"] >= 0.95
        assert cv["meanFalsePositiveRate"] <= 0.05
        assert cv["meanFalseNegativeRate"] <= 0.05
        assert len(cv["foldMetrics"]) == 5

    def test_calculate_metrics_returns_full_evaluation_dict(self):
        """calculateMetrics computes accuracy, precision, recall, f1, fpr, fnr, and confusion matrix."""
        actual = pd.Series(["Benign", "Benign", "Ransomware", "Ransomware"])
        predicted = pd.Series(["Benign", "Ransomware", "Ransomware", "Ransomware"])
        probas = np.array([[0.9, 0.1], [0.4, 0.6], [0.1, 0.9], [0.05, 0.95]])
        classes = ["Benign", "Ransomware"]

        metrics = calculateMetrics(actual, predicted, probabilities=probas, classes=classes)
        assert metrics["accuracy"] == 0.75
        assert metrics["falsePositiveRate"] == 0.5  # 1 FP out of 2 Benign
        assert metrics["falseNegativeRate"] == 0.0  # 0 FN out of 2 Ransomware
        assert metrics["rocAuc"] is not None
        assert len(metrics["confusionMatrix"]) == 2


# ============================================================================
# Section 5: Hyperparameter Tuning & Feature Scaling
# ============================================================================

class TestHyperparameterTuningAndScaling:
    """Test GridSearchCV parameter exploration, StandardScaler pipelines, and feature importances."""

    def test_tune_hyperparameters_finds_best_estimator(self):
        """tuneHyperparameters searches grid and returns optimized estimator and summary."""
        df = generateSyntheticDataset(sampleCount=60, seed=42)
        X = df[list(featureColumns)].astype(float)
        y = df["label"].astype(str)

        paramGrid = {
            "n_estimators": [10, 20],
            "max_depth": [3, 5],
        }
        bestModel, summary = tuneHyperparameters(
            X, y, paramGrid=paramGrid, cvFolds=3, seed=42, useScaler=False
        )

        assert bestModel is not None
        assert "bestParams" in summary
        assert "bestScore" in summary
        assert summary["bestParams"]["n_estimators"] in [10, 20]
        assert summary["bestScore"] > 0.8

    def test_feature_scaling_pipeline_integration(self):
        """Model trained with useScaler=True wraps StandardScaler and RandomForestClassifier."""
        with tempfile.TemporaryDirectory() as tmpdir:
            modelPath = Path(tmpdir) / "scaled_model.joblib"
            df = generateSyntheticDataset(sampleCount=60, seed=42)

            metadata = trainModel(
                dataset=df,
                modelPath=modelPath,
                useScaler=True,
                cvFolds=3,
            )

            assert modelPath.is_file()
            assert metadata["useScaler"] is True

            # Verify that predictor loads and executes scaled pipeline transparently
            predictor = ModelPredictor(modelPath)
            sampleInput = {col: 1.0 for col in featureColumns}
            proba = predictor.predictProbability(sampleInput)
            assert 0.0 <= proba <= 1.0

    def test_extract_feature_importances_ranks_features(self):
        """Feature importances are extracted and ordered descending."""
        df = generateSyntheticDataset(sampleCount=80, seed=42)
        X = df[list(featureColumns)].astype(float)
        y = df["label"].astype(str)

        from sklearn.ensemble import RandomForestClassifier

        clf = RandomForestClassifier(n_estimators=30, random_state=42)
        clf.fit(X, y)

        importances = extractFeatureImportances(clf)
        assert len(importances) == len(featureColumns)
        values = list(importances.values())
        # Check sorted descending
        assert values == sorted(values, reverse=True)


# ============================================================================
# Section 6: Model Validator
# ============================================================================

class TestModelValidatorEngine:
    """Test comprehensive model artifact verification."""

    def test_validates_clean_unencrypted_model(self):
        """ModelValidator accepts a valid unencrypted model artifact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            modelPath = Path(tmpdir) / "valid_model.joblib"
            df = generateSyntheticDataset(sampleCount=50, seed=42)
            trainModel(df, modelPath, encrypt=False)

            validator = ModelValidator()
            result = validator.validateArtifact(modelPath, strict=True)
            assert result.isValid is True
            assert result.status == "PASSED"
            assert result.averageLatencyMs < 20.0
            assert "Ransomware" in result.classes or "ransomware" in [c.lower() for c in result.classes]

    def test_validates_encrypted_model(self):
        """ModelValidator accepts and validates an AES-256-GCM encrypted artifact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            modelPath = Path(tmpdir) / "encrypted_model.joblib"
            df = generateSyntheticDataset(sampleCount=50, seed=42)
            trainModel(df, modelPath, encrypt=True)

            validator = ModelValidator()
            result = validator.validateArtifact(modelPath, strict=True)
            assert result.isValid is True
            assert result.isEncrypted is True

    def test_rejects_tampered_model(self):
        """ModelValidator rejects tampered encrypted models."""
        with tempfile.TemporaryDirectory() as tmpdir:
            modelPath = Path(tmpdir) / "tampered.joblib"
            df = generateSyntheticDataset(sampleCount=50, seed=42)
            trainModel(df, modelPath, encrypt=True)

            # Corrupt byte payload
            data = bytearray(modelPath.read_bytes())
            data[50] ^= 0xFF
            modelPath.write_bytes(bytes(data))

            validator = ModelValidator()
            result = validator.validateArtifact(modelPath, strict=False)
            assert result.isValid is False
            assert any("tamper" in err.lower() or "integrity" in err.lower() for err in result.errors)


# ============================================================================
# Section 7: Enhanced Predictor & Explainability
# ============================================================================

class TestModelPredictorExplainability:
    """Test predictor explainability, feature contributions, and end-to-end inference."""

    def test_predictor_provides_feature_importances(self):
        """predictor.getFeatureImportances() returns feature importance mapping."""
        with tempfile.TemporaryDirectory() as tmpdir:
            modelPath = Path(tmpdir) / "model.joblib"
            df = generateSyntheticDataset(sampleCount=60, seed=42)
            trainModel(df, modelPath)

            predictor = ModelPredictor(modelPath)
            importances = predictor.getFeatureImportances()
            assert len(importances) == len(featureColumns)
            assert sum(importances.values()) == pytest.approx(1.0, 0.05)

    def test_explain_prediction_identifies_top_drivers(self):
        """explainPrediction returns probability and sorted risk-contributing features."""
        with tempfile.TemporaryDirectory() as tmpdir:
            modelPath = Path(tmpdir) / "model.joblib"
            df = generateSyntheticDataset(sampleCount=80, seed=42)
            trainModel(df, modelPath)

            predictor = ModelPredictor(modelPath)
            # High-risk malicious vector
            maliciousSample = {
                "fileReadCount": 100.0,
                "fileWriteCount": 250.0,
                "fileCreateCount": 30.0,
                "fileRenameCount": 80.0,
                "fileDeleteCount": 10.0,
                "filesModifiedPerMinute": 250.0,
                "uniqueDirectoriesModified": 15.0,
                "uniqueExtensionsModified": 10.0,
                "extensionChangeCount": 80.0,
                "averageFileEntropy": 7.9,
                "entropyChangeRate": 4.5,
                "processCpuUsage": 80.0,
                "processMemoryUsage": 65.0,
                "processLifetime": 15.0,
                "networkBytes": 50000.0,
                "networkConnectionCount": 5.0,
            }

            prob, explanation = predictor.predictWithExplanation(maliciousSample, topN=3)
            assert prob > 0.8
            assert explanation["threatClassification"] == "ransomwareLike"
            assert len(explanation["topContributingFeatures"]) == 3
            assert "feature" in explanation["topContributingFeatures"][0]

    def test_end_to_end_training_and_prediction_workflow(self):
        """End-to-end workflow: load dataset -> train with CV & scaling -> predict with explanation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csvPath = Path(tmpdir) / "dataset.csv"
            modelPath = Path(tmpdir) / "prod_model.joblib"

            # 1. Generate dataset
            generateAndSaveDataset(csvPath, sampleCount=100, maliciousRatio=0.5, seed=42)

            # 2. Train workflow
            dataset = loadDataset(str(csvPath))
            metadata = runTrainingWorkflow(
                dataset=dataset,
                modelPath=str(modelPath),
                cvFolds=5,
                tune=False,
                useScaler=True,
            )
            assert metadata["crossValidation"]["folds"] == 5
            assert metadata["crossValidation"]["meanF1"] >= 0.90

            # 3. Predict & explain
            predictor = ModelPredictor(modelPath)
            benignSample = {col: 0.0 for col in featureColumns}
            prob = predictor.predictProbability(benignSample)
            assert prob < 0.3


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
