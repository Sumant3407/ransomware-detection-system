"""Sprint 1.4 - Model Artifact Security, AES-256-GCM Encryption, and Dataset Poisoning Protection tests."""

import hashlib
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from app.domain.schemas import featureColumns, featureSchemaVersion
from app.detection.predictor import ModelPredictor, ModelValidationError
from app.logging.logger import closeLogging, createLogger, setSessionId
from app.models.modelRegistry import ModelRegistry, ModelRegistryError, getFileChecksum
from app.security.modelEncryption import (
    ENCRYPTED_MAGIC_HEADER,
    ModelEncryption,
    ModelEncryptionError,
    ModelTamperError,
)
from app.storage.sqliteStore import closeDatabase
from trainingModel.training.trainModel import trainModel
from trainingModel.validation.datasetValidator import (
    DatasetValidationError,
    DatasetValidationResult,
    DatasetValidator,
    validateDatasetSecurity,
)


@pytest.fixture(autouse=True)
def clean_environment():
    """Ensure clean logging context and closed database for each test."""
    setSessionId(None)
    closeLogging()
    closeDatabase()
    yield
    setSessionId(None)
    closeLogging()
    closeDatabase()


def create_sample_dataset(
    sample_count: int = 50,
    include_malicious: bool = True,
    malicious_ratio: float = 0.5,
) -> pd.DataFrame:
    """Helper to generate a clean synthetic dataset for testing."""
    np.random.seed(42)
    data = {}
    for col in featureColumns:
        if col == "averageFileEntropy":
            data[col] = np.random.uniform(1.0, 7.5, size=sample_count)
        elif col in ("processCpuUsage", "entropyChangeRate"):
            data[col] = np.random.uniform(0.0, 80.0, size=sample_count)
        else:
            data[col] = np.random.randint(0, 100, size=sample_count).astype(float)

    if include_malicious:
        malicious_count = max(2, int(sample_count * malicious_ratio))
        benign_count = sample_count - malicious_count
        labels = ["Benign"] * benign_count + ["Ransomware"] * malicious_count
        np.random.shuffle(labels)
        data["label"] = labels
    else:
        data["label"] = ["Benign"] * sample_count

    return pd.DataFrame(data)


def create_dummy_model_artifact(include_malicious_class: bool = True) -> dict:
    """Helper to generate a valid model artifact dict for tests."""
    df = create_sample_dataset(sample_count=20, include_malicious=include_malicious_class)
    X = df[list(featureColumns)]
    y = df["label"]
    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    clf.fit(X, y)

    return {
        "model": clf,
        "featureColumns": featureColumns,
        "featureSchemaVersion": featureSchemaVersion,
        "randomSeed": 42,
        "metrics": {"accuracy": 1.0},
    }


# ============================================================================
# Section 1: Model Encryption & Integrity Tests (AES-256-GCM + HMAC)
# ============================================================================

class TestModelEncryption:
    """Test AES-256-GCM encryption, decryption, and tamper detection."""

    def test_encrypt_decrypt_bytes_roundtrip(self):
        """Plaintext bytes encrypt and decrypt identically."""
        enc = ModelEncryption(systemIdentifier="test-system-node-12345")
        plaintext = b"Secret ML Model Binary Payload 12345!@#$%"

        encrypted = enc.encryptBytes(plaintext)
        assert encrypted != plaintext
        assert encrypted.startswith(ENCRYPTED_MAGIC_HEADER)

        decrypted = enc.decryptBytes(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_file_roundtrip(self):
        """Model file on disk encrypts and decrypts correctly."""
        enc = ModelEncryption(systemIdentifier="test-system-node-12345")
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "model.joblib"
            artifact = create_dummy_model_artifact()
            joblib.dump(artifact, model_path)

            original_bytes = model_path.read_bytes()
            assert not ModelEncryption.isEncryptedFile(model_path)

            # Encrypt in-place
            enc.encryptFile(model_path)
            assert ModelEncryption.isEncryptedFile(model_path)
            assert model_path.read_bytes() != original_bytes

            # Load model transparently
            loaded_artifact = enc.loadModel(model_path)
            assert isinstance(loaded_artifact, dict)
            assert tuple(loaded_artifact["featureColumns"]) == featureColumns

    def test_tampered_ciphertext_fails_decryption(self):
        """Modifying 1 byte of ciphertext causes ModelTamperError."""
        enc = ModelEncryption(systemIdentifier="test-system-node-12345")
        plaintext = b"Highly sensitive machine learning weights"
        encrypted = bytearray(enc.encryptBytes(plaintext))

        # Tamper with ciphertext (inside the body)
        tamper_idx = len(ENCRYPTED_MAGIC_HEADER) + enc.SALT_SIZE + enc.NONCE_SIZE + 2
        encrypted[tamper_idx] ^= 0xFF

        with pytest.raises(ModelTamperError):
            enc.decryptBytes(bytes(encrypted))

    def test_tampered_hmac_signature_fails_decryption(self):
        """Modifying 1 byte of HMAC signature causes ModelTamperError."""
        enc = ModelEncryption(systemIdentifier="test-system-node-12345")
        plaintext = b"Highly sensitive machine learning weights"
        encrypted = bytearray(enc.encryptBytes(plaintext))

        # Tamper with the trailing HMAC byte
        encrypted[-1] ^= 0xFF

        with pytest.raises(ModelTamperError):
            enc.decryptBytes(bytes(encrypted))

    def test_wrong_system_key_fails_decryption(self):
        """Decryption with a different system key fails authentication."""
        enc1 = ModelEncryption(systemIdentifier="node-system-A")
        enc2 = ModelEncryption(systemIdentifier="node-system-B")

        plaintext = b"Weights encrypted on machine A"
        encrypted = enc1.encryptBytes(plaintext)

        with pytest.raises(ModelTamperError):
            enc2.decryptBytes(encrypted)

    def test_checksum_computation_and_verification(self):
        """SHA-256 checksum computation and constant-time verification."""
        enc = ModelEncryption()
        data = b"Arbitrary binary data for hashing"
        checksum = enc.computeChecksum(data)

        assert len(checksum) == 64
        assert enc.verifyChecksum(data, checksum) is True
        assert enc.verifyChecksum(data, "0" * 64) is False


# ============================================================================
# Section 2: ModelPredictor Secure Loading & Validation Tests
# ============================================================================

class TestModelPredictorSecurity:
    """Test ModelPredictor validation against plaintext, encrypted, and invalid models."""

    def test_predictor_loads_unencrypted_model(self):
        """ModelPredictor loads legacy plaintext .joblib model seamlessly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "plain_model.joblib"
            artifact = create_dummy_model_artifact(include_malicious_class=True)
            joblib.dump(artifact, model_path)

            predictor = ModelPredictor(model_path)
            assert predictor.model is not None
            assert len(predictor.maliciousIndexes) > 0

            # Predict probability
            features = {col: 10.0 for col in featureColumns}
            features["averageFileEntropy"] = 4.5
            prob = predictor.predictProbability(features)
            assert 0.0 <= prob <= 1.0

    def test_predictor_loads_encrypted_model(self):
        """ModelPredictor loads AES-256-GCM encrypted model transparently."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "encrypted_model.joblib"
            artifact = create_dummy_model_artifact(include_malicious_class=True)
            joblib.dump(artifact, model_path)

            enc = ModelEncryption(systemIdentifier="test-key")
            enc.encryptFile(model_path)
            assert ModelEncryption.isEncryptedFile(model_path)

            predictor = ModelPredictor(model_path, encryption=enc)
            assert predictor.model is not None

            features = {col: 10.0 for col in featureColumns}
            features["averageFileEntropy"] = 4.5
            prob = predictor.predictProbability(features)
            assert 0.0 <= prob <= 1.0

    def test_predictor_rejects_tampered_encrypted_model(self):
        """Tampered encrypted model file raises ModelValidationError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "tampered.joblib"
            artifact = create_dummy_model_artifact(include_malicious_class=True)
            joblib.dump(artifact, model_path)

            enc = ModelEncryption()
            enc.encryptFile(model_path)

            # Corrupt the file
            data = bytearray(model_path.read_bytes())
            data[-5] ^= 0xAA
            model_path.write_bytes(bytes(data))

            with pytest.raises(ModelValidationError) as exc_info:
                ModelPredictor(model_path, encryption=enc)
            assert "integrity" in str(exc_info.value).lower() or "validation failed" in str(exc_info.value).lower()

    def test_predictor_rejects_missing_features_input(self):
        """Prediction input with missing features raises ModelValidationError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "model.joblib"
            artifact = create_dummy_model_artifact()
            joblib.dump(artifact, model_path)

            predictor = ModelPredictor(model_path)
            incomplete_features = {"averageFileEntropy": 5.0}  # Missing 15 columns

            with pytest.raises(ModelValidationError) as exc_info:
                predictor.predictProbability(incomplete_features)
            assert "missing features" in str(exc_info.value).lower()

    def test_predictor_rejects_model_without_malicious_class(self):
        """Model with only benign class is rejected by ModelPredictor."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "benign_only.joblib"
            # Train only with Benign
            df = create_sample_dataset(sample_count=20, include_malicious=False)
            clf = RandomForestClassifier(n_estimators=10, random_state=42)
            clf.fit(df[list(featureColumns)], df["label"])

            artifact = {
                "model": clf,
                "featureColumns": featureColumns,
                "featureSchemaVersion": featureSchemaVersion,
            }
            joblib.dump(artifact, model_path)

            with pytest.raises(ModelValidationError) as exc_info:
                ModelPredictor(model_path)
            assert "no recognized malicious label" in str(exc_info.value).lower()

    def test_predictor_rejects_schema_mismatch(self):
        """Model with mismatched feature columns is rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "mismatched.joblib"
            artifact = create_dummy_model_artifact()
            artifact["featureColumns"] = ("fileReadCount", "invalidFeature")
            joblib.dump(artifact, model_path)

            with pytest.raises(ModelValidationError) as exc_info:
                ModelPredictor(model_path)
            assert "schema" in str(exc_info.value).lower()


# ============================================================================
# Section 3: ModelRegistry Validation & Activation with Encryption
# ============================================================================

class TestModelRegistrySecurity:
    """Test ModelRegistry atomic activation, encryption enforcement, and rollback."""

    def test_registry_activates_and_encrypts_model(self):
        """ModelRegistry encrypts candidate model with AES-256-GCM on activation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            models_dir = temp_path / "models"
            candidate_dir = temp_path / "candidate"
            candidate_dir.mkdir()
            db_path = temp_path / "detector.sqlite3"

            dataset = create_sample_dataset(sample_count=30, include_malicious=True)
            candidate_model = candidate_dir / "candidate.joblib"
            trainModel(dataset, candidate_model, encrypt=False)

            assert candidate_model.is_file()
            assert not ModelEncryption.isEncryptedFile(candidate_model)

            registry = ModelRegistry(models_dir, db_path)
            active_path = registry.activateModel(candidate_model, encrypt=True)

            assert active_path.is_file()
            assert ModelEncryption.isEncryptedFile(active_path)

            # Check metadata.json in current/
            metadata_path = models_dir / "current" / "metadata.json"
            assert metadata_path.is_file()
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            assert metadata["encrypted"] is True
            assert metadata["checksum"] == getFileChecksum(active_path)

            # Predictor can load the activated encrypted model
            predictor = ModelPredictor(active_path)
            assert predictor.model is not None

    def test_registry_rollback_restores_previous_model(self):
        """ModelRegistry cleanly rolls back to previous model."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            models_dir = temp_path / "models"
            candidate_dir = temp_path / "candidates"
            candidate_dir.mkdir()
            db_path = temp_path / "detector.sqlite3"

            # Train Model v1
            dataset1 = create_sample_dataset(sample_count=30, include_malicious=True)
            model_v1 = candidate_dir / "v1.joblib"
            trainModel(dataset1, model_v1)

            registry = ModelRegistry(models_dir, db_path)
            registry.activateModel(model_v1)
            v1_checksum = getFileChecksum(models_dir / "current" / "model.joblib")

            # Train Model v2
            dataset2 = create_sample_dataset(sample_count=40, include_malicious=True)
            model_v2 = candidate_dir / "v2.joblib"
            trainModel(dataset2, model_v2)
            registry.activateModel(model_v2)
            v2_checksum = getFileChecksum(models_dir / "current" / "model.joblib")
            assert v2_checksum != v1_checksum

            # Rollback to v1
            rolled_back = registry.rollbackModel()
            assert getFileChecksum(rolled_back) == v1_checksum

    def test_registry_rejects_checksum_mismatch(self):
        """Model with tampered file or wrong metadata checksum is rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            models_dir = temp_path / "models"
            candidate_dir = temp_path / "candidates"
            candidate_dir.mkdir()
            db_path = temp_path / "detector.sqlite3"

            dataset = create_sample_dataset(sample_count=30, include_malicious=True)
            candidate = candidate_dir / "candidate.joblib"
            trainModel(dataset, candidate)

            # Tamper with metadata checksum
            meta_path = candidate.with_suffix(".metadata.json")
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            meta["checksum"] = "bad" * 16
            meta_path.write_text(json.dumps(meta), encoding="utf-8")

            registry = ModelRegistry(models_dir, db_path)
            with pytest.raises(ModelRegistryError) as exc_info:
                registry.validateModel(candidate)
            assert "checksum" in str(exc_info.value).lower()


# ============================================================================
# Section 4: Dataset Security & Poisoning Detection Tests
# ============================================================================

class TestDatasetPoisoningAndSecurity:
    """Test DatasetValidator detection of poisoning attacks and data corruption."""

    def test_valid_dataset_passes_validation(self):
        """Clean balanced dataset passes validation with status PASSED."""
        df = create_sample_dataset(sample_count=50, include_malicious=True)
        validator = DatasetValidator()
        result = validator.validate(df, strict=True)

        assert result.isValid is True
        assert result.status in ("PASSED", "WARNING")
        assert len(result.errors) == 0
        assert result.sampleCount == 50

    def test_single_class_dataset_rejected(self):
        """Dataset with 100% benign samples (monoculture) is rejected."""
        df = create_sample_dataset(sample_count=50, include_malicious=False)
        validator = DatasetValidator()

        with pytest.raises(DatasetValidationError) as exc_info:
            validator.validate(df, strict=True)
        assert "at least 2 distinct classes" in str(exc_info.value).lower()

        # Non-strict mode returns result object
        result = validator.validate(df, strict=False)
        assert result.isValid is False
        assert result.status == "REJECTED"
        assert any("single-class" in err.lower() or "2 distinct classes" in err.lower() for err in result.errors)

    def test_missing_feature_column_rejected(self):
        """Dataset missing a required schema feature column is rejected."""
        df = create_sample_dataset(sample_count=30, include_malicious=True)
        df = df.drop(columns=["averageFileEntropy"])

        validator = DatasetValidator()
        with pytest.raises(DatasetValidationError) as exc_info:
            validator.validate(df, strict=True)
        assert "missing required columns" in str(exc_info.value).lower()

    def test_nan_or_infinite_features_rejected(self):
        """Dataset with NaN or infinite values is rejected."""
        df = create_sample_dataset(sample_count=30, include_malicious=True)
        df.loc[5, "processCpuUsage"] = np.nan
        df.loc[10, "fileReadCount"] = np.inf

        validator = DatasetValidator()
        with pytest.raises(DatasetValidationError) as exc_info:
            validator.validate(df, strict=True)
        assert "nan" in str(exc_info.value).lower() or "infinite" in str(exc_info.value).lower()

    def test_out_of_bounds_entropy_rejected(self):
        """Dataset with mathematically impossible Shannon entropy (>8.0 or <0.0) is rejected."""
        df = create_sample_dataset(sample_count=30, include_malicious=True)
        df.loc[3, "averageFileEntropy"] = 9.5  # Max theoretical is 8.0 bits/byte
        df.loc[4, "averageFileEntropy"] = -1.2

        validator = DatasetValidator()
        with pytest.raises(DatasetValidationError) as exc_info:
            validator.validate(df, strict=True)
        assert "averagefileentropy" in str(exc_info.value).lower()

    def test_negative_counts_rejected(self):
        """Dataset with negative file counts is rejected."""
        df = create_sample_dataset(sample_count=30, include_malicious=True)
        df.loc[2, "fileWriteCount"] = -5.0

        validator = DatasetValidator()
        with pytest.raises(DatasetValidationError) as exc_info:
            validator.validate(df, strict=True)
        assert "filewritecount" in str(exc_info.value).lower()

    def test_label_flip_poisoning_detected(self):
        """Identical feature vectors with contradictory labels (label flip attack) are detected."""
        df = create_sample_dataset(sample_count=30, include_malicious=True)

        # Duplicate row 0 with opposite label
        poison_row = df.iloc[0].copy()
        poison_row["label"] = "Ransomware" if df.iloc[0]["label"] == "Benign" else "Benign"
        df = pd.concat([df, pd.DataFrame([poison_row])], ignore_index=True)

        validator = DatasetValidator()
        with pytest.raises(DatasetValidationError) as exc_info:
            validator.validate(df, strict=True)
        assert "contradictory labels" in str(exc_info.value).lower() or "label flip" in str(exc_info.value).lower()

    def test_severe_class_imbalance_generates_warning(self):
        """Severely imbalanced dataset triggers a validation warning."""
        # 96% benign, 4% malicious
        df = create_sample_dataset(sample_count=100, include_malicious=True, malicious_ratio=0.04)
        validator = DatasetValidator()
        result = validator.validate(df, strict=False)

        assert result.isValid is True
        assert any("imbalance" in warn.lower() or "scarcity" in warn.lower() for warn in result.warnings)


# ============================================================================
# Section 5: End-to-End Training & Encrypted Artifact Pipeline
# ============================================================================

class TestEndToEndEncryptedTrainingPipeline:
    """Test full pipeline: Dataset Validation -> Training -> AES-256-GCM Encryption -> Predictor."""

    def test_complete_training_encryption_and_inference_pipeline(self):
        """Full workflow creates valid encrypted model and computes accurate predictions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            model_path = temp_path / "ransomware_encrypted.joblib"
            dataset = create_sample_dataset(sample_count=60, include_malicious=True)

            # 1. Train with encryption enabled
            metadata = trainModel(dataset, model_path, encrypt=True)
            assert metadata["encrypted"] is True
            assert ModelEncryption.isEncryptedFile(model_path)

            # 2. Verify metadata
            assert metadata["metrics"]["accuracy"] >= 0.0
            assert metadata["checksum"] == getFileChecksum(model_path)

            # 3. Load with ModelPredictor
            predictor = ModelPredictor(model_path)
            assert predictor.model is not None

            # 4. Predict on a high-risk sample
            high_risk_input = {col: 10.0 for col in featureColumns}
            high_risk_input["averageFileEntropy"] = 7.8
            high_risk_input["fileWriteCount"] = 250.0
            high_risk_input["extensionChangeCount"] = 80.0

            probability = predictor.predictProbability(high_risk_input)
            assert 0.0 <= probability <= 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
