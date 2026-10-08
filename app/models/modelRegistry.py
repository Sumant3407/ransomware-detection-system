"""Validated model registry and atomic activation with encryption and structured logging."""

import hashlib
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.detection.predictor import ModelPredictor, ModelValidationError
from app.logging.logger import logSecurityEvent
from app.security.modelEncryption import ModelEncryption
from app.storage.sqliteStore import initializeDatabase

logger = logging.getLogger(__name__)


class ModelRegistryError(ValueError):
    """Raised when a model cannot be validated or activated."""


def getFileChecksum(filePath: Path) -> str:
    digest = hashlib.sha256()
    with filePath.open("rb") as modelFile:
        for chunk in iter(lambda: modelFile.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ModelRegistry:
    def __init__(
        self,
        modelsDirectory: Path,
        databasePath: Path,
        encryption: Optional[ModelEncryption] = None,
    ):
        self.modelsDirectory = modelsDirectory.resolve()
        self.databasePath = databasePath
        self.encryption = encryption or ModelEncryption()

    def validateModel(self, modelPath: Path) -> dict:
        modelPath = modelPath.resolve()
        logger.info(f"Validating model candidate: {modelPath}", extra={"event": "model_registry"})

        try:
            ModelPredictor(modelPath, encryption=self.encryption)
        except ModelValidationError as error:
            logger.error(f"Model validation failed: {error}", extra={"event": "model_registry"})
            logSecurityEvent(
                logger,
                action="model_validation",
                target=str(modelPath),
                status="blocked",
                details={"error": str(error)},
            )
            raise ModelRegistryError(str(error)) from error

        metadataPath = self.getMetadataPath(modelPath)
        if not metadataPath.is_file():
            logger.error(f"Model metadata not found at {metadataPath}", extra={"event": "model_registry"})
            raise ModelRegistryError("Model metadata was not found")

        try:
            metadata = json.loads(metadataPath.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            logger.error(f"Model metadata invalid: {error}", extra={"event": "model_registry"})
            raise ModelRegistryError("Model metadata is invalid") from error

        expectedChecksum = metadata.get("checksum")
        actualChecksum = getFileChecksum(modelPath)
        if expectedChecksum and expectedChecksum != actualChecksum:
            # Check if encrypted file has its own recorded encryptedChecksum
            encryptedChecksum = metadata.get("encryptedChecksum")
            if encryptedChecksum != actualChecksum:
                logger.error(
                    f"Model checksum mismatch: expected={expectedChecksum}, actual={actualChecksum}",
                    extra={
                        "event": "model_registry",
                        "context": {"expected": expectedChecksum, "actual": actualChecksum},
                    },
                )
                raise ModelRegistryError("Model checksum does not match metadata")

        logger.info(
            f"Model validation passed: version={metadata.get('modelVersion')}",
            extra={"event": "model_registry"},
        )
        return metadata

    @staticmethod
    def getMetadataPath(modelPath: Path) -> Path:
        uniqueMetadataPath = modelPath.with_suffix(".metadata.json")
        if uniqueMetadataPath.is_file():
            return uniqueMetadataPath
        return modelPath.with_name("metadata.json")

    def activateModel(self, modelPath: Path, encrypt: bool = True) -> Path:
        """
        Activate a model artifact atomically, optionally encrypting with AES-256-GCM.

        Args:
            modelPath: Path to candidate model file
            encrypt: Whether to encrypt the active model artifact with AES-256-GCM

        Returns:
            Path to activated model
        """
        metadata = self.validateModel(modelPath)
        version = str(metadata.get("modelVersion", "unknown"))
        targetDirectory = self.modelsDirectory / "current"
        targetDirectory.mkdir(parents=True, exist_ok=True)
        targetModel = targetDirectory / "model.joblib"
        temporaryModel = targetDirectory / "model.joblib.tmp"
        previousModel = targetDirectory / "previous.joblib"

        if targetModel.is_file():
            shutil.copyfile(targetModel, previousModel)
            logger.debug("Backed up current model to previous.joblib")

        shutil.copyfile(modelPath, temporaryModel)

        # Encrypt the temporary model if requested and not already encrypted
        if encrypt and not ModelEncryption.isEncryptedFile(temporaryModel):
            self.encryption.encryptFile(temporaryModel)
            logger.info("Encrypted model artifact during activation with AES-256-GCM")

        temporaryModel.replace(targetModel)

        # Update metadata for target directory
        targetMetadata = dict(metadata)
        targetMetadata["checksum"] = getFileChecksum(targetModel)
        targetMetadata["encrypted"] = ModelEncryption.isEncryptedFile(targetModel)
        (targetDirectory / "metadata.json").write_text(
            json.dumps(targetMetadata, indent=2), encoding="utf-8"
        )

        connection = initializeDatabase(self.databasePath)
        connection.execute(
            "INSERT OR REPLACE INTO models (version, createdAt, artifactPath, checksum, status) VALUES (?, ?, ?, ?, ?)",
            (
                version,
                datetime.now(timezone.utc).isoformat(),
                str(targetModel),
                targetMetadata["checksum"],
                "active",
            ),
        )
        connection.commit()
        connection.close()

        logger.info(
            f"Model activated: version={version} -> {targetModel} (encrypted={targetMetadata['encrypted']})",
            extra={
                "event": "model_activation",
                "context": {
                    "version": version,
                    "path": str(targetModel),
                    "encrypted": targetMetadata["encrypted"],
                },
            },
        )
        return targetModel

    def rollbackModel(self) -> Path:
        targetDirectory = self.modelsDirectory / "current"
        previousModel = targetDirectory / "previous.joblib"
        if not previousModel.is_file():
            logger.warning("Rollback requested but no previous model exists", extra={"event": "model_rollback"})
            raise ModelRegistryError("No previous model is available for rollback")

        targetModel = targetDirectory / "model.joblib"
        temporaryModel = targetDirectory / "model.joblib.tmp"
        shutil.copyfile(previousModel, temporaryModel)
        temporaryModel.replace(targetModel)

        logger.info(f"Model rolled back successfully to previous version", extra={"event": "model_rollback"})
        return targetModel

    def getActiveModel(self) -> Path:
        """Return the path to the currently active model artifact."""
        return self.modelsDirectory / "current" / "model.joblib"
