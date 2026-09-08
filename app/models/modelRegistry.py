"""Validated model registry and atomic activation."""

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from app.storage.sqliteStore import initializeDatabase
from app.detection.predictor import ModelPredictor, ModelValidationError


class ModelRegistryError(ValueError):
    """Raised when a model cannot be validated or activated."""


def getFileChecksum(filePath: Path) -> str:
    digest = hashlib.sha256()
    with filePath.open("rb") as modelFile:
        for chunk in iter(lambda: modelFile.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ModelRegistry:
    def __init__(self, modelsDirectory: Path, databasePath: Path):
        self.modelsDirectory = modelsDirectory.resolve()
        self.databasePath = databasePath

    def validateModel(self, modelPath: Path) -> dict:
        modelPath = modelPath.resolve()
        try:
            ModelPredictor(modelPath)
        except ModelValidationError as error:
            raise ModelRegistryError(str(error)) from error
        metadataPath = self.getMetadataPath(modelPath)
        if not metadataPath.is_file():
            raise ModelRegistryError("Model metadata was not found")
        try:
            metadata = json.loads(metadataPath.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ModelRegistryError("Model metadata is invalid") from error
        expectedChecksum = metadata.get("checksum")
        actualChecksum = getFileChecksum(modelPath)
        if expectedChecksum != actualChecksum:
            raise ModelRegistryError("Model checksum does not match metadata")
        return metadata

    @staticmethod
    def getMetadataPath(modelPath: Path) -> Path:
        uniqueMetadataPath = modelPath.with_suffix(".metadata.json")
        if uniqueMetadataPath.is_file():
            return uniqueMetadataPath
        return modelPath.with_name("metadata.json")

    def activateModel(self, modelPath: Path) -> Path:
        metadata = self.validateModel(modelPath)
        version = str(metadata.get("modelVersion", "unknown"))
        targetDirectory = self.modelsDirectory / "current"
        targetDirectory.mkdir(parents=True, exist_ok=True)
        targetModel = targetDirectory / "model.joblib"
        temporaryModel = targetDirectory / "model.joblib.tmp"
        previousModel = targetDirectory / "previous.joblib"
        if targetModel.is_file():
            shutil.copyfile(targetModel, previousModel)
        shutil.copyfile(modelPath, temporaryModel)
        temporaryModel.replace(targetModel)
        shutil.copyfile(self.getMetadataPath(modelPath), targetDirectory / "metadata.json")

        connection = initializeDatabase(self.databasePath)
        connection.execute(
            "INSERT OR REPLACE INTO models (version, createdAt, artifactPath, checksum, status) VALUES (?, ?, ?, ?, ?)",
            (version, datetime.now(timezone.utc).isoformat(), str(targetModel), getFileChecksum(targetModel), "active"),
        )
        connection.commit()
        connection.close()
        return targetModel

    def rollbackModel(self) -> Path:
        targetDirectory = self.modelsDirectory / "current"
        previousModel = targetDirectory / "previous.joblib"
        if not previousModel.is_file():
            raise ModelRegistryError("No previous model is available for rollback")
        targetModel = targetDirectory / "model.joblib"
        temporaryModel = targetDirectory / "model.joblib.tmp"
        shutil.copyfile(previousModel, temporaryModel)
        temporaryModel.replace(targetModel)
        return targetModel
