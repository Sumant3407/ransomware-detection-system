import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from app.domain.schemas import featureColumns
from app.models.modelRegistry import ModelRegistry, ModelRegistryError, getFileChecksum
from trainingModel.training.trainModel import trainModel


class ModelRegistryTests(unittest.TestCase):
    def createDataset(self):
        return pd.DataFrame([
            {**{column: float(index + offset) for offset, column in enumerate(featureColumns)}, "label": "Benign" if index < 10 else "Ransomware"}
            for index in range(20)
        ])

    def testValidModelCanBeActivated(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            rootPath = Path(temporaryDirectory)
            candidatePath = rootPath / "candidate.joblib"
            trainModel(self.createDataset(), candidatePath)
            metadataPath = candidatePath.with_suffix(".metadata.json")
            metadata = json.loads(metadataPath.read_text(encoding="utf-8"))
            metadata["checksum"] = getFileChecksum(candidatePath)
            metadataPath.write_text(json.dumps(metadata), encoding="utf-8")
            registry = ModelRegistry(rootPath / "models", rootPath / "detector.sqlite3")
            activatedPath = registry.activateModel(candidatePath)
            self.assertTrue(activatedPath.is_file())

    def testTamperedModelIsRejected(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            rootPath = Path(temporaryDirectory)
            candidatePath = rootPath / "candidate.joblib"
            trainModel(self.createDataset(), candidatePath)
            metadataPath = candidatePath.with_suffix(".metadata.json")
            metadata = json.loads(metadataPath.read_text(encoding="utf-8"))
            metadata["checksum"] = getFileChecksum(candidatePath)
            metadataPath.write_text(json.dumps(metadata), encoding="utf-8")
            candidatePath.write_bytes(candidatePath.read_bytes() + b"tampered")
            registry = ModelRegistry(rootPath / "models", rootPath / "detector.sqlite3")
            with self.assertRaises(ModelRegistryError):
                registry.activateModel(candidatePath)

    def testPreviousModelCanBeRolledBack(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            rootPath = Path(temporaryDirectory)
            firstPath = rootPath / "first.joblib"
            secondPath = rootPath / "second.joblib"
            trainModel(self.createDataset(), firstPath)
            firstMetadataPath = firstPath.with_suffix(".metadata.json")
            firstMetadata = json.loads(firstMetadataPath.read_text(encoding="utf-8"))
            firstMetadata["checksum"] = getFileChecksum(firstPath)
            firstMetadataPath.write_text(json.dumps(firstMetadata), encoding="utf-8")
            trainModel(self.createDataset().iloc[::-1], secondPath)
            secondMetadataPath = secondPath.with_suffix(".metadata.json")
            secondMetadata = json.loads(secondMetadataPath.read_text(encoding="utf-8"))
            secondMetadata["checksum"] = getFileChecksum(secondPath)
            secondMetadataPath.write_text(json.dumps(secondMetadata), encoding="utf-8")
            registry = ModelRegistry(rootPath / "models", rootPath / "detector.sqlite3")
            registry.activateModel(firstPath)
            registry.activateModel(secondPath)
            self.assertTrue(registry.rollbackModel().is_file())


if __name__ == "__main__":
    unittest.main()
