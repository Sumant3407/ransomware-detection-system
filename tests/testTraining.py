import tempfile
import unittest
from pathlib import Path

import pandas as pd

from app.domain.schemas import featureColumns
from app.detection.predictor import ModelPredictor
from trainingModel.training.trainModel import trainModel
from trainingModel.unlearning.unlearnModel import forgetLabel


class TrainingTests(unittest.TestCase):
    def createDataset(self):
        rows = []
        for index in range(20):
            rows.append({**{column: float(index + offset) for offset, column in enumerate(featureColumns)}, "label": "Benign" if index < 10 else "Ransomware"})
        return pd.DataFrame(rows)

    def testTrainingWritesValidatedArtifactAndMetadata(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            modelPath = Path(temporaryDirectory) / "model.joblib"
            metadata = trainModel(self.createDataset(), modelPath)
            self.assertTrue(modelPath.is_file())
            self.assertEqual(metadata["featureSchemaVersion"], "1.0")
            self.assertIn("f1", metadata["metrics"])

    def testUnlearningRemovesOnlyRequestedLabel(self):
        remainingData = forgetLabel(self.createDataset(), "Ransomware")
        self.assertEqual(set(remainingData["label"]), {"Benign"})
        self.assertEqual(len(remainingData), 10)

    def testPredictorUsesMaliciousProbability(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            modelPath = Path(temporaryDirectory) / "model.joblib"
            trainModel(self.createDataset(), modelPath)
            predictor = ModelPredictor(modelPath)
            probability = predictor.predictProbability(
                {column: 1.0 for column in featureColumns}
            )
            self.assertGreaterEqual(probability, 0.0)
            self.assertLessEqual(probability, 1.0)


if __name__ == "__main__":
    unittest.main()
