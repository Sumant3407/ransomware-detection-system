"""Load behavior datasets for model training workflows with validation, cross-validation, and encryption."""

import argparse
import sys
from pathlib import Path
from typing import Any, Optional

# Ensure project root is in sys.path
projectRoot = Path(__file__).resolve().parent.parent.parent
if str(projectRoot) not in sys.path:
    sys.path.insert(0, str(projectRoot))

import pandas as pd

from app.config.configuration import getProjectRoot
from app.domain.schemas import featureColumns
from trainingModel.training.trainModel import trainModel as trainValidatedModel
from trainingModel.validation.datasetSchema import reconcileDataset


def loadDataset(datasetPath: str = "data/datasets/ransomwareBehaviorDataset.csv") -> pd.DataFrame:
    """Load the behavior dataset from disk, falling back to project root resolution."""
    resolvedPath = Path(datasetPath)
    if not resolvedPath.is_absolute():
        resolvedPath = getProjectRoot() / resolvedPath

    if not resolvedPath.is_file():
        raise FileNotFoundError(f"Dataset was not found: {resolvedPath}")

    return pd.read_csv(resolvedPath)


def trainModel(
    dataset: pd.DataFrame,
    modelPath: str = "ransomwareModel.joblib",
    encrypt: bool = False,
    cvFolds: int = 5,
    tune: bool = False,
    useScaler: bool = False,
    autoReconcile: bool = True,
) -> dict[str, Any]:
    """Train and save a validated, optionally encrypted classifier from behavior samples."""
    resolvedModelPath = Path(modelPath)
    return trainValidatedModel(
        dataset,
        resolvedModelPath,
        encrypt=encrypt,
        cvFolds=cvFolds,
        tune=tune,
        useScaler=useScaler,
        autoReconcileSchema=autoReconcile,
    )


def getArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a ransomware behavior classifier with cross-validation and tuning."
    )
    parser.add_argument(
        "--datasetPath",
        default="data/datasets/ransomwareBehaviorDataset.csv",
        help="Path to the collected CSV dataset (default: data/datasets/ransomwareBehaviorDataset.csv)",
    )
    parser.add_argument(
        "--modelPath",
        default="ransomwareModel.joblib",
        help="Path where the trained model will be saved (default: ransomwareModel.joblib)",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        default=False,
        help="Encrypt model artifact with AES-256-GCM after training.",
    )
    parser.add_argument(
        "--cvFolds",
        type=int,
        default=5,
        help="Number of Stratified K-Fold cross validation folds (default: 5)",
    )
    parser.add_argument(
        "--tune",
        action="store_true",
        default=False,
        help="Run GridSearchCV hyperparameter optimization.",
    )
    parser.add_argument(
        "--scale",
        action="store_true",
        default=False,
        help="Scale features with StandardScaler in a Pipeline.",
    )
    parser.add_argument(
        "--no-reconcile",
        dest="reconcile",
        action="store_false",
        default=True,
        help="Disable automatic schema reconciliation for legacy datasets.",
    )
    return parser.parse_args()


def main() -> None:
    arguments = getArguments()
    dataset = loadDataset(arguments.datasetPath)
    print("=" * 72)
    print("           RANSOMWARE BEHAVIOR MODEL TRAINING")
    print("=" * 72)
    print(f"Dataset path   : {arguments.datasetPath} ({len(dataset)} samples)")
    print(f"Target model   : {arguments.modelPath}")
    print(f"Cross-val folds: {arguments.cvFolds}")
    print(f"Hyperparam tune: {arguments.tune}")
    print(f"Feature scaling: {arguments.scale}")
    print(f"AES Encryption : {arguments.encrypt}")
    print("-" * 72)

    metadata = trainModel(
        dataset,
        arguments.modelPath,
        encrypt=arguments.encrypt,
        cvFolds=arguments.cvFolds,
        tune=arguments.tune,
        useScaler=arguments.scale,
        autoReconcile=arguments.reconcile,
    )

    cv = metadata.get("crossValidation", {})
    metrics = metadata.get("metrics", {})

    print(f"Cross-Validation Accuracy : {cv.get('meanAccuracy', 0):.4f} +/- {cv.get('stdAccuracy', 0):.4f}")
    print(f"Cross-Validation F1-Score : {cv.get('meanF1', 0):.4f} +/- {cv.get('stdF1', 0):.4f}")
    if cv.get("meanRocAuc") is not None:
        print(f"Cross-Validation ROC-AUC  : {cv.get('meanRocAuc', 0):.4f} +/- {cv.get('stdRocAuc', 0):.4f}")
    print(f"Holdout Test Accuracy     : {metrics.get('accuracy', 0):.4f}")
    print(f"Holdout Test F1-Score     : {metrics.get('f1', 0):.4f}")
    print(f"Trained model saved to    : {arguments.modelPath} (encrypted={metadata.get('encrypted')})")
    print("=" * 72)


if __name__ == "__main__":
    main()
