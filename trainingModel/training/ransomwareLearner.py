"""Load the collected behavior dataset for model training workflows."""

import argparse
from pathlib import Path

import pandas as pd

from app.domain.schemas import featureColumns
from app.config.configuration import getProjectRoot
from trainingModel.training.trainModel import trainModel as trainValidatedModel


def loadDataset(datasetPath="data/ransomwareBehaviorDataset.csv"):
    """Load the collector output using a path relative to this module."""
    resolvedPath = Path(datasetPath)
    if not resolvedPath.is_absolute():
        resolvedPath = getProjectRoot() / resolvedPath

    if not resolvedPath.is_file():
        raise FileNotFoundError(f"Dataset was not found: {resolvedPath}")

    return pd.read_csv(resolvedPath)


def trainModel(dataset, modelPath="ransomwareModel.joblib"):
    """Train and save a classifier from collected behavior samples."""
    resolvedModelPath = Path(modelPath)
    trainValidatedModel(dataset, resolvedModelPath)
    return resolvedModelPath


def getArguments():
    parser = argparse.ArgumentParser(
        description="Train a ransomware behavior classifier."
    )
    parser.add_argument(
        "--datasetPath",
        default="data/ransomwareBehaviorDataset.csv",
        help="Path to the collected CSV dataset.",
    )
    parser.add_argument(
        "--modelPath",
        default="ransomwareModel.joblib",
        help="Path where the trained model will be saved.",
    )
    return parser.parse_args()


def main():
    arguments = getArguments()
    dataset = loadDataset(arguments.datasetPath)
    modelPath = trainModel(dataset, arguments.modelPath)
    print(f"Trained model saved to {modelPath}")


if __name__ == "__main__":
    main()