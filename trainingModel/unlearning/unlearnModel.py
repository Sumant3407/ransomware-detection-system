"""Exact retraining baseline for measurable machine unlearning."""

from pathlib import Path

import pandas as pd

from trainingModel.training.trainModel import trainModel


def forgetLabel(dataset: pd.DataFrame, label: str) -> pd.DataFrame:
    if "label" not in dataset.columns:
        raise ValueError("Dataset must contain a label column")
    remainingData = dataset[dataset["label"] != label].copy()
    if remainingData.empty:
        raise ValueError("Unlearning would remove every sample")
    return remainingData


def unlearnLabel(
    dataset: pd.DataFrame,
    label: str,
    candidateModelPath: Path,
) -> dict:
    remainingData = forgetLabel(dataset, label)
    return trainModel(remainingData, candidateModelPath)
