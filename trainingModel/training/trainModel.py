"""Reproducible model training and evaluation."""

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import pandas as pd
from joblib import dump
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from app.domain.schemas import featureColumns, featureSchemaVersion

randomSeed = 42


def getDatasetFingerprint(dataset: pd.DataFrame) -> str:
    content = dataset.to_csv(index=False).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def validateDataset(dataset: pd.DataFrame) -> None:
    requiredColumns = set(featureColumns) | {"label"}
    missingColumns = sorted(requiredColumns - set(dataset.columns))
    if missingColumns:
        raise ValueError(f"Dataset is missing required columns: {', '.join(missingColumns)}")
    if dataset.empty:
        raise ValueError("Dataset has no samples")
    if dataset["label"].isna().any() or dataset["label"].nunique() < 2:
        raise ValueError("Training requires at least two non-empty labels")
    if dataset.duplicated().any():
        raise ValueError("Dataset contains duplicate samples")
    numericData = dataset[list(featureColumns)].apply(pd.to_numeric, errors="coerce")
    if numericData.isna().any().any():
        raise ValueError("Feature columns contain missing or non-numeric values")
    if not numericData.map(lambda value: float(value)).map(lambda value: pd.notna(value) and pd.api.types.is_number(value)).all().all():
        raise ValueError("Feature columns contain invalid values")
    if dataset["label"].value_counts().min() < 2:
        raise ValueError("Each label requires at least two samples")


def calculateMetrics(actual: pd.Series, predicted: Any) -> dict[str, Any]:
    labels = sorted(set(actual) | set(predicted))
    matrix = confusion_matrix(actual, predicted, labels=labels)
    benignIndexes = [index for index, label in enumerate(labels) if str(label).lower() == "benign"]
    falsePositiveCount = sum(
        matrix[rowIndex, columnIndex]
        for rowIndex in benignIndexes
        for columnIndex in range(len(labels))
        if rowIndex != columnIndex
    )
    benignCount = sum(matrix[index].sum() for index in benignIndexes)
    ransomwareIndexes = [index for index, label in enumerate(labels) if str(label).lower() in {"ransomware", "ransomware_like", "ransomware-like", "malicious"}]
    ransomwareCount = sum(matrix[index].sum() for index in ransomwareIndexes)
    falseNegativeCount = sum(
        matrix[rowIndex, columnIndex]
        for rowIndex in ransomwareIndexes
        for columnIndex in range(len(labels))
        if rowIndex != columnIndex
    )
    return {
        "accuracy": round(accuracy_score(actual, predicted), 6),
        "precision": round(precision_score(actual, predicted, average="weighted", zero_division=0), 6),
        "recall": round(recall_score(actual, predicted, average="weighted", zero_division=0), 6),
        "f1": round(f1_score(actual, predicted, average="weighted", zero_division=0), 6),
        "falsePositiveRate": round(falsePositiveCount / benignCount, 6) if benignCount else 0.0,
        "falseNegativeRate": round(falseNegativeCount / ransomwareCount, 6) if ransomwareCount else 0.0,
        "perClass": classification_report(actual, predicted, output_dict=True, zero_division=0),
    }


def trainModel(dataset: pd.DataFrame, modelPath: Path) -> dict[str, Any]:
    validateDataset(dataset)
    trainingData = dataset[list(featureColumns)].astype(float)
    labels = dataset["label"]
    testSize = max(2, round(len(dataset) * 0.2))
    trainData, testData, trainLabels, testLabels = train_test_split(
        trainingData,
        labels,
        test_size=testSize,
        random_state=randomSeed,
        stratify=labels,
    )
    startedAt = time.perf_counter()
    classifier = RandomForestClassifier(
        n_estimators=100,
        random_state=randomSeed,
        class_weight="balanced",
        n_jobs=-1,
    )
    classifier.fit(trainData, trainLabels)
    trainingSeconds = round(time.perf_counter() - startedAt, 6)
    predictedLabels = classifier.predict(testData)
    metrics = calculateMetrics(testLabels, predictedLabels)
    inferenceStartedAt = time.perf_counter()
    classifier.predict_proba(testData.iloc[:1])
    inferenceMilliseconds = round((time.perf_counter() - inferenceStartedAt) * 1000, 6)
    artifact = {
        "model": classifier,
        "featureColumns": featureColumns,
        "featureSchemaVersion": featureSchemaVersion,
        "randomSeed": randomSeed,
        "metrics": metrics,
    }
    modelPath = Path(modelPath)
    modelPath.parent.mkdir(parents=True, exist_ok=True)
    dump(artifact, modelPath)
    artifactChecksum = hashlib.sha256(modelPath.read_bytes()).hexdigest()
    metadata = {
        "modelVersion": "1.0.0",
        "algorithm": "RandomForestClassifier",
        "featureSchemaVersion": featureSchemaVersion,
        "featureColumns": list(featureColumns),
        "randomSeed": randomSeed,
        "datasetFingerprint": getDatasetFingerprint(dataset),
        "sampleCount": len(dataset),
        "metrics": metrics,
        "trainingSeconds": trainingSeconds,
        "inferenceMilliseconds": inferenceMilliseconds,
        "checksum": artifactChecksum,
    }
    metadataPath = modelPath.with_suffix(".metadata.json")
    metadataPath.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata
