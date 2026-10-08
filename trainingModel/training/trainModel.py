"""Reproducible model training, stratified cross-validation, hyperparameter tuning, and encrypted serialization."""

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Optional, Union

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.domain.schemas import featureColumns, featureSchemaVersion
from app.security.modelEncryption import ModelEncryption
from trainingModel.validation.datasetSchema import reconcileDataset
from trainingModel.validation.datasetValidator import DatasetValidator

logger = logging.getLogger(__name__)

randomSeed = 42

RECOGNIZED_MALICIOUS_LABELS = {
    "ransomware",
    "ransomware_like",
    "ransomware-like",
    "malicious",
}


def getDatasetFingerprint(dataset: pd.DataFrame) -> str:
    """Generate SHA-256 fingerprint of dataset content."""
    content = dataset.to_csv(index=False).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def validateDataset(dataset: pd.DataFrame, strict: bool = True) -> None:
    """
    Validate dataset for poisoning, label balance, and feature corruption.

    Delegates to DatasetValidator.
    """
    validator = DatasetValidator()
    validator.validate(dataset, strict=strict)


def calculateMetrics(
    actual: pd.Series,
    predicted: Any,
    probabilities: Optional[np.ndarray] = None,
    classes: Optional[list[Any]] = None,
) -> dict[str, Any]:
    """Calculate standard classification evaluation metrics including ROC-AUC, FPR, and FNR."""
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
    ransomwareIndexes = [
        index
        for index, label in enumerate(labels)
        if str(label).lower() in RECOGNIZED_MALICIOUS_LABELS
    ]
    ransomwareCount = sum(matrix[index].sum() for index in ransomwareIndexes)
    falseNegativeCount = sum(
        matrix[rowIndex, columnIndex]
        for rowIndex in ransomwareIndexes
        for columnIndex in range(len(labels))
        if rowIndex != columnIndex
    )

    # ROC-AUC calculation
    rocAuc: Optional[float] = None
    if probabilities is not None and classes is not None and len(classes) >= 2:
        try:
            if len(classes) == 2:
                # Binary classification
                maliciousIdx = next(
                    (i for i, c in enumerate(classes) if str(c).lower() in RECOGNIZED_MALICIOUS_LABELS),
                    1,
                )
                maliciousProba = probabilities[:, maliciousIdx]
                # Convert actual to binary indicator
                yBinary = actual.astype(str).str.lower().isin(RECOGNIZED_MALICIOUS_LABELS).astype(int)
                if len(set(yBinary)) > 1:
                    rocAuc = round(float(roc_auc_score(yBinary, maliciousProba)), 6)
            else:
                # Multi-class classification
                rocAuc = round(
                    float(roc_auc_score(actual, probabilities, multi_class="ovr", average="weighted")),
                    6,
                )
        except Exception as error:
            logger.debug(f"Could not compute ROC-AUC score: {error}")
            rocAuc = None

    return {
        "accuracy": round(accuracy_score(actual, predicted), 6),
        "precision": round(precision_score(actual, predicted, average="weighted", zero_division=0), 6),
        "recall": round(recall_score(actual, predicted, average="weighted", zero_division=0), 6),
        "f1": round(f1_score(actual, predicted, average="weighted", zero_division=0), 6),
        "rocAuc": rocAuc,
        "falsePositiveRate": round(falsePositiveCount / benignCount, 6) if benignCount else 0.0,
        "falseNegativeRate": round(falseNegativeCount / ransomwareCount, 6) if ransomwareCount else 0.0,
        "confusionMatrix": matrix.tolist(),
        "labels": [str(l) for l in labels],
        "perClass": classification_report(actual, predicted, output_dict=True, zero_division=0),
    }


def runStratifiedCrossValidation(
    X: pd.DataFrame,
    y: pd.Series,
    estimatorFactory: Any,
    cvFolds: int = 5,
    seed: int = 42,
) -> dict[str, Any]:
    """
    Execute Stratified K-Fold cross validation and return aggregate & fold-by-fold performance metrics.

    Args:
        X: Feature matrix DataFrame
        y: Labels Series
        estimatorFactory: Callable returning a fresh estimator or Pipeline
        cvFolds: Target number of stratified folds (capped by class frequencies)
        seed: Random state seed

    Returns:
        Dictionary with mean/std for accuracy, precision, recall, f1, rocAuc, fpr, fnr, and fold reports
    """
    minClassCount = y.value_counts().min()
    effectiveFolds = max(2, min(cvFolds, minClassCount))

    skf = StratifiedKFold(n_splits=effectiveFolds, shuffle=True, random_state=seed)
    foldMetrics: list[dict[str, Any]] = []

    for foldIndex, (trainIdx, valIdx) in enumerate(skf.split(X, y), start=1):
        XTrain, XVal = X.iloc[trainIdx], X.iloc[valIdx]
        yTrain, yVal = y.iloc[trainIdx], y.iloc[valIdx]

        estimator = estimatorFactory() if callable(estimatorFactory) else estimatorFactory
        estimator.fit(XTrain, yTrain)

        yPred = estimator.predict(XVal)
        yProba = estimator.predict_proba(XVal) if hasattr(estimator, "predict_proba") else None
        classes = list(getattr(estimator, "classes_", []))

        metrics = calculateMetrics(yVal, yPred, probabilities=yProba, classes=classes)
        metrics["fold"] = foldIndex
        foldMetrics.append(metrics)

    accuracies = [m["accuracy"] for m in foldMetrics]
    precisions = [m["precision"] for m in foldMetrics]
    recalls = [m["recall"] for m in foldMetrics]
    f1s = [m["f1"] for m in foldMetrics]
    fprs = [m["falsePositiveRate"] for m in foldMetrics]
    fnrs = [m["falseNegativeRate"] for m in foldMetrics]
    rocAucs = [m["rocAuc"] for m in foldMetrics if m.get("rocAuc") is not None]

    return {
        "folds": effectiveFolds,
        "meanAccuracy": round(float(np.mean(accuracies)), 6),
        "stdAccuracy": round(float(np.std(accuracies)), 6),
        "meanPrecision": round(float(np.mean(precisions)), 6),
        "stdPrecision": round(float(np.std(precisions)), 6),
        "meanRecall": round(float(np.mean(recalls)), 6),
        "stdRecall": round(float(np.std(recalls)), 6),
        "meanF1": round(float(np.mean(f1s)), 6),
        "stdF1": round(float(np.std(f1s)), 6),
        "meanRocAuc": round(float(np.mean(rocAucs)), 6) if rocAucs else None,
        "stdRocAuc": round(float(np.std(rocAucs)), 6) if rocAucs else None,
        "meanFalsePositiveRate": round(float(np.mean(fprs)), 6),
        "stdFalsePositiveRate": round(float(np.std(fprs)), 6),
        "meanFalseNegativeRate": round(float(np.mean(fnrs)), 6),
        "stdFalseNegativeRate": round(float(np.std(fnrs)), 6),
        "foldMetrics": foldMetrics,
    }


def tuneHyperparameters(
    X: pd.DataFrame,
    y: pd.Series,
    paramGrid: Optional[dict[str, list[Any]]] = None,
    cvFolds: int = 5,
    seed: int = 42,
    useScaler: bool = False,
) -> tuple[Any, dict[str, Any]]:
    """
    Perform GridSearchCV hyperparameter tuning over RandomForestClassifier.

    Args:
        X: Feature matrix
        y: Target labels
        paramGrid: Optional custom grid parameters
        cvFolds: Number of cross-validation folds
        seed: Random seed
        useScaler: Whether to wrap classifier with StandardScaler in a Pipeline

    Returns:
        Tuple of (best_fitted_estimator, tuning_summary_dict)
    """
    minClassCount = y.value_counts().min()
    effectiveFolds = max(2, min(cvFolds, minClassCount))

    if paramGrid is None:
        if useScaler:
            grid = {
                "classifier__n_estimators": [50, 100, 200],
                "classifier__max_depth": [5, 10, None],
                "classifier__min_samples_split": [2, 5, 10],
            }
        else:
            grid = {
                "n_estimators": [50, 100, 200],
                "max_depth": [5, 10, None],
                "min_samples_split": [2, 5, 10],
            }
    else:
        grid = paramGrid

    if useScaler:
        baseEstimator = Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", RandomForestClassifier(random_state=seed, class_weight="balanced")),
        ])
    else:
        baseEstimator = RandomForestClassifier(random_state=seed, class_weight="balanced")

    cv = StratifiedKFold(n_splits=effectiveFolds, shuffle=True, random_state=seed)
    gridSearch = GridSearchCV(
        estimator=baseEstimator,
        param_grid=grid,
        scoring="f1_weighted",
        cv=cv,
        n_jobs=-1,
    )

    t0 = time.perf_counter()
    gridSearch.fit(X, y)
    tuningSeconds = round(time.perf_counter() - t0, 4)

    summary = {
        "bestParams": gridSearch.best_params_,
        "bestScore": round(float(gridSearch.best_score_), 6),
        "tuningSeconds": tuningSeconds,
        "paramGrid": grid,
    }
    return gridSearch.best_estimator_, summary


def extractFeatureImportances(estimator: Any) -> dict[str, float]:
    """Extract feature importances from a RandomForestClassifier or Pipeline."""
    rawImportances = None
    if hasattr(estimator, "feature_importances_"):
        rawImportances = estimator.feature_importances_
    elif hasattr(estimator, "named_steps") and "classifier" in estimator.named_steps:
        clf = estimator.named_steps["classifier"]
        if hasattr(clf, "feature_importances_"):
            rawImportances = clf.feature_importances_

    importances: dict[str, float] = {}
    if rawImportances is not None and len(rawImportances) == len(featureColumns):
        pairs = sorted(zip(featureColumns, rawImportances), key=lambda x: x[1], reverse=True)
        for col, val in pairs:
            importances[col] = round(float(val), 6)
    return importances


def trainModel(
    dataset: pd.DataFrame,
    modelPath: Union[str, Path],
    encrypt: bool = False,
    encryption: Optional[ModelEncryption] = None,
    cvFolds: int = 5,
    tune: bool = False,
    useScaler: bool = False,
    paramGrid: Optional[dict[str, list[Any]]] = None,
    autoReconcileSchema: bool = True,
) -> dict[str, Any]:
    """
    Train and save a validated, optionally encrypted classifier from collected behavior samples.

    Includes:
    - Automatic schema reconciliation and dataset quality validation
    - Stratified K-Fold cross validation (k=5)
    - Optional GridSearchCV hyperparameter optimization
    - Feature scaling with StandardScaler
    - Feature importance extraction and ranking
    - Comprehensive performance evaluation (Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR)
    - AES-256-GCM artifact encryption and SHA-256 fingerprinting

    Args:
        dataset: Training pandas DataFrame
        modelPath: Output path for .joblib artifact
        encrypt: Whether to encrypt the artifact with AES-256-GCM
        encryption: Optional ModelEncryption instance
        cvFolds: Number of stratified cross-validation folds (default: 5)
        tune: Whether to perform GridSearchCV hyperparameter tuning
        useScaler: Whether to scale features with StandardScaler
        paramGrid: Optional custom hyperparameter search grid
        autoReconcileSchema: Reconcile legacy column names and missing features

    Returns:
        Metadata dictionary describing the model and training metrics
    """
    # 1. Reconcile schema if enabled
    if autoReconcileSchema:
        df = reconcileDataset(dataset)
    else:
        df = dataset.copy()

    # 2. Validate dataset security and class balance
    validator = DatasetValidator()
    validationResult = validator.validate(df, strict=True)

    trainingData = df[list(featureColumns)].astype(float)
    labels = df["label"].astype(str).str.strip()

    # 3. Stratified Cross-Validation on Full Dataset
    def makeBaseEstimator():
        if useScaler:
            return Pipeline([
                ("scaler", StandardScaler()),
                ("classifier", RandomForestClassifier(
                    n_estimators=100,
                    random_state=randomSeed,
                    class_weight="balanced",
                )),
            ])
        return RandomForestClassifier(
            n_estimators=100,
            random_state=randomSeed,
            class_weight="balanced",
        )

    cvResults = runStratifiedCrossValidation(
        X=trainingData,
        y=labels,
        estimatorFactory=makeBaseEstimator,
        cvFolds=cvFolds,
        seed=randomSeed,
    )

    # 4. Train / Test Split for Final Evaluation
    testSize = max(2, round(len(df) * 0.2))
    trainData, testData, trainLabels, testLabels = train_test_split(
        trainingData,
        labels,
        test_size=testSize,
        random_state=randomSeed,
        stratify=labels,
    )

    tuningSummary: Optional[dict[str, Any]] = None
    startedAt = time.perf_counter()

    if tune:
        logger.info("Executing hyperparameter tuning with GridSearchCV...")
        classifier, tuningSummary = tuneHyperparameters(
            trainData,
            trainLabels,
            paramGrid=paramGrid,
            cvFolds=cvFolds,
            seed=randomSeed,
            useScaler=useScaler,
        )
    else:
        classifier = makeBaseEstimator()
        classifier.fit(trainData, trainLabels)

    trainingSeconds = round(time.perf_counter() - startedAt, 6)

    # 5. Evaluate on Holdout Test Set
    predictedLabels = classifier.predict(testData)
    probabilities = classifier.predict_proba(testData) if hasattr(classifier, "predict_proba") else None
    classes = list(getattr(classifier, "classes_", []))

    metrics = calculateMetrics(
        testLabels,
        predictedLabels,
        probabilities=probabilities,
        classes=classes,
    )

    # 6. Benchmark Single-Sample Inference Speed
    inferenceStartedAt = time.perf_counter()
    classifier.predict_proba(testData.iloc[:1])
    inferenceMilliseconds = round((time.perf_counter() - inferenceStartedAt) * 1000, 6)

    # 7. Extract Feature Importances
    featureImportances = extractFeatureImportances(classifier)

    # 8. Build and Serialize Artifact
    artifact = {
        "model": classifier,
        "featureColumns": featureColumns,
        "featureSchemaVersion": featureSchemaVersion,
        "randomSeed": randomSeed,
        "metrics": metrics,
        "crossValidation": cvResults,
        "featureImportances": featureImportances,
        "useScaler": useScaler,
    }

    resolvedModelPath = Path(modelPath).resolve()
    resolvedModelPath.parent.mkdir(parents=True, exist_ok=True)

    dump(artifact, resolvedModelPath)
    unencryptedChecksum = hashlib.sha256(resolvedModelPath.read_bytes()).hexdigest()

    # 9. Optional AES-256-GCM Encryption
    isEncrypted = False
    if encrypt:
        enc = encryption or ModelEncryption()
        enc.encryptFile(resolvedModelPath)
        isEncrypted = True

    finalChecksum = hashlib.sha256(resolvedModelPath.read_bytes()).hexdigest()

    metadata = {
        "modelVersion": "1.0.0",
        "algorithm": "RandomForestClassifier",
        "featureSchemaVersion": featureSchemaVersion,
        "featureColumns": list(featureColumns),
        "randomSeed": randomSeed,
        "datasetFingerprint": getDatasetFingerprint(df),
        "sampleCount": len(df),
        "useScaler": useScaler,
        "crossValidation": cvResults,
        "metrics": metrics,
        "featureImportances": featureImportances,
        "hyperparameterTuning": tuningSummary,
        "trainingSeconds": trainingSeconds,
        "inferenceMilliseconds": inferenceMilliseconds,
        "checksum": finalChecksum,
        "unencryptedChecksum": unencryptedChecksum,
        "encrypted": isEncrypted,
        "validationSummary": {
            "status": validationResult.status,
            "sampleCount": validationResult.sampleCount,
            "classDistribution": validationResult.classDistribution,
        },
    }

    metadataPath = resolvedModelPath.with_suffix(".metadata.json")
    metadataPath.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    logger.info(
        f"Model trained successfully: path={resolvedModelPath.name}, encrypted={isEncrypted}, "
        f"cv_accuracy={cvResults['meanAccuracy']:.4f}, cv_f1={cvResults['meanF1']:.4f}",
        extra={"event": "model_training", "context": {"path": str(resolvedModelPath), "encrypted": isEncrypted}},
    )
    return metadata
