"""Schema reconciliation and normalization for training datasets."""

import logging
from pathlib import Path
from typing import Optional, Union

import numpy as np
import pandas as pd

from app.domain.schemas import featureColumns

logger = logging.getLogger(__name__)

# Legacy column aliases mapped to canonical featureColumns
SCHEMA_ALIASES: dict[str, str] = {
    "avgfileentropy": "averageFileEntropy",
    "avg_file_entropy": "averageFileEntropy",
    "fileentropy": "averageFileEntropy",
    "entropy": "averageFileEntropy",
    "cpuusage": "processCpuUsage",
    "cpu_usage": "processCpuUsage",
    "processcpu": "processCpuUsage",
    "memoryusage": "processMemoryUsage",
    "memory_usage": "processMemoryUsage",
    "processmemory": "processMemoryUsage",
    "networkdelta": "networkBytes",
    "network_bytes": "networkBytes",
    "filereadcount": "fileReadCount",
    "filewritecount": "fileWriteCount",
    "filecreatecount": "fileCreateCount",
    "filerenamecount": "fileRenameCount",
    "filedeletecount": "fileDeleteCount",
    "filesmodifiedperminute": "filesModifiedPerMinute",
    "uniquedirectoriesmodified": "uniqueDirectoriesModified",
    "uniqueextensionsmodified": "uniqueExtensionsModified",
    "extensionchangecount": "extensionChangeCount",
    "entropychangerate": "entropyChangeRate",
    "processlifetime": "processLifetime",
    "networkconnectioncount": "networkConnectionCount",
}

# Standard default values for missing columns
COLUMN_DEFAULTS: dict[str, float] = {
    "fileReadCount": 0.0,
    "fileWriteCount": 0.0,
    "fileCreateCount": 0.0,
    "fileRenameCount": 0.0,
    "fileDeleteCount": 0.0,
    "filesModifiedPerMinute": 0.0,
    "uniqueDirectoriesModified": 0.0,
    "uniqueExtensionsModified": 0.0,
    "extensionChangeCount": 0.0,
    "averageFileEntropy": 0.0,
    "entropyChangeRate": 0.0,
    "processCpuUsage": 0.0,
    "processMemoryUsage": 0.0,
    "processLifetime": 0.0,
    "networkBytes": 0.0,
    "networkConnectionCount": 0.0,
}


def reconcileDataset(
    dataset: pd.DataFrame,
    fillDefaults: bool = True,
    standardizeLabels: bool = True,
) -> pd.DataFrame:
    """
    Reconcile and normalize a dataset DataFrame to canonical featureColumns and types.

    1. Maps legacy column aliases to canonical schema names (case-insensitive).
    2. Fills missing canonical feature columns with safe defaults if fillDefaults=True.
    3. Normalizes numeric types (float64).
    4. Standardizes label column format if standardizeLabels=True.
    5. Preserves timestamp column if present.

    Args:
        dataset: Input DataFrame (legacy or modern)
        fillDefaults: Whether to add missing canonical columns with default values
        standardizeLabels: Whether to strip and normalize label string formatting

    Returns:
        Reconciled pandas DataFrame
    """
    if not isinstance(dataset, pd.DataFrame):
        raise TypeError(f"Expected pandas DataFrame, got {type(dataset).__name__}")

    df = dataset.copy()

    # Step 1: Normalize column names using alias mapping
    newColumns: dict[str, str] = {}
    for col in df.columns:
        cleanKey = str(col).strip().replace(" ", "").replace("_", "").lower()
        if cleanKey in SCHEMA_ALIASES:
            canonicalName = SCHEMA_ALIASES[cleanKey]
            newColumns[col] = canonicalName

    if newColumns:
        df = df.rename(columns=newColumns)
        logger.debug(f"Reconciled column aliases: {newColumns}")

    # Step 2: Ensure label column exists
    labelCol = None
    for col in df.columns:
        if str(col).strip().lower() == "label":
            labelCol = col
            break

    if labelCol and labelCol != "label":
        df = df.rename(columns={labelCol: "label"})

    if "label" in df.columns and standardizeLabels:
        # Standardize labels (e.g., 'benign' -> 'Benign', 'ransomware_like' -> 'Ransomware')
        df["label"] = df["label"].astype(str).str.strip()

    # Step 3: Fill missing canonical columns if requested
    if fillDefaults:
        for col in featureColumns:
            if col not in df.columns:
                defaultValue = COLUMN_DEFAULTS.get(col, 0.0)
                df[col] = defaultValue
                logger.debug(f"Populated missing schema column '{col}' with default {defaultValue}")

    # Step 4: Cast all feature columns to float
    for col in featureColumns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0).astype(float)

    # Step 5: Order columns predictably: [timestamp (if present), *featureColumns, label (if present)]
    orderedCols = []
    if "timestamp" in df.columns:
        orderedCols.append("timestamp")
    for col in featureColumns:
        if col in df.columns:
            orderedCols.append(col)
    if "label" in df.columns:
        orderedCols.append("label")

    # Add any other extra columns at the end
    extraCols = [c for c in df.columns if c not in orderedCols]
    orderedCols.extend(extraCols)

    return df[orderedCols]


def reconcileDatasetFile(
    inputPath: Union[str, Path],
    outputPath: Optional[Union[str, Path]] = None,
) -> pd.DataFrame:
    """
    Read a CSV dataset file, reconcile its schema to canonical format, and optionally save.

    Args:
        inputPath: Path to source CSV file
        outputPath: Optional destination path to write reconciled CSV

    Returns:
        Reconciled pandas DataFrame
    """
    inPath = Path(inputPath).resolve()
    if not inPath.is_file():
        raise FileNotFoundError(f"Dataset file not found: {inPath}")

    df = pd.read_csv(inPath)
    reconciled = reconcileDataset(df)

    if outputPath is not None:
        outPath = Path(outputPath).resolve()
        outPath.parent.mkdir(parents=True, exist_ok=True)
        reconciled.to_csv(outPath, index=False)
        logger.info(f"Reconciled dataset saved to {outPath} ({len(reconciled)} rows)")

    return reconciled
