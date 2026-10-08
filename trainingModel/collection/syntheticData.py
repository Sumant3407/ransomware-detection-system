"""Synthetic balanced behavioral dataset generator for ransomware ML training."""

import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Union

import numpy as np
import pandas as pd

from app.domain.schemas import featureColumns
from trainingModel.validation.datasetValidator import DatasetValidator

logger = logging.getLogger(__name__)


def generateSyntheticSample(
    label: str,
    randomGenerator: random.Random,
    profileVariant: Optional[int] = None,
) -> dict[str, float]:
    """
    Generate a single realistic behavioral feature sample based on class profile.

    Args:
        label: "Benign" or "Ransomware"
        randomGenerator: Seeded random.Random instance
        profileVariant: Optional integer selecting a specific behavioral sub-profile

    Returns:
        Dictionary mapping canonical feature names to float values
    """
    isMalicious = str(label).strip().lower() in {
        "ransomware",
        "ransomware_like",
        "ransomware-like",
        "malicious",
    }

    if not isMalicious:
        # Benign behavioral profiles
        variant = profileVariant if profileVariant is not None else randomGenerator.randint(1, 5)
        if variant == 1:
            # Profile 1: Idle Workstation / Background OS Tasks
            sample = {
                "fileReadCount": float(randomGenerator.randint(0, 5)),
                "fileWriteCount": float(randomGenerator.randint(0, 3)),
                "fileCreateCount": float(randomGenerator.randint(0, 1)),
                "fileRenameCount": 0.0,
                "fileDeleteCount": 0.0,
                "filesModifiedPerMinute": float(randomGenerator.randint(0, 3)),
                "uniqueDirectoriesModified": float(randomGenerator.randint(0, 1)),
                "uniqueExtensionsModified": float(randomGenerator.randint(0, 1)),
                "extensionChangeCount": 0.0,
                "averageFileEntropy": round(randomGenerator.uniform(0.0, 3.5), 4),
                "entropyChangeRate": round(randomGenerator.uniform(0.0, 0.5), 4),
                "processCpuUsage": round(randomGenerator.uniform(0.5, 8.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(25.0, 55.0), 2),
                "processLifetime": round(randomGenerator.uniform(300.0, 7200.0), 1),
                "networkBytes": float(randomGenerator.randint(0, 20000)),
                "networkConnectionCount": float(randomGenerator.randint(1, 8)),
            }
        elif variant == 2:
            # Profile 2: Document Editing & Office Productivity
            mods = randomGenerator.randint(1, 8)
            sample = {
                "fileReadCount": float(randomGenerator.randint(5, 25)),
                "fileWriteCount": float(mods),
                "fileCreateCount": float(randomGenerator.randint(0, 2)),
                "fileRenameCount": float(randomGenerator.randint(0, 1)),
                "fileDeleteCount": float(randomGenerator.randint(0, 1)),
                "filesModifiedPerMinute": float(mods),
                "uniqueDirectoriesModified": float(randomGenerator.randint(1, 2)),
                "uniqueExtensionsModified": float(randomGenerator.randint(1, 2)),
                "extensionChangeCount": 0.0,
                "averageFileEntropy": round(randomGenerator.uniform(3.2, 5.2), 4),
                "entropyChangeRate": round(randomGenerator.uniform(0.1, 0.8), 4),
                "processCpuUsage": round(randomGenerator.uniform(2.0, 18.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(35.0, 65.0), 2),
                "processLifetime": round(randomGenerator.uniform(120.0, 3600.0), 1),
                "networkBytes": float(randomGenerator.randint(500, 100000)),
                "networkConnectionCount": float(randomGenerator.randint(2, 10)),
            }
        elif variant == 3:
            # Profile 3: Software Compilation / Git Operations
            mods = randomGenerator.randint(8, 30)
            sample = {
                "fileReadCount": float(randomGenerator.randint(20, 80)),
                "fileWriteCount": float(mods),
                "fileCreateCount": float(randomGenerator.randint(2, 12)),
                "fileRenameCount": float(randomGenerator.randint(0, 3)),
                "fileDeleteCount": float(randomGenerator.randint(0, 4)),
                "filesModifiedPerMinute": float(mods),
                "uniqueDirectoriesModified": float(randomGenerator.randint(2, 6)),
                "uniqueExtensionsModified": float(randomGenerator.randint(2, 5)),
                "extensionChangeCount": float(randomGenerator.randint(0, 1)),
                "averageFileEntropy": round(randomGenerator.uniform(4.0, 5.8), 4),
                "entropyChangeRate": round(randomGenerator.uniform(0.2, 1.2), 4),
                "processCpuUsage": round(randomGenerator.uniform(15.0, 60.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(40.0, 75.0), 2),
                "processLifetime": round(randomGenerator.uniform(30.0, 1800.0), 1),
                "networkBytes": float(randomGenerator.randint(5000, 500000)),
                "networkConnectionCount": float(randomGenerator.randint(4, 15)),
            }
        elif variant == 4:
            # Profile 4: Photo / File Organization (renames without extension change)
            renames = randomGenerator.randint(3, 15)
            sample = {
                "fileReadCount": float(randomGenerator.randint(10, 40)),
                "fileWriteCount": float(randomGenerator.randint(2, 10)),
                "fileCreateCount": float(randomGenerator.randint(0, 2)),
                "fileRenameCount": float(renames),
                "fileDeleteCount": float(randomGenerator.randint(0, 2)),
                "filesModifiedPerMinute": float(randomGenerator.randint(2, 10)),
                "uniqueDirectoriesModified": float(randomGenerator.randint(1, 3)),
                "uniqueExtensionsModified": float(randomGenerator.randint(1, 3)),
                "extensionChangeCount": 0.0,  # Legitimate rename preserves extension
                "averageFileEntropy": round(randomGenerator.uniform(5.5, 7.1), 4),
                "entropyChangeRate": round(randomGenerator.uniform(0.0, 0.6), 4),
                "processCpuUsage": round(randomGenerator.uniform(3.0, 22.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(30.0, 60.0), 2),
                "processLifetime": round(randomGenerator.uniform(60.0, 2400.0), 1),
                "networkBytes": float(randomGenerator.randint(0, 50000)),
                "networkConnectionCount": float(randomGenerator.randint(1, 6)),
            }
        else:
            # Profile 5: Clean Archiving / Zip Compression
            writes = randomGenerator.randint(2, 8)
            sample = {
                "fileReadCount": float(randomGenerator.randint(30, 150)),
                "fileWriteCount": float(writes),
                "fileCreateCount": float(randomGenerator.randint(1, 3)),
                "fileRenameCount": 0.0,
                "fileDeleteCount": 0.0,
                "filesModifiedPerMinute": float(writes),
                "uniqueDirectoriesModified": 1.0,
                "uniqueExtensionsModified": float(randomGenerator.randint(1, 2)),
                "extensionChangeCount": 0.0,
                "averageFileEntropy": round(randomGenerator.uniform(6.8, 7.7), 4),  # High entropy due to zip
                "entropyChangeRate": round(randomGenerator.uniform(0.5, 2.0), 4),
                "processCpuUsage": round(randomGenerator.uniform(25.0, 75.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(45.0, 70.0), 2),
                "processLifetime": round(randomGenerator.uniform(15.0, 600.0), 1),
                "networkBytes": float(randomGenerator.randint(0, 30000)),
                "networkConnectionCount": float(randomGenerator.randint(1, 4)),
            }
    else:
        # Ransomware / Malicious behavioral profiles
        variant = profileVariant if profileVariant is not None else randomGenerator.randint(1, 5)
        if variant == 1:
            # Ransomware Profile 1: High-Speed Mass Encryptor (LockBit / Conti style)
            mods = randomGenerator.randint(60, 350)
            sample = {
                "fileReadCount": float(randomGenerator.randint(80, 400)),
                "fileWriteCount": float(mods),
                "fileCreateCount": float(randomGenerator.randint(10, 80)),
                "fileRenameCount": float(randomGenerator.randint(20, 120)),
                "fileDeleteCount": float(randomGenerator.randint(5, 50)),
                "filesModifiedPerMinute": float(mods),
                "uniqueDirectoriesModified": float(randomGenerator.randint(8, 35)),
                "uniqueExtensionsModified": float(randomGenerator.randint(5, 16)),
                "extensionChangeCount": float(randomGenerator.randint(25, 140)),
                "averageFileEntropy": round(randomGenerator.uniform(7.55, 7.99), 4),  # Shannon entropy close to 8.0
                "entropyChangeRate": round(randomGenerator.uniform(3.0, 6.5), 4),
                "processCpuUsage": round(randomGenerator.uniform(45.0, 98.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(40.0, 88.0), 2),
                "processLifetime": round(randomGenerator.uniform(3.0, 120.0), 1),
                "networkBytes": float(randomGenerator.randint(10000, 2000000)),
                "networkConnectionCount": float(randomGenerator.randint(2, 20)),
            }
        elif variant == 2:
            # Ransomware Profile 2: Cryptographic Bulk Renaming (.locked / .crypto)
            renames = randomGenerator.randint(40, 200)
            sample = {
                "fileReadCount": float(randomGenerator.randint(50, 250)),
                "fileWriteCount": float(randomGenerator.randint(40, 180)),
                "fileCreateCount": float(randomGenerator.randint(15, 60)),
                "fileRenameCount": float(renames),
                "fileDeleteCount": float(randomGenerator.randint(2, 25)),
                "filesModifiedPerMinute": float(randomGenerator.randint(50, 220)),
                "uniqueDirectoriesModified": float(randomGenerator.randint(6, 28)),
                "uniqueExtensionsModified": float(randomGenerator.randint(6, 18)),
                "extensionChangeCount": float(renames),  # All renames alter extensions to ransomware markers
                "averageFileEntropy": round(randomGenerator.uniform(7.45, 7.98), 4),
                "entropyChangeRate": round(randomGenerator.uniform(2.5, 5.8), 4),
                "processCpuUsage": round(randomGenerator.uniform(35.0, 90.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(35.0, 80.0), 2),
                "processLifetime": round(randomGenerator.uniform(5.0, 180.0), 1),
                "networkBytes": float(randomGenerator.randint(5000, 500000)),
                "networkConnectionCount": float(randomGenerator.randint(1, 12)),
            }
        elif variant == 3:
            # Ransomware Profile 3: Broad Directory Traversal & Deep Tree Attack
            dirs = randomGenerator.randint(12, 45)
            mods = randomGenerator.randint(45, 280)
            sample = {
                "fileReadCount": float(randomGenerator.randint(60, 320)),
                "fileWriteCount": float(mods),
                "fileCreateCount": float(randomGenerator.randint(12, 50)),
                "fileRenameCount": float(randomGenerator.randint(15, 90)),
                "fileDeleteCount": float(randomGenerator.randint(4, 30)),
                "filesModifiedPerMinute": float(mods),
                "uniqueDirectoriesModified": float(dirs),
                "uniqueExtensionsModified": float(randomGenerator.randint(8, 22)),
                "extensionChangeCount": float(randomGenerator.randint(20, 100)),
                "averageFileEntropy": round(randomGenerator.uniform(7.50, 7.97), 4),
                "entropyChangeRate": round(randomGenerator.uniform(2.8, 6.0), 4),
                "processCpuUsage": round(randomGenerator.uniform(40.0, 95.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(45.0, 85.0), 2),
                "processLifetime": round(randomGenerator.uniform(4.0, 150.0), 1),
                "networkBytes": float(randomGenerator.randint(20000, 1500000)),
                "networkConnectionCount": float(randomGenerator.randint(3, 18)),
            }
        elif variant == 4:
            # Ransomware Profile 4: Double Extortion / Exfiltration + Encryption
            mods = randomGenerator.randint(50, 250)
            sample = {
                "fileReadCount": float(randomGenerator.randint(150, 600)),
                "fileWriteCount": float(mods),
                "fileCreateCount": float(randomGenerator.randint(8, 40)),
                "fileRenameCount": float(randomGenerator.randint(20, 110)),
                "fileDeleteCount": float(randomGenerator.randint(2, 20)),
                "filesModifiedPerMinute": float(mods),
                "uniqueDirectoriesModified": float(randomGenerator.randint(5, 25)),
                "uniqueExtensionsModified": float(randomGenerator.randint(4, 15)),
                "extensionChangeCount": float(randomGenerator.randint(18, 95)),
                "averageFileEntropy": round(randomGenerator.uniform(7.60, 7.99), 4),
                "entropyChangeRate": round(randomGenerator.uniform(3.2, 6.2), 4),
                "processCpuUsage": round(randomGenerator.uniform(50.0, 99.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(50.0, 90.0), 2),
                "processLifetime": round(randomGenerator.uniform(10.0, 240.0), 1),
                "networkBytes": float(randomGenerator.randint(500000, 15000000)),  # Heavy data exfiltration
                "networkConnectionCount": float(randomGenerator.randint(8, 35)),
            }
        else:
            # Ransomware Profile 5: Wiper / Shadow Copy Deleter & Note Dropper
            deletes = randomGenerator.randint(25, 120)
            creates = randomGenerator.randint(15, 80)
            sample = {
                "fileReadCount": float(randomGenerator.randint(40, 200)),
                "fileWriteCount": float(randomGenerator.randint(30, 160)),
                "fileCreateCount": float(creates),
                "fileRenameCount": float(randomGenerator.randint(10, 70)),
                "fileDeleteCount": float(deletes),
                "filesModifiedPerMinute": float(randomGenerator.randint(35, 180)),
                "uniqueDirectoriesModified": float(randomGenerator.randint(5, 22)),
                "uniqueExtensionsModified": float(randomGenerator.randint(4, 14)),
                "extensionChangeCount": float(randomGenerator.randint(12, 60)),
                "averageFileEntropy": round(randomGenerator.uniform(7.40, 7.95), 4),
                "entropyChangeRate": round(randomGenerator.uniform(2.4, 5.5), 4),
                "processCpuUsage": round(randomGenerator.uniform(30.0, 85.0), 2),
                "processMemoryUsage": round(randomGenerator.uniform(35.0, 75.0), 2),
                "processLifetime": round(randomGenerator.uniform(2.0, 90.0), 1),
                "networkBytes": float(randomGenerator.randint(5000, 600000)),
                "networkConnectionCount": float(randomGenerator.randint(2, 10)),
            }

    # Ensure all canonical columns are present and strictly formatted
    result: dict[str, float] = {}
    for col in featureColumns:
        result[col] = float(sample.get(col, 0.0))

    return result


def generateSyntheticDataset(
    sampleCount: int = 300,
    maliciousRatio: float = 0.5,
    seed: int = 42,
    baseTimestamp: Optional[datetime] = None,
    timeStepSeconds: float = 1.0,
) -> pd.DataFrame:
    """
    Generate a balanced, high-fidelity synthetic behavioral dataset for ML training.

    Args:
        sampleCount: Total number of samples to generate (default: 300)
        maliciousRatio: Ratio of malicious/ransomware samples (default: 0.5 for 50/50 balance)
        seed: Random seed for reproducible generation
        baseTimestamp: Starting timestamp (default: current UTC time)
        timeStepSeconds: Seconds between successive samples

    Returns:
        pandas DataFrame containing timestamps, canonical feature columns, and class labels
    """
    if sampleCount < 4:
        raise ValueError(f"sampleCount must be >= 4, got {sampleCount}")
    if not (0.05 <= maliciousRatio <= 0.95):
        raise ValueError(f"maliciousRatio must be between 0.05 and 0.95, got {maliciousRatio}")

    randomGen = random.Random(seed)
    np.random.seed(seed)

    maliciousCount = int(round(sampleCount * maliciousRatio))
    benignCount = sampleCount - maliciousCount

    # Create label list
    labels = ["Benign"] * benignCount + ["Ransomware"] * maliciousCount
    randomGen.shuffle(labels)

    currentTimestamp = baseTimestamp or datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    rows: list[dict[str, Union[str, float]]] = []

    for index, label in enumerate(labels):
        sampleFeatures = generateSyntheticSample(label, randomGen)
        sampleTime = currentTimestamp + timedelta(seconds=index * timeStepSeconds)

        row: dict[str, Union[str, float]] = {
            "timestamp": sampleTime.isoformat(),
            **sampleFeatures,
            "label": label,
        }
        rows.append(row)

    df = pd.DataFrame(rows)

    # Validate generated dataset quality
    validator = DatasetValidator()
    validationResult = validator.validate(df, strict=True)
    logger.info(
        f"Generated synthetic dataset: {sampleCount} samples ({benignCount} Benign, {maliciousCount} Ransomware). "
        f"Validation: {validationResult.status}"
    )

    return df


def generateAndSaveDataset(
    outputPath: Union[str, Path],
    sampleCount: int = 300,
    maliciousRatio: float = 0.5,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Generate a synthetic dataset and save to disk as a CSV file.

    Args:
        outputPath: Destination path for CSV file
        sampleCount: Total number of samples (default: 300)
        maliciousRatio: Ratio of ransomware samples (default: 0.5)
        seed: Random seed (default: 42)

    Returns:
        Generated pandas DataFrame
    """
    destPath = Path(outputPath).resolve()
    destPath.parent.mkdir(parents=True, exist_ok=True)

    df = generateSyntheticDataset(
        sampleCount=sampleCount,
        maliciousRatio=maliciousRatio,
        seed=seed,
    )
    df.to_csv(destPath, index=False)
    logger.info(f"Synthetic dataset saved to {destPath}")
    return df
