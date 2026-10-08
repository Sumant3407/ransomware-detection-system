"""Bounded rolling feature aggregation for normalized file events."""

import logging
import math
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from app.domain.schemas import (
    KNOWN_RANSOMWARE_EXTENSIONS,
    TARGETED_DOCUMENT_EXTENSIONS,
    FeatureSample,
    FileAction,
    FileEvent,
    extendedFeatureColumns,
    featureColumns,
    getCurrentTime,
)

logger = logging.getLogger(__name__)


# Safe file extensions to read for entropy calculation
SAFE_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".log", ".md",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg",
    ".zip", ".rar", ".7z", ".tar", ".gz",
}

# Dangerous extensions to skip (executables, system files)
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".scr", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jar", ".msi", ".cab",
}

# Maximum file size to read for entropy (1 MB)
MAX_FILE_SIZE_FOR_ENTROPY = 1024 * 1024

# Maximum entropy read timeout (2 seconds)
ENTROPY_READ_TIMEOUT = 2


class FeatureWindow:
    """
    Maintains a bounded rolling temporal window of file events and computes
    both canonical and extended behavioral features.
    """

    def __init__(self, durationSeconds: int = 60, maxEvents: int = 5000):
        self.duration = timedelta(seconds=max(5, durationSeconds))
        self.maxEvents = max(100, maxEvents)
        self.events: list[FileEvent] = []
        self.previousEntropy = 0.0

    def addEvents(self, events: list[FileEvent]) -> None:
        """Add events to the window and maintain bounds."""
        self.events.extend(events)
        # Hard bound: a burst of file activity must never create unbounded RAM use.
        if len(self.events) > self.maxEvents:
            self.events = self.events[-self.maxEvents:]
        self._trim(getCurrentTime())

    def _trim(self, currentTime: datetime) -> None:
        """Discard events older than the window duration."""
        cutoffTime = currentTime - self.duration
        self.events = [event for event in self.events if event.occurredAt >= cutoffTime]

    def _canReadFileForEntropy(self, filePath: Path) -> bool:
        """Check if a file is safe to read for entropy calculation."""
        suffix = filePath.suffix.lower()
        if suffix in DANGEROUS_EXTENSIONS:
            return False

        try:
            if not filePath.is_file():
                return False
        except (OSError, PermissionError) as error:
            logger.debug(f"Cannot check if file exists: {filePath} ({error})")
            return False

        try:
            if filePath.stat().st_size > MAX_FILE_SIZE_FOR_ENTROPY:
                logger.debug(f"File too large for entropy calculation: {filePath}")
                return False
        except (OSError, PermissionError):
            logger.debug(f"Cannot stat file for entropy: {filePath}")
            return False

        return True

    def _calculateFileEntropy(self, filePath: Path) -> Optional[float]:
        """
        Calculate Shannon entropy for a file (range 0.0 to 8.0).
        Safely catches read errors, permission issues, and missing files.
        """
        if not self._canReadFileForEntropy(filePath):
            return None

        try:
            if not filePath.stat().st_mode & 0o400:  # Check if readable
                logger.debug(f"File not readable: {filePath}")
                return None

            with open(filePath, "rb") as file:
                data = file.read(4096)

            if not data:
                return None

            frequencies = Counter(data)
            length = len(data)
            entropy = -sum((count / length) * math.log2(count / length) for count in frequencies.values())
            return min(8.0, max(0.0, float(entropy)))

        except PermissionError:
            logger.debug(f"Permission denied reading file for entropy: {filePath}")
            return None
        except (OSError, IOError) as error:
            logger.debug(f"Error reading file for entropy {filePath}: {error}")
            return None
        except (ValueError, ZeroDivisionError) as error:
            logger.warning(f"Error calculating entropy for {filePath}: {error}")
            return None

    def createSample(
        self,
        observedAt: datetime | None = None,
        processCpuUsage: float = 0.0,
        processMemoryUsage: float = 0.0,
        processLifetime: float = 0.0,
        networkBytes: float = 0.0,
        networkConnectionCount: float = 0.0,
    ) -> FeatureSample:
        """
        Aggregate features across the rolling window into a FeatureSample.

        Computes canonical 16 features for model compatibility as well as
        extended behavioral metrics (burst velocity, target diversity, directory depth).
        """
        sampleTime = observedAt or getCurrentTime()
        self._trim(sampleTime)

        modifiedEvents = [e for e in self.events if e.action == FileAction.modified]
        createdEvents = [e for e in self.events if e.action == FileAction.created]
        renamedEvents = [e for e in self.events if e.action == FileAction.renamed]
        deletedEvents = [e for e in self.events if e.action == FileAction.deleted]

        actionCounts = Counter(e.action for e in self.events)

        # 1. Entropy metrics
        entropyCandidates = (modifiedEvents + createdEvents)[-32:]
        entropyValues: list[float] = []
        for event in entropyCandidates:
            try:
                entropy = self._calculateFileEntropy(Path(event.path))
                if entropy is not None:
                    entropyValues.append(entropy)
            except Exception as error:
                logger.warning(f"Unexpected error during entropy calculation for {event.path}: {error}")
                continue

        averageEntropy = sum(entropyValues) / len(entropyValues) if entropyValues else 0.0
        maxFileEntropy = max(entropyValues) if entropyValues else 0.0
        highEntropyCount = sum(1 for e in entropyValues if e > 7.2)
        highEntropyRatio = (highEntropyCount / len(entropyValues)) if entropyValues else 0.0
        entropyChangeRate = abs(averageEntropy - self.previousEntropy)
        self.previousEntropy = averageEntropy

        # 2. Extension analysis & diversity
        allExtensions = [
            Path(e.path).suffix.lower() for e in self.events if Path(e.path).suffix
        ]
        uniqueModifiedExtensions = {
            Path(e.path).suffix.lower() for e in modifiedEvents if Path(e.path).suffix
        }

        if allExtensions:
            extCounts = Counter(allExtensions)
            totalExts = len(allExtensions)
            extensionEntropy = -sum((c / totalExts) * math.log2(c / totalExts) for c in extCounts.values())
        else:
            extensionEntropy = 0.0

        # Extension changes: rename pairs where extension changed + ransomware extension creations
        extensionChanges = 0
        for event in renamedEvents:
            if event.oldPath:
                oldExt = Path(event.oldPath).suffix.lower()
                newExt = Path(event.path).suffix.lower()
                if oldExt != newExt:
                    extensionChanges += 1
            else:
                extensionChanges += 1

        for event in createdEvents:
            if Path(event.path).suffix.lower() in KNOWN_RANSOMWARE_EXTENSIONS:
                extensionChanges += 1

        if extensionChanges == 0 and len(uniqueModifiedExtensions) > 1:
            extensionChangeCount = float(len(uniqueModifiedExtensions))
        else:
            extensionChangeCount = float(extensionChanges)

        # 3. Targeted document & suspicious extension tracking
        targetedDocumentCount = float(sum(
            1 for e in self.events if Path(e.path).suffix.lower() in TARGETED_DOCUMENT_EXTENSIONS
        ))
        suspiciousExtensionCount = float(sum(
            1 for e in self.events if Path(e.path).suffix.lower() in KNOWN_RANSOMWARE_EXTENSIONS
        ))

        # 4. Directory depth and traversal metrics
        modifiedDirectories = {str(Path(e.path).parent) for e in modifiedEvents}
        depths = [len(Path(e.path).parts) for e in self.events]
        averageDirectoryDepth = sum(depths) / len(depths) if depths else 0.0
        maxDirectoryDepth = float(max(depths)) if depths else 0.0

        # 5. Velocity and short-window burst intensity (last 5 seconds)
        burstCutoff = sampleTime - timedelta(seconds=5)
        burstEvents = [e for e in self.events if e.occurredAt >= burstCutoff]
        burstModified = [e for e in burstEvents if e.action == FileAction.modified]
        filesModifiedPerSecond = len(burstModified) / 5.0

        windowSeconds = self.duration.total_seconds()
        expectedFraction = 5.0 / max(5.0, windowSeconds)
        actualFraction = len(burstEvents) / max(1, len(self.events)) if self.events else 0.0
        burstIntensity = (actualFraction / expectedFraction) if expectedFraction > 0 else 0.0

        # 6. Process attribution correlation
        processIds = [e.processId for e in self.events if e.processId is not None]
        uniqueProcessesActive = float(len(set(processIds)))
        if processIds:
            procCounts = Counter(processIds)
            topCount = procCounts.most_common(1)[0][1]
            topProcessEventConcentration = float(topCount / len(processIds))
        else:
            topProcessEventConcentration = 0.0

        # Construct comprehensive feature values dictionary
        values: dict[str, float] = {
            # Canonical 16 features (strict model compatibility)
            "fileReadCount": 0.0,
            "fileWriteCount": float(actionCounts[FileAction.modified]),
            "fileCreateCount": float(actionCounts[FileAction.created]),
            "fileRenameCount": float(actionCounts[FileAction.renamed]),
            "fileDeleteCount": float(actionCounts[FileAction.deleted]),
            "filesModifiedPerMinute": float(len(modifiedEvents)),
            "uniqueDirectoriesModified": float(len(modifiedDirectories)),
            "uniqueExtensionsModified": float(len(uniqueModifiedExtensions)),
            "extensionChangeCount": float(extensionChangeCount),
            "averageFileEntropy": float(averageEntropy),
            "entropyChangeRate": float(entropyChangeRate),
            "processCpuUsage": float(processCpuUsage),
            "processMemoryUsage": float(processMemoryUsage),
            "processLifetime": float(processLifetime),
            "networkBytes": float(networkBytes),
            "networkConnectionCount": float(networkConnectionCount),
            # Extended behavioral features
            "filesModifiedPerSecond": float(filesModifiedPerSecond),
            "burstIntensity": float(burstIntensity),
            "targetedDocumentCount": float(targetedDocumentCount),
            "suspiciousExtensionCount": float(suspiciousExtensionCount),
            "extensionEntropy": float(extensionEntropy),
            "averageDirectoryDepth": float(averageDirectoryDepth),
            "maxDirectoryDepth": float(maxDirectoryDepth),
            "maxFileEntropy": float(maxFileEntropy),
            "highEntropyRatio": float(highEntropyRatio),
            "uniqueProcessesActive": float(uniqueProcessesActive),
            "topProcessEventConcentration": float(topProcessEventConcentration),
        }

        return FeatureSample(values=values, observedAt=sampleTime)
