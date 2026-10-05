"""Bounded rolling feature aggregation for normalized file events."""

from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
import math
import logging

from app.domain.schemas import FileAction, FileEvent, FeatureSample, featureColumns, getCurrentTime

logger = logging.getLogger(__name__)


class FeatureWindow:
    def __init__(self, durationSeconds: int = 60, maxEvents: int = 5000):
        self.duration = timedelta(seconds=durationSeconds)
        self.maxEvents = max(100, maxEvents)
        self.events: list[FileEvent] = []
        self.previousEntropy = 0.0

    def addEvents(self, events: list[FileEvent]) -> None:
        self.events.extend(events)
        # Hard bound: a burst of file activity must never create unbounded RAM use.
        if len(self.events) > self.maxEvents:
            self.events = self.events[-self.maxEvents:]
        self._trim(getCurrentTime())

    def _trim(self, currentTime: datetime) -> None:
        cutoffTime = currentTime - self.duration
        self.events = [event for event in self.events if event.occurredAt >= cutoffTime]

    def createSample(
        self,
        observedAt: datetime | None = None,
        processCpuUsage: float = 0.0,
        processMemoryUsage: float = 0.0,
        processLifetime: float = 0.0,
        networkBytes: float = 0.0,
        networkConnectionCount: float = 0.0,
    ) -> FeatureSample:
        sampleTime = observedAt or getCurrentTime()
        self._trim(sampleTime)
        modifiedEvents = [
            event for event in self.events if event.action == FileAction.modified
        ]
        entropyValues = []
        # Entropy is sampled, not calculated for every changed file. This keeps
        # the always-on detector predictable on large workloads.
        for event in modifiedEvents[-32:]:
            try:
                event_path = Path(event.path)
                # Skip special file types and very large files
                if event_path.suffix.lower() in {'.exe', '.dll', '.sys', '.drv'}:
                    continue
                if event_path.is_file() and event_path.stat().st_size > 10 * 1024 * 1024:  # Skip files > 10MB
                    continue

                with event_path.open("rb") as file:
                    data = file.read(4096)
                if data:
                    frequencies = Counter(data)
                    length = len(data)
                    entropyValues.append(
                        -sum((count / length) * math.log2(count / length) for count in frequencies.values())
                    )
            except (OSError, PermissionError) as error:
                logger.debug(f"Unable to calculate entropy for {event.path}: {error}")
                continue
        averageEntropy = sum(entropyValues) / len(entropyValues) if entropyValues else 0.0
        entropyChangeRate = abs(averageEntropy - self.previousEntropy)
        self.previousEntropy = averageEntropy
        extensions = {
            Path(event.path).suffix.lower()
            for event in modifiedEvents
            if Path(event.path).suffix
        }
        directories = {str(Path(event.path).parent) for event in modifiedEvents}
        actionCounts = Counter(event.action for event in self.events)
        values = {column: 0.0 for column in featureColumns}
        values.update(
            {
                "fileWriteCount": float(actionCounts[FileAction.modified]),
                "fileCreateCount": float(actionCounts[FileAction.created]),
                "fileRenameCount": float(actionCounts[FileAction.renamed]),
                "fileDeleteCount": float(actionCounts[FileAction.deleted]),
                "filesModifiedPerMinute": float(len(modifiedEvents)),
                "uniqueDirectoriesModified": float(len(directories)),
                "uniqueExtensionsModified": float(len(extensions)),
                "extensionChangeCount": float(len(extensions)),
                "averageFileEntropy": averageEntropy,
                "entropyChangeRate": entropyChangeRate,
                "processCpuUsage": processCpuUsage,
                "processMemoryUsage": processMemoryUsage,
                "processLifetime": processLifetime,
                "networkBytes": networkBytes,
                "networkConnectionCount": networkConnectionCount,
            }
        )
        return FeatureSample(values=values, observedAt=sampleTime)
