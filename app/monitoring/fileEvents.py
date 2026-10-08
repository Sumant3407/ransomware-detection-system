"""Deterministic polling file-event source used as the safe fallback."""

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.domain.schemas import FileAction, FileEvent, getCurrentTime

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FileState:
    size: int
    modifiedTime: float


def getSnapshot(directory: Path) -> dict[str, FileState]:
    snapshot = {}
    if not directory.is_dir():
        logger.debug(f"Snapshot target is not a directory: {directory}")
        return snapshot
    for root, directoryNames, fileNames in os.walk(directory):
        directoryNames[:] = [name for name in directoryNames if not name.startswith(".")]
        for fileName in fileNames:
            filePath = Path(root) / fileName
            try:
                fileStats = filePath.stat()
            except OSError as error:
                logger.debug(f"Skipping unreadable file during snapshot: {filePath} ({error})")
                continue
            snapshot[str(filePath)] = FileState(fileStats.st_size, fileStats.st_mtime)
    return snapshot


def compareSnapshots(
    previousSnapshot: dict[str, FileState],
    currentSnapshot: dict[str, FileState],
    occurredAt: datetime | None = None,
    pathId: int | None = None,
    monitoredPath: str | None = None,
) -> list[FileEvent]:
    eventTime = occurredAt or getCurrentTime()
    previousPaths = set(previousSnapshot)
    currentPaths = set(currentSnapshot)
    events = [
        FileEvent(FileAction.created, path, eventTime, source="polling", pathId=pathId, monitoredPath=monitoredPath)
        for path in sorted(currentPaths - previousPaths)
    ]
    events.extend(
        FileEvent(FileAction.deleted, path, eventTime, source="polling", pathId=pathId, monitoredPath=monitoredPath)
        for path in sorted(previousPaths - currentPaths)
    )
    events.extend(
        FileEvent(FileAction.modified, path, eventTime, source="polling", pathId=pathId, monitoredPath=monitoredPath)
        for path in sorted(previousPaths & currentPaths)
        if previousSnapshot[path] != currentSnapshot[path]
    )
    return events


class PollingFileEventSource:
    def __init__(self, directory: Path, pathId: int | None = None):
        self.directory = directory.resolve()
        self.pathId = pathId
        self.previousSnapshot = getSnapshot(self.directory)

    def collectEvents(self) -> list[FileEvent]:
        currentSnapshot = getSnapshot(self.directory)
        events = compareSnapshots(
            self.previousSnapshot,
            currentSnapshot,
            pathId=self.pathId,
            monitoredPath=str(self.directory),
        )
        self.previousSnapshot = currentSnapshot
        return events
