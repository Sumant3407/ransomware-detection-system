"""Versioned event and feature contracts."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum


featureSchemaVersion = "1.0"
featureColumns = (
    "fileReadCount",
    "fileWriteCount",
    "fileCreateCount",
    "fileRenameCount",
    "fileDeleteCount",
    "filesModifiedPerMinute",
    "uniqueDirectoriesModified",
    "uniqueExtensionsModified",
    "extensionChangeCount",
    "averageFileEntropy",
    "entropyChangeRate",
    "processCpuUsage",
    "processMemoryUsage",
    "processLifetime",
    "networkBytes",
    "networkConnectionCount",
)


class FileAction(StrEnum):
    created = "created"
    modified = "modified"
    renamed = "renamed"
    deleted = "deleted"


@dataclass(frozen=True)
class FileEvent:
    action: FileAction
    path: str
    occurredAt: datetime
    source: str = "polling"
    oldPath: str | None = None
    processId: int | None = None


@dataclass(frozen=True)
class FeatureSample:
    values: dict[str, float]
    observedAt: datetime
    schemaVersion: str = featureSchemaVersion


def getCurrentTime() -> datetime:
    return datetime.now(timezone.utc)
