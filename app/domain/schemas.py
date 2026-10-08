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

extendedFeatureColumns = featureColumns + (
    "filesModifiedPerSecond",
    "burstIntensity",
    "targetedDocumentCount",
    "suspiciousExtensionCount",
    "extensionEntropy",
    "averageDirectoryDepth",
    "maxDirectoryDepth",
    "maxFileEntropy",
    "highEntropyRatio",
    "uniqueProcessesActive",
    "topProcessEventConcentration",
)

# High-value document and user data extensions targeted by ransomware
TARGETED_DOCUMENT_EXTENSIONS = frozenset({
    # Documents & text
    ".doc", ".docx", ".odt", ".rtf", ".pdf", ".txt", ".md", ".tex",
    # Spreadsheets & presentations
    ".xls", ".xlsx", ".ods", ".csv", ".tsv", ".ppt", ".pptx", ".odp",
    # Databases & data
    ".db", ".sqlite", ".sqlite3", ".sql", ".mdb", ".accdb", ".json", ".xml",
    # Source code & configs
    ".py", ".c", ".cpp", ".h", ".hpp", ".cs", ".java", ".go", ".rs", ".js", ".ts", ".php",
    # Images & multimedia
    ".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".psd", ".raw", ".svg",
    # Archives & backups
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bak", ".iso",
})

# Known ransomware and high-entropy encrypted file extension markers
KNOWN_RANSOMWARE_EXTENSIONS = frozenset({
    ".locked", ".crypto", ".crypt", ".crypted", ".enc", ".encrypted",
    ".ransom", ".wnry", ".dark", ".locky", ".cerber", ".zepto",
    ".thor", ".aes", ".vault", ".wallet", ".pay", ".payme",
    ".mole", ".crash", ".bleep", ".eking", ".makop", ".phobos",
    ".mallox", ".stop", ".djvu", ".coot", ".nesa", ".boot",
    ".harma", ".dharma", ".ryuk", ".conti", ".blackcat", ".alphv",
    ".lockbit", ".hive", ".babuk", ".medusa", ".play",
})


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
    pathId: int | None = None
    monitoredPath: str | None = None
    processName: str | None = None
    parentProcessId: int | None = None


@dataclass(frozen=True)
class FeatureSample:
    values: dict[str, float]
    observedAt: datetime
    schemaVersion: str = featureSchemaVersion


def getCurrentTime() -> datetime:
    return datetime.now(timezone.utc)
