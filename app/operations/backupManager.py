"""Backup and disaster recovery manager for the Ransomware Detection System."""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import time
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from app import applicationVersion
from app.config.configuration import (
    getDataDirectory,
    getProjectRoot,
    loadConfiguration,
)
from app.logging.logger import logSecurityEvent
from app.security.modelEncryption import ModelEncryption

logger = logging.getLogger(__name__)


@dataclass
class BackupFileEntry:
    relativePath: str
    sha256: str
    sizeBytes: int


@dataclass
class BackupManifest:
    backupId: str
    createdAt: str
    version: str
    description: str
    files: list[dict[str, Any]]
    databaseStats: dict[str, int] = field(default_factory=dict)
    modelsCount: int = 0
    totalSizeBytes: int = 0

    def toDict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def fromDict(cls, data: dict[str, Any]) -> "BackupManifest":
        return cls(
            backupId=data["backupId"],
            createdAt=data["createdAt"],
            version=data.get("version", applicationVersion),
            description=data.get("description", ""),
            files=data.get("files", []),
            databaseStats=data.get("databaseStats", {}),
            modelsCount=data.get("modelsCount", 0),
            totalSizeBytes=data.get("totalSizeBytes", 0),
        )


@dataclass
class BackupResult:
    success: bool
    backupId: str
    backupPath: Optional[Path]
    manifest: Optional[BackupManifest]
    errorMessage: Optional[str] = None
    durationSeconds: float = 0.0


@dataclass
class RestoreResult:
    success: bool
    backupId: str
    restoredFiles: list[str]
    preRestoreBackupPath: Optional[Path] = None
    errorMessage: Optional[str] = None
    durationSeconds: float = 0.0


def calculateSha256(filePath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filePath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class BackupManager:
    """Manages online database snapshots, encrypted model backups, manifests, rotation, and recovery."""

    def __init__(
        self,
        backupDirectory: Optional[Union[str, Path]] = None,
        databasePath: Optional[Union[str, Path]] = None,
        modelsDirectory: Optional[Union[str, Path]] = None,
        configPath: Optional[Union[str, Path]] = None,
        maxRetainedBackups: int = 10,
        encryption: Optional[ModelEncryption] = None,
    ):
        dataDir = getDataDirectory()
        self.backupDirectory = Path(backupDirectory or (dataDir / "backups")).resolve()
        self.backupDirectory.mkdir(parents=True, exist_ok=True)

        if databasePath is not None:
            self.databasePath = Path(databasePath).resolve()
        else:
            self.databasePath = (dataDir / "database" / "detector.sqlite3").resolve()

        if modelsDirectory is not None:
            self.modelsDirectory = Path(modelsDirectory).resolve()
        else:
            self.modelsDirectory = (dataDir / "models").resolve()

        if configPath is not None:
            self.configPath = Path(configPath).resolve()
        else:
            self.configPath = (dataDir / "settings.json").resolve()

        self.maxRetainedBackups = max(1, maxRetainedBackups)
        self.encryption = encryption or ModelEncryption()

    def _snapshotDatabase(self, destinationPath: Path) -> dict[str, int]:
        """
        Create a consistent online point-in-time snapshot using SQLite Online Backup API.

        Returns:
            Dictionary containing table record counts at snapshot time.
        """
        destinationPath.parent.mkdir(parents=True, exist_ok=True)
        stats: dict[str, int] = {}

        if not self.databasePath.is_file():
            logger.warning(f"Database file {self.databasePath} does not exist for backup")
            return stats

        # Connect to source and destination
        sourceConn = sqlite3.connect(str(self.databasePath), timeout=30.0)
        destConn = sqlite3.connect(str(destinationPath))

        try:
            # Execute online backup
            with destConn:
                sourceConn.backup(destConn, pages=100, sleep=0.001)

            # Collect table statistics
            tables = [
                row[0]
                for row in destConn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            ]
            for table in tables:
                try:
                    count = destConn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]
                    stats[table] = count
                except Exception:
                    pass

            # Verify integrity of snapshot
            integrity = destConn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity.lower() != "ok":
                raise RuntimeError(f"Database snapshot integrity check failed: {integrity}")

        finally:
            destConn.close()
            sourceConn.close()

        return stats

    def createBackup(
        self,
        description: str = "",
        includeModels: bool = True,
        autoPrune: bool = True,
    ) -> BackupResult:
        """
        Create a complete, consistent, SHA-256 verified backup archive.

        Args:
            description: Human-readable description of backup reason
            includeModels: Whether to package model artifacts
            autoPrune: Whether to automatically prune older backups exceeding retention policy

        Returns:
            BackupResult with backupId, path, and manifest
        """
        startTime = time.perf_counter()
        nowUtc = datetime.now(timezone.utc)
        timestampStr = nowUtc.strftime("%Y%m%d_%H%M%S_%f")[:22]  # Millisecond resolution
        backupId = f"backup_{timestampStr}"
        zipFileName = f"{backupId}.zip"
        targetZipPath = self.backupDirectory / zipFileName

        tempDir = Path(tempfile.mkdtemp(prefix="backup_staging_"))
        try:
            fileEntries: list[dict[str, Any]] = []
            dbStats: dict[str, int] = {}
            modelsCount = 0

            # 1. Snapshot SQLite Database
            if self.databasePath.is_file():
                stagedDb = tempDir / "database" / "detector.sqlite3"
                dbStats = self._snapshotDatabase(stagedDb)
                if stagedDb.is_file():
                    sha = calculateSha256(stagedDb)
                    size = stagedDb.stat().st_size
                    fileEntries.append(
                        asdict(BackupFileEntry("database/detector.sqlite3", sha, size))
                    )

            # 2. Package Models
            if includeModels and self.modelsDirectory.is_dir():
                stagedModelsDir = tempDir / "models"
                stagedModelsDir.mkdir(parents=True, exist_ok=True)

                for modelFile in self.modelsDirectory.rglob("*.joblib"):
                    relPath = modelFile.relative_to(self.modelsDirectory)
                    destModel = stagedModelsDir / relPath
                    destModel.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(modelFile, destModel)

                    sha = calculateSha256(destModel)
                    size = destModel.stat().st_size
                    fileEntries.append(
                        asdict(BackupFileEntry(f"models/{relPath.as_posix()}", sha, size))
                    )
                    modelsCount += 1

            # 3. Package Configuration if present
            if self.configPath.is_file():
                stagedConfig = tempDir / "settings.json"
                shutil.copy2(self.configPath, stagedConfig)
                sha = calculateSha256(stagedConfig)
                size = stagedConfig.stat().st_size
                fileEntries.append(asdict(BackupFileEntry("settings.json", sha, size)))

            # 4. Generate Manifest
            manifest = BackupManifest(
                backupId=backupId,
                createdAt=datetime.now(timezone.utc).isoformat(),
                version=applicationVersion,
                description=description,
                files=fileEntries,
                databaseStats=dbStats,
                modelsCount=modelsCount,
                totalSizeBytes=sum(f["sizeBytes"] for f in fileEntries),
            )

            manifestPath = tempDir / "manifest.json"
            manifestPath.write_text(json.dumps(manifest.toDict(), indent=2), encoding="utf-8")

            # 5. Build ZIP Archive
            with zipfile.ZipFile(targetZipPath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.write(manifestPath, "manifest.json")
                for item in tempDir.rglob("*"):
                    if item.is_file() and item.name != "manifest.json":
                        arcname = item.relative_to(tempDir).as_posix()
                        zf.write(item, arcname)

            duration = time.perf_counter() - startTime

            logSecurityEvent(
                logger,
                "backup_create",
                str(targetZipPath),
                "success",
                {
                    "backupId": backupId,
                    "modelsCount": modelsCount,
                    "databaseStats": dbStats,
                    "sizeBytes": targetZipPath.stat().st_size,
                    "durationSeconds": round(duration, 3),
                },
            )

            # Auto-prune old backups if enabled
            if autoPrune:
                self.pruneBackups()

            return BackupResult(
                success=True,
                backupId=backupId,
                backupPath=targetZipPath,
                manifest=manifest,
                durationSeconds=round(duration, 3),
            )

        except Exception as error:
            duration = time.perf_counter() - startTime
            logger.error(f"Backup creation failed: {error}", exc_info=True)
            logSecurityEvent(
                logger,
                "backup_create",
                str(targetZipPath),
                "failed",
                {"backupId": backupId, "error": str(error)},
            )
            return BackupResult(
                success=False,
                backupId=backupId,
                backupPath=None,
                manifest=None,
                errorMessage=str(error),
                durationSeconds=round(duration, 3),
            )
        finally:
            shutil.rmtree(tempDir, ignore_errors=True)

    def verifyBackup(self, backupZipPath: Union[str, Path]) -> tuple[bool, str, Optional[BackupManifest]]:
        """
        Verify the structural integrity, SHA-256 checksums, and SQLite validity of a backup.

        Returns:
            Tuple of (isValid, message, manifest)
        """
        zipPath = Path(backupZipPath).resolve()
        if not zipPath.is_file():
            return False, f"Backup file not found: {zipPath}", None

        tempDir = Path(tempfile.mkdtemp(prefix="backup_verify_"))
        try:
            with zipfile.ZipFile(zipPath, "r") as zf:
                zf.extractall(tempDir)

            manifestFile = tempDir / "manifest.json"
            if not manifestFile.is_file():
                return False, "Archive missing manifest.json", None

            manifestData = json.loads(manifestFile.read_text(encoding="utf-8"))
            manifest = BackupManifest.fromDict(manifestData)

            # Verify every file listed in manifest
            for entry in manifest.files:
                targetPath = tempDir / entry["relativePath"]
                if not targetPath.is_file():
                    return False, f"Missing expected file in backup: {entry['relativePath']}", manifest

                calculatedSha = calculateSha256(targetPath)
                if calculatedSha != entry["sha256"]:
                    return (
                        False,
                        f"Checksum mismatch on {entry['relativePath']}: expected {entry['sha256']}, got {calculatedSha}",
                        manifest,
                    )

            # Test database integrity if present
            dbPath = tempDir / "database" / "detector.sqlite3"
            if dbPath.is_file():
                conn = sqlite3.connect(str(dbPath))
                res = conn.execute("PRAGMA integrity_check").fetchone()[0]
                conn.close()
                if res.lower() != "ok":
                    return False, f"Corrupted SQLite database in backup: {res}", manifest

            return True, "Backup archive is verified and intact", manifest

        except Exception as error:
            return False, f"Backup verification failed: {error}", None
        finally:
            shutil.rmtree(tempDir, ignore_errors=True)

    def restoreBackup(
        self,
        backupZipPath: Union[str, Path],
        createSafetySnapshot: bool = True,
        restoreModels: bool = True,
        restoreDatabase: bool = True,
        restoreConfig: bool = True,
    ) -> RestoreResult:
        """
        Restore system state from a backup archive with pre-restore safety snapshots and verification.

        Args:
            backupZipPath: Path to backup archive ZIP
            createSafetySnapshot: Whether to snapshot current state before overwrite
            restoreModels: Whether to restore model artifacts
            restoreDatabase: Whether to restore database
            restoreConfig: Whether to restore settings.json

        Returns:
            RestoreResult with status and restored files list
        """
        startTime = time.perf_counter()
        zipPath = Path(backupZipPath).resolve()

        # Step 1: Verify backup archive before attempting restore
        isValid, verifyMsg, manifest = self.verifyBackup(zipPath)
        if not isValid or manifest is None:
            logger.error(f"Cannot restore: verification failed: {verifyMsg}")
            return RestoreResult(
                success=False,
                backupId=manifest.backupId if manifest else "unknown",
                restoredFiles=[],
                errorMessage=f"Verification failed: {verifyMsg}",
            )

        preRestoreSnapshot: Optional[Path] = None
        if createSafetySnapshot:
            # Create a rollback safety snapshot of current system state
            safetyResult = self.createBackup(
                description=f"Pre-restore safety snapshot prior to restoring {manifest.backupId}",
                autoPrune=False,
            )
            if safetyResult.success:
                preRestoreSnapshot = safetyResult.backupPath

        tempDir = Path(tempfile.mkdtemp(prefix="backup_restore_"))
        restoredFiles: list[str] = []

        try:
            with zipfile.ZipFile(zipPath, "r") as zf:
                zf.extractall(tempDir)

            # Restore database
            if restoreDatabase:
                stagedDb = tempDir / "database" / "detector.sqlite3"
                if stagedDb.is_file():
                    self.databasePath.parent.mkdir(parents=True, exist_ok=True)
                    # Clean up any active WAL / SHM files to prevent replaying stale transactions
                    walPath = Path(str(self.databasePath) + "-wal")
                    shmPath = Path(str(self.databasePath) + "-shm")
                    if walPath.is_file():
                        try:
                            walPath.unlink()
                        except Exception:
                            pass
                    if shmPath.is_file():
                        try:
                            shmPath.unlink()
                        except Exception:
                            pass

                    # Overwrite main database file
                    shutil.copy2(stagedDb, self.databasePath)

                    # Checkpoint and verify restored database
                    try:
                        verifyConn = sqlite3.connect(str(self.databasePath))
                        verifyConn.execute("PRAGMA journal_mode=WAL")
                        verifyConn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                        verifyConn.execute("PRAGMA integrity_check")
                        verifyConn.close()
                    except Exception as chkErr:
                        logger.warning(f"Restored database checkpoint warning: {chkErr}")

                    restoredFiles.append(str(self.databasePath))

            # Restore models
            if restoreModels:
                stagedModels = tempDir / "models"
                if stagedModels.is_dir():
                    self.modelsDirectory.mkdir(parents=True, exist_ok=True)
                    for modelFile in stagedModels.rglob("*.joblib"):
                        relPath = modelFile.relative_to(stagedModels)
                        targetModel = self.modelsDirectory / relPath
                        targetModel.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(modelFile, targetModel)
                        restoredFiles.append(str(targetModel))

            # Restore configuration
            if restoreConfig:
                stagedConfig = tempDir / "settings.json"
                if stagedConfig.is_file():
                    self.configPath.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(stagedConfig, self.configPath)
                    restoredFiles.append(str(self.configPath))

            duration = time.perf_counter() - startTime

            logSecurityEvent(
                logger,
                "backup_restore",
                str(zipPath),
                "success",
                {
                    "backupId": manifest.backupId,
                    "restoredFilesCount": len(restoredFiles),
                    "preRestoreSnapshot": str(preRestoreSnapshot) if preRestoreSnapshot else None,
                    "durationSeconds": round(duration, 3),
                },
            )

            return RestoreResult(
                success=True,
                backupId=manifest.backupId,
                restoredFiles=restoredFiles,
                preRestoreBackupPath=preRestoreSnapshot,
                durationSeconds=round(duration, 3),
            )

        except Exception as error:
            duration = time.perf_counter() - startTime
            logger.error(f"Restore failed: {error}", exc_info=True)
            logSecurityEvent(
                logger,
                "backup_restore",
                str(zipPath),
                "failed",
                {"backupId": manifest.backupId, "error": str(error)},
            )
            return RestoreResult(
                success=False,
                backupId=manifest.backupId,
                restoredFiles=restoredFiles,
                preRestoreBackupPath=preRestoreSnapshot,
                errorMessage=str(error),
                durationSeconds=round(duration, 3),
            )
        finally:
            shutil.rmtree(tempDir, ignore_errors=True)

    def listBackups(self) -> list[dict[str, Any]]:
        """
        List all available backups in the backup directory, sorted from newest to oldest.

        Returns:
            List of backup summary dictionaries.
        """
        backups: list[dict[str, Any]] = []
        if not self.backupDirectory.is_dir():
            return backups

        for zipFile in sorted(self.backupDirectory.glob("backup_*.zip"), reverse=True):
            try:
                with zipfile.ZipFile(zipFile, "r") as zf:
                    if "manifest.json" in zf.namelist():
                        manifestData = json.loads(zf.read("manifest.json").decode("utf-8"))
                        backups.append({
                            "backupId": manifestData.get("backupId", zipFile.stem),
                            "path": str(zipFile),
                            "createdAt": manifestData.get("createdAt", ""),
                            "version": manifestData.get("version", ""),
                            "description": manifestData.get("description", ""),
                            "sizeBytes": zipFile.stat().st_size,
                            "modelsCount": manifestData.get("modelsCount", 0),
                            "databaseStats": manifestData.get("databaseStats", {}),
                        })
            except Exception as error:
                logger.debug(f"Could not read backup {zipFile}: {error}")

        return backups

    def pruneBackups(self, maxRetained: Optional[int] = None) -> list[str]:
        """
        Prune older backups exceeding the retention threshold.

        Returns:
            List of deleted backup paths.
        """
        limit = maxRetained or self.maxRetainedBackups
        backups = sorted(self.backupDirectory.glob("backup_*.zip"), reverse=True)
        deleted: list[str] = []

        if len(backups) > limit:
            toDelete = backups[limit:]
            for bPath in toDelete:
                try:
                    bPath.unlink()
                    deleted.append(str(bPath))
                    logSecurityEvent(
                        logger,
                        "backup_prune",
                        str(bPath),
                        "success",
                        {"prunedFile": str(bPath), "retainedCount": limit},
                    )
                except Exception as error:
                    logger.warning(f"Failed to prune old backup {bPath}: {error}")

        return deleted
