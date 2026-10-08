"""Unit and Integration Tests for Sprint 3.2: Backup & Disaster Recovery Engine."""

import json
import os
import shutil
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Generator

import pandas as pd
import pytest

from app.domain.schemas import featureColumns
from app.models.modelRegistry import ModelRegistry
from app.operations.backupManager import (
    BackupFileEntry,
    BackupManager,
    BackupManifest,
    BackupResult,
    RestoreResult,
    calculateSha256,
)
from app.security.modelEncryption import ModelEncryption
from app.storage.sqliteStore import (
    initializeDatabase,
    recordDetectionFeedback,
    recordRetrainingRun,
)
from trainingModel.collection.syntheticData import generateAndSaveDataset
from trainingModel.training.trainModel import trainModel


@pytest.fixture
def backupEnvironment() -> Generator[dict, None, None]:
    """Create isolated sandbox for backup & disaster recovery testing."""
    tempDir = Path(tempfile.mkdtemp(prefix="backup_test_env_"))
    dbPath = tempDir / "database" / "detector.sqlite3"
    dbPath.parent.mkdir(parents=True, exist_ok=True)
    modelsDir = tempDir / "models"
    modelsDir.mkdir(parents=True, exist_ok=True)
    backupsDir = tempDir / "backups"
    backupsDir.mkdir(parents=True, exist_ok=True)
    configPath = tempDir / "settings.json"

    # 1. Initialize SQLite DB and populate seed records
    conn = initializeDatabase(dbPath)
    conn.execute("INSERT INTO sessions (startedAt) VALUES (datetime('now'))")
    sessionId = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO fileEvents (sessionId, occurredAt, action, pathHash, source) VALUES (?, datetime('now'), 'CREATED', 'hash123', 'watcher')",
        (sessionId,),
    )
    conn.execute(
        "INSERT INTO detections (sessionId, occurredAt, classification, riskScore, actionTaken) VALUES (?, datetime('now'), 'ransomwareLike', 0.95, 'alert')",
        (sessionId,),
    )
    conn.commit()
    conn.close()

    # 2. Train and activate an encrypted model artifact
    datasetPath = tempDir / "dataset.csv"
    generateAndSaveDataset(datasetPath, sampleCount=30, seed=42)
    candidatePath = tempDir / "candidate.joblib"
    trainModel(
        dataset=pd.read_csv(datasetPath),
        modelPath=candidatePath,
        encrypt=False,
        cvFolds=2,
        useScaler=True,
    )

    encryption = ModelEncryption()
    registry = ModelRegistry(modelsDirectory=modelsDir, databasePath=dbPath, encryption=encryption)
    activeModel = registry.activateModel(candidatePath, encrypt=True)

    # 3. Create dummy settings.json
    configPath.write_text(json.dumps({"version": "2.0.0", "sensitivity": "medium"}), encoding="utf-8")

    yield {
        "tempDir": tempDir,
        "dbPath": dbPath,
        "modelsDir": modelsDir,
        "backupsDir": backupsDir,
        "configPath": configPath,
        "activeModel": activeModel,
        "encryption": encryption,
    }

    shutil.rmtree(tempDir, ignore_errors=True)


class TestBackupDataStructures:
    """Test dataclasses, manifest serialization, and hashing."""

    def test_calculate_sha256(self, backupEnvironment: dict):
        env = backupEnvironment
        sha = calculateSha256(env["configPath"])
        assert len(sha) == 64
        assert int(sha, 16) > 0

    def test_manifest_serialization_roundtrip(self):
        manifest = BackupManifest(
            backupId="backup_20261008_120000",
            createdAt="2026-10-08T12:00:00Z",
            version="2.0.0",
            description="Test backup",
            files=[
                {"relativePath": "database/detector.sqlite3", "sha256": "abc123def456", "sizeBytes": 1024}
            ],
            databaseStats={"fileEvents": 10, "detections": 2},
            modelsCount=1,
            totalSizeBytes=1024,
        )

        asDict = manifest.toDict()
        reconstructed = BackupManifest.fromDict(asDict)
        assert reconstructed.backupId == manifest.backupId
        assert reconstructed.databaseStats["fileEvents"] == 10
        assert len(reconstructed.files) == 1


class TestBackupCreationAndIntegrity:
    """Test online database snapshots, archiving, and SHA-256 manifest generation."""

    def test_create_backup_success(self, backupEnvironment: dict):
        env = backupEnvironment
        manager = BackupManager(
            backupDirectory=env["backupsDir"],
            databasePath=env["dbPath"],
            modelsDirectory=env["modelsDir"],
            configPath=env["configPath"],
        )

        result = manager.createBackup(description="Initial test snapshot", includeModels=True)

        assert result.success is True
        assert result.backupPath is not None
        assert result.backupPath.is_file()
        assert result.manifest is not None
        assert result.manifest.modelsCount >= 1
        assert "fileEvents" in result.manifest.databaseStats
        assert result.manifest.databaseStats["fileEvents"] == 1

        # Check inside the zip archive
        with zipfile.ZipFile(result.backupPath, "r") as zf:
            namelist = zf.namelist()
            assert "manifest.json" in namelist
            assert "database/detector.sqlite3" in namelist
            assert "settings.json" in namelist
            assert any(n.startswith("models/") and n.endswith(".joblib") for n in namelist)

    def test_verify_backup_intact(self, backupEnvironment: dict):
        env = backupEnvironment
        manager = BackupManager(
            backupDirectory=env["backupsDir"],
            databasePath=env["dbPath"],
            modelsDirectory=env["modelsDir"],
            configPath=env["configPath"],
        )

        result = manager.createBackup(description="Verification test")
        assert result.success is True

        isValid, msg, manifest = manager.verifyBackup(result.backupPath)
        assert isValid is True
        assert "intact" in msg.lower() or "verified" in msg.lower()
        assert manifest is not None
        assert manifest.backupId == result.backupId

    def test_verify_backup_tampered_fails(self, backupEnvironment: dict):
        env = backupEnvironment
        manager = BackupManager(
            backupDirectory=env["backupsDir"],
            databasePath=env["dbPath"],
            modelsDirectory=env["modelsDir"],
            configPath=env["configPath"],
        )

        result = manager.createBackup(description="Tamper test")
        assert result.success is True

        # Unpack, corrupt database, repack
        tamperDir = Path(tempfile.mkdtemp())
        with zipfile.ZipFile(result.backupPath, "r") as zf:
            zf.extractall(tamperDir)

        dbFile = tamperDir / "database" / "detector.sqlite3"
        # Alter a byte in the database file
        data = bytearray(dbFile.read_bytes())
        data[25] = (data[25] + 1) % 256
        dbFile.write_bytes(bytes(data))

        # Re-pack into a tampered zip
        tamperedZip = env["backupsDir"] / "tampered_backup.zip"
        with zipfile.ZipFile(tamperedZip, "w") as zf:
            for item in tamperDir.rglob("*"):
                if item.is_file():
                    zf.write(item, item.relative_to(tamperDir).as_posix())
        shutil.rmtree(tamperDir, ignore_errors=True)

        isValid, msg, manifest = manager.verifyBackup(tamperedZip)
        assert isValid is False
        assert "mismatch" in msg.lower() or "corrupted" in msg.lower()


class TestBackupPruningAndRotation:
    """Test backup retention policy and automated pruning."""

    def test_backup_pruning_respects_limit(self, backupEnvironment: dict):
        env = backupEnvironment
        manager = BackupManager(
            backupDirectory=env["backupsDir"],
            databasePath=env["dbPath"],
            modelsDirectory=env["modelsDir"],
            configPath=env["configPath"],
            maxRetainedBackups=3,
        )

        # Create 5 backups with slight sleep to ensure distinct timestamps
        createdBackups = []
        for i in range(5):
            res = manager.createBackup(description=f"Snapshot {i}", autoPrune=False)
            assert res.success is True
            createdBackups.append(res.backupPath)
            time.sleep(1.05)

        assert len(list(env["backupsDir"].glob("backup_*.zip"))) == 5

        # Prune to keep 3
        pruned = manager.pruneBackups(maxRetained=3)
        assert len(pruned) == 2

        remaining = list(env["backupsDir"].glob("backup_*.zip"))
        assert len(remaining) == 3

    def test_list_backups_sorted_order(self, backupEnvironment: dict):
        env = backupEnvironment
        manager = BackupManager(
            backupDirectory=env["backupsDir"],
            databasePath=env["dbPath"],
            modelsDirectory=env["modelsDir"],
            configPath=env["configPath"],
        )

        for i in range(3):
            manager.createBackup(description=f"Backup #{i}", autoPrune=False)
            time.sleep(1.05)

        backupsList = manager.listBackups()
        assert len(backupsList) == 3
        # Should be sorted newest first
        assert backupsList[0]["description"] == "Backup #2"
        assert backupsList[-1]["description"] == "Backup #0"


class TestRestoreWorkflowAndSafetySnapshot:
    """Test complete restore flow, data integrity, and pre-restore rollback snapshotting."""

    def test_restore_recovers_database_and_models(self, backupEnvironment: dict):
        env = backupEnvironment
        manager = BackupManager(
            backupDirectory=env["backupsDir"],
            databasePath=env["dbPath"],
            modelsDirectory=env["modelsDir"],
            configPath=env["configPath"],
        )

        # 1. Create known-good backup with 1 session and 1 detection
        backupRes = manager.createBackup(description="Known good state")
        assert backupRes.success is True

        # 2. Mutate/corrupt state: Insert 10 new fake sessions and delete the model
        conn = sqlite3.connect(str(env["dbPath"]))
        for _ in range(10):
            conn.execute("INSERT INTO sessions (startedAt) VALUES (datetime('now'))")
        conn.commit()
        conn.close()

        for modelFile in env["modelsDir"].rglob("*.joblib"):
            modelFile.unlink()

        # Verify mutation occurred
        conn = sqlite3.connect(str(env["dbPath"]))
        count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        conn.close()
        assert count == 11
        assert len(list(env["modelsDir"].rglob("*.joblib"))) == 0

        # 3. Restore from known-good backup
        restoreRes = manager.restoreBackup(backupRes.backupPath, createSafetySnapshot=True)

        assert restoreRes.success is True
        assert restoreRes.preRestoreBackupPath is not None
        assert restoreRes.preRestoreBackupPath.is_file()

        # 4. Verify original state is restored
        conn = sqlite3.connect(str(env["dbPath"]))
        restoredCount = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        conn.close()
        assert restoredCount == 1

        restoredModels = list(env["modelsDir"].rglob("*.joblib"))
        assert len(restoredModels) >= 1
        assert ModelEncryption.isEncryptedFile(restoredModels[0])

    def test_restore_fails_on_corrupted_backup_without_altering_data(self, backupEnvironment: dict):
        env = backupEnvironment
        manager = BackupManager(
            backupDirectory=env["backupsDir"],
            databasePath=env["dbPath"],
            modelsDirectory=env["modelsDir"],
            configPath=env["configPath"],
        )

        # Create a bad zip file
        badZip = env["backupsDir"] / "corrupted_archive.zip"
        badZip.write_text("not a valid zip file", encoding="utf-8")

        restoreRes = manager.restoreBackup(badZip, createSafetySnapshot=False)
        assert restoreRes.success is False
        assert "verification failed" in restoreRes.errorMessage.lower()


class TestBackupCliIntegration:
    """Test CLI commands for scripts/backupCli.py."""

    def test_cli_create_and_list_backups(self, backupEnvironment: dict, capsys):
        from scripts.backupCli import main as backupCliMain
        env = backupEnvironment

        # Create backup via CLI
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "sys.argv",
                [
                    "backupCli.py",
                    "--create",
                    "--description",
                    "CLI Test Snapshot",
                    "--backup-dir",
                    str(env["backupsDir"]),
                ],
            )
            ret = backupCliMain()
            assert ret == 0

        # List backups via CLI (human readable)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "sys.argv",
                [
                    "backupCli.py",
                    "--list",
                    "--backup-dir",
                    str(env["backupsDir"]),
                ],
            )
            ret = backupCliMain()
            assert ret == 0
            captured = capsys.readouterr()
            assert "AVAILABLE SYSTEM BACKUPS" in captured.out
            assert "CLI Test Snapshot" in captured.out

        # List backups via CLI (JSON)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "sys.argv",
                [
                    "backupCli.py",
                    "--list",
                    "--json",
                    "--backup-dir",
                    str(env["backupsDir"]),
                ],
            )
            ret = backupCliMain()
            assert ret == 0
            captured = capsys.readouterr()
            parsed = json.loads(captured.out)
            assert len(parsed) >= 1
            assert parsed[0]["description"] == "CLI Test Snapshot"

    def test_cli_verify_backup(self, backupEnvironment: dict, capsys):
        from scripts.backupCli import main as backupCliMain
        env = backupEnvironment

        manager = BackupManager(
            backupDirectory=env["backupsDir"],
            databasePath=env["dbPath"],
            modelsDirectory=env["modelsDir"],
            configPath=env["configPath"],
        )
        res = manager.createBackup(description="For CLI Verify")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "sys.argv",
                [
                    "backupCli.py",
                    "--verify",
                    str(res.backupPath),
                    "--backup-dir",
                    str(env["backupsDir"]),
                ],
            )
            ret = backupCliMain()
            assert ret == 0
            captured = capsys.readouterr()
            assert "[OK] VERIFIED" in captured.out

    def test_cli_restore_force(self, backupEnvironment: dict, capsys):
        from scripts.backupCli import main as backupCliMain
        env = backupEnvironment

        manager = BackupManager(
            backupDirectory=env["backupsDir"],
            databasePath=env["dbPath"],
            modelsDirectory=env["modelsDir"],
            configPath=env["configPath"],
        )
        res = manager.createBackup(description="For CLI Restore")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "sys.argv",
                [
                    "backupCli.py",
                    "--restore",
                    str(res.backupPath),
                    "--force",
                    "--backup-dir",
                    str(env["backupsDir"]),
                ],
            )
            ret = backupCliMain()
            assert ret == 0
            captured = capsys.readouterr()
            assert "RESTORE COMPLETED SUCCESSFULLY" in captured.out
