"""Sprint 3.4 - Database Performance & Forensic Logging Test Suite.

Verifies:
1. Database schema enhancements (forensicSnapshots table, foreign keys, performance indexes, and migration).
2. Process attribution & lineage capture (ancestor tree recursion, open handles, memory/CPU telemetry, target file SHA-256).
3. Forensic snapshot persistence and retrieval (by detectionId, snapshotId, recent list, JSON, and ASCII console formatting).
4. DetectionController automated forensic capture integration on threat detection.
5. Automated data retention pruning (pruneOldData) with threat preservation and session cleanup.
6. SQLite database optimization (optimizeDatabase, PRAGMA optimize/analyze, WAL checkpointing, page statistics).
7. CLI commands for forensics inspection, database pruning, and optimization.
"""

import json
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil
import pytest

from app.domain.schemas import FileAction, FileEvent, getCurrentTime
from app.detection.riskEngine import RiskDecision, ThreatLevel
from app.forensics.forensicCollector import (
    ForensicCollector,
    ForensicSnapshot,
    ProcessInfo,
)
from app.logging.logger import closeLogging, setSessionId
from app.main import (
    performDatabaseOptimization,
    performDatabasePruning,
    showForensics,
)
from app.runtime.controller import DetectionController
from app.storage.sqliteStore import (
    closeDatabase,
    getDatabaseStatistics,
    initializeDatabase,
    migrateSchema,
    optimizeDatabase,
    pruneOldData,
)


@pytest.fixture(autouse=True)
def clean_environment():
    """Ensure clean logging context and closed database for each test."""
    setSessionId(None)
    closeLogging()
    closeDatabase()
    yield
    setSessionId(None)
    closeLogging()
    closeDatabase()


# ============================================================================
# Section 1: Database Schema & Migration for Forensics & Indexes
# ============================================================================

class TestDatabaseForensicsSchemaAndIndexes:
    """Test schema creation, indexes, and migration for forensic logging."""

    def test_database_has_forensic_snapshots_table(self):
        """initializeDatabase creates forensicSnapshots table with all required forensic columns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)

            cursor = conn.execute("PRAGMA table_info(forensicSnapshots)")
            columns = {row[1]: row[2] for row in cursor.fetchall()}

            expected_columns = [
                "snapshotId", "detectionId", "sessionId", "capturedAt",
                "processId", "processName", "parentProcessId", "processCommandLine",
                "processPath", "processUser", "processTreeJson", "openHandlesCount",
                "cpuPercent", "memoryRssMb", "monitoredPath", "targetFileHash",
                "targetFilePath", "featureSnapshotJson", "riskScore", "classification",
                "metadataJson"
            ]

            for col in expected_columns:
                assert col in columns, f"Column {col} missing from forensicSnapshots schema"
            conn.close()

    def test_performance_query_indexes_exist(self):
        """Verify performance query indexes are created across tables."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)

            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
            indexes = [row[0] for row in cursor.fetchall()]

            expected_indexes = [
                "fileEventsOccurredAtIndex",
                "fileEventsPathIdIndex",
                "fileEventsProcessIdIndex",
                "fileEventsProcessNameIndex",
                "fileEventsSessionOccurredIndex",
                "detectionsOccurredAtIndex",
                "detectionsRiskScoreIndex",
                "detectionsSessionIdIndex",
                "alertsOccurredAtIndex",
                "alertsSeverityIndex",
                "alertsDetectionIdIndex",
                "forensicSnapshotsDetectionIdIndex",
                "forensicSnapshotsCapturedAtIndex",
                "forensicSnapshotsProcessIdIndex",
                "forensicSnapshotsSessionIdIndex",
            ]

            for idx in expected_indexes:
                assert idx in indexes, f"Index {idx} missing from database"
            conn.close()

    def test_schema_migration_creates_forensic_snapshots_and_indexes(self):
        """migrateSchema upgrades a legacy database by creating forensicSnapshots table and indexes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "legacy.sqlite3"

            conn = sqlite3.connect(str(db_path))
            conn.execute(
                """
                CREATE TABLE fileEvents (
                    eventId INTEGER PRIMARY KEY,
                    sessionId INTEGER,
                    occurredAt TEXT NOT NULL,
                    action TEXT NOT NULL,
                    pathHash TEXT NOT NULL,
                    source TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE detections (
                    detectionId INTEGER PRIMARY KEY,
                    sessionId INTEGER,
                    occurredAt TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    riskScore REAL NOT NULL,
                    actionTaken TEXT NOT NULL
                );
                """
            )
            conn.commit()

            # Migrate
            migrateSchema(conn)
            conn.commit()

            # Verify forensicSnapshots table was created
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='forensicSnapshots'"
            )
            assert cursor.fetchone() is not None

            # Verify indexes were created
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='forensicSnapshotsDetectionIdIndex'"
            )
            assert cursor.fetchone() is not None
            conn.close()

    def test_get_database_statistics(self):
        """getDatabaseStatistics returns complete table row counts and diagnostic metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)

            stats = getDatabaseStatistics(conn)
            assert "tableCounts" in stats
            assert "fileEvents" in stats["tableCounts"]
            assert "forensicSnapshots" in stats["tableCounts"]
            assert "detections" in stats["tableCounts"]
            assert stats["indexCount"] > 5
            assert stats["databaseSizeBytes"] > 0
            conn.close()


# ============================================================================
# Section 2: Forensic Process Lineage & Evidence Collection
# ============================================================================

class TestForensicCollectorAndLineage:
    """Test process tree capture, file hashing, and snapshot serialization."""

    def test_capture_process_info_for_live_process(self):
        """captureProcessInfo extracts metadata from current live process."""
        collector = ForensicCollector()
        current_pid = os.getpid()

        info = collector.captureProcessInfo(current_pid)
        assert info.pid == current_pid
        assert isinstance(info.name, str)
        assert len(info.name) > 0
        assert info.memoryRssMb > 0
        assert isinstance(info.openHandles, int)
        assert info.createTime is not None

    def test_capture_process_info_for_terminated_or_invalid_pid(self):
        """captureProcessInfo handles nonexistent PIDs gracefully without throwing."""
        collector = ForensicCollector()
        info = collector.captureProcessInfo(99999999)
        assert info.pid == 99999999
        assert "terminated" in info.name or "unknown" in info.name

        info_none = collector.captureProcessInfo(None)
        assert info_none.pid == 0
        assert info_none.name == "unknown"

    def test_capture_process_tree_lineage_recursion(self):
        """captureProcessTree traverses parent processes and orders from root ancestor to target."""
        collector = ForensicCollector()
        current_pid = os.getpid()

        tree = collector.captureProcessTree(current_pid, maxDepth=4)
        assert isinstance(tree, list)
        assert len(tree) >= 1

        # Outermost ancestor should be first, current process should be last
        assert tree[-1]["pid"] == current_pid
        for p in tree:
            assert "pid" in p
            assert "name" in p

    def test_capture_file_hash_sha256(self):
        """captureFileHash computes exact SHA-256 hash of target file."""
        collector = ForensicCollector()
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = Path(tmpdir) / "evidence.txt"
            content = b"CRITICAL_RANSOMWARE_ENCRYPTED_ARTIFACT_CONTENT"
            sample_file.write_bytes(content)

            import hashlib
            expected_hash = hashlib.sha256(content).hexdigest()

            actual_hash = collector.captureFileHash(sample_file)
            assert actual_hash == expected_hash

            # Non-existent file returns None
            assert collector.captureFileHash(Path(tmpdir) / "missing.bin") is None

    def test_forensic_snapshot_formatting_console_and_json(self):
        """ForensicSnapshot formatConsoleReport and formatJson generate valid diagnostic summaries."""
        snapshot = ForensicSnapshot(
            snapshotId=42,
            detectionId=10,
            sessionId=2,
            capturedAt="2026-10-08T12:00:00Z",
            riskScore=0.92,
            classification="ransomwareLike",
            processId=1234,
            processName="malware.exe",
            parentProcessId=5678,
            processCommandLine="malware.exe -encrypt C:\\Data",
            processPath="C:\\Windows\\Temp\\malware.exe",
            processUser="DOMAIN\\CompromisedUser",
            processTree=[
                {"pid": 100, "name": "explorer.exe", "exePath": "C:\\Windows\\explorer.exe"},
                {"pid": 5678, "name": "powershell.exe", "exePath": "C:\\Windows\\System32\\powershell.exe"},
                {"pid": 1234, "name": "malware.exe", "exePath": "C:\\Windows\\Temp\\malware.exe"},
            ],
            openHandlesCount=45,
            cpuPercent=85.5,
            memoryRssMb=120.4,
            monitoredPath="C:\\Users\\Victim\\Documents",
            targetFileHash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            targetFilePath="C:\\Users\\Victim\\Documents\\finances.xlsx.locked",
            featureSnapshot={
                "filesModifiedPerMinute": 450.0,
                "highEntropyRatio": 0.95,
                "suspiciousExtensionCount": 35.0,
            },
            metadata={"networkConnections": 3},
        )

        console_report = snapshot.formatConsoleReport()
        assert "FORENSIC INVESTIGATION REPORT" in console_report
        assert "Snapshot ID:       42" in console_report
        assert "malware.exe" in console_report
        assert "explorer.exe" in console_report
        assert "finances.xlsx.locked" in console_report

        json_str = snapshot.formatJson()
        parsed = json.loads(json_str)
        assert parsed["snapshotId"] == 42
        assert parsed["riskScore"] == 0.92
        assert parsed["classification"] == "ransomwareLike"
        assert len(parsed["processTree"]) == 3


# ============================================================================
# Section 3: Database Persistence & Forensics Retrieval
# ============================================================================

class TestForensicDatabasePersistence:
    """Test saving and retrieving forensic snapshots in SQLite."""

    def test_save_and_retrieve_snapshot_by_detection_id(self):
        """ForensicCollector saves snapshot and retrieves it by detectionId."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)
            collector = ForensicCollector()

            # Insert dummy session and detection
            conn.execute("INSERT INTO sessions (startedAt) VALUES (datetime('now'))")
            conn.execute(
                "INSERT INTO detections (sessionId, occurredAt, classification, riskScore, actionTaken) VALUES (1, datetime('now'), 'ransomwareLike', 0.95, 'quarantined')"
            )
            conn.commit()

            decision = RiskDecision(
                level=ThreatLevel.critical,
                score=0.95,
                classification="ransomwareLike",
                action="quarantined",
            )

            snapshot = collector.collectSnapshot(
                decision=decision,
                processId=os.getpid(),
                processName="pytest.exe",
                targetFilePath=str(Path(tmpdir) / "dummy.txt"),
                monitoredPath=str(tmpdir),
                featureValues={"filesModifiedPerMinute": 300.0, "highEntropyRatio": 0.88},
                detectionId=1,
                sessionId=1,
                metadata={"testKey": "testValue"},
            )

            snapshot_id = collector.saveSnapshot(conn, snapshot)
            conn.commit()

            assert snapshot_id > 0
            assert snapshot.snapshotId == snapshot_id

            # Retrieve by detectionId
            retrieved = collector.getSnapshotByDetectionId(conn, detectionId=1)
            assert retrieved is not None
            assert retrieved.snapshotId == snapshot_id
            assert retrieved.detectionId == 1
            assert retrieved.riskScore == 0.95
            assert retrieved.classification == "ransomwareLike"
            assert retrieved.processId == os.getpid()
            assert retrieved.featureSnapshot["filesModifiedPerMinute"] == 300.0
            assert retrieved.metadata["testKey"] == "testValue"

            conn.close()

    def test_save_and_retrieve_snapshot_by_snapshot_id(self):
        """ForensicCollector retrieves snapshot by its primary snapshotId."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)
            collector = ForensicCollector()

            conn.execute("INSERT INTO sessions (startedAt) VALUES (datetime('now'))")
            conn.execute(
                "INSERT INTO detections (sessionId, occurredAt, classification, riskScore, actionTaken) VALUES (1, datetime('now'), 'suspiciousActivity', 0.70, 'alert')"
            )
            conn.commit()

            decision = RiskDecision(
                level=ThreatLevel.high,
                score=0.70,
                classification="suspiciousActivity",
                action="alert",
            )

            snapshot = collector.collectSnapshot(
                decision=decision,
                processId=1000,
                processName="powershell.exe",
                detectionId=1,
                sessionId=1,
            )

            snapshot_id = collector.saveSnapshot(conn, snapshot)
            conn.commit()

            retrieved = collector.getSnapshotById(conn, snapshot_id)
            assert retrieved is not None
            assert retrieved.snapshotId == snapshot_id
            assert retrieved.processName == "powershell.exe"

            # Nonexistent snapshot returns None
            assert collector.getSnapshotById(conn, 99999) is None
            conn.close()

    def test_get_recent_snapshots_ordered(self):
        """getRecentSnapshots fetches recent snapshots ordered newest first."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)
            collector = ForensicCollector()

            conn.execute("INSERT INTO sessions (startedAt) VALUES (datetime('now'))")
            conn.commit()

            for i in range(5):
                decision = RiskDecision(
                    level=ThreatLevel.high,
                    score=0.60 + (i * 0.05),
                    classification=f"threat_{i}",
                    action="alert",
                )
                snap = collector.collectSnapshot(
                    decision=decision,
                    processId=2000 + i,
                    processName=f"proc_{i}.exe",
                    sessionId=1,
                )
                collector.saveSnapshot(conn, snap)

            conn.commit()

            recent = collector.getRecentSnapshots(conn, limit=3)
            assert len(recent) == 3
            # Ordered newest first
            assert recent[0].classification == "threat_4"
            assert recent[1].classification == "threat_3"
            assert recent[2].classification == "threat_2"
            conn.close()


# ============================================================================
# Section 4: DetectionController Automated Forensic Capture
# ============================================================================

class TestControllerForensicIntegration:
    """Test automated forensic evidence collection inside DetectionController."""

    def test_controller_captures_forensic_snapshot_on_threat_detection(self):
        """When controller evaluates a non-low threat, a forensic snapshot is automatically saved."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitored_dir = Path(tmpdir) / "watch"
            monitored_dir.mkdir()
            db_path = Path(tmpdir) / "db.sqlite3"

            with DetectionController(monitoredPaths=[monitored_dir], databasePath=db_path) as controller:
                # Inject a burst of high-threat ransomware activity
                for i in range(15):
                    target = monitored_dir / f"doc_{i}.locked"
                    event = FileEvent(
                        occurredAt=getCurrentTime(),
                        action=FileAction.created,
                        path=str(target),
                        source="windows",
                        pathId=1,
                        processId=os.getpid(),
                        processName="ransom_sim.exe",
                        monitoredPath=str(monitored_dir),
                    )
                    controller.featureWindow.addEvents([event])

                decision = controller.collectOnce()
                assert decision.level != ThreatLevel.low

                # Verify snapshot persisted in database
                collector = ForensicCollector()
                snapshots = collector.getRecentSnapshots(controller.connection)
                assert len(snapshots) >= 1

                latest_snap = snapshots[0]
                assert latest_snap.classification == decision.classification
                assert latest_snap.processId == os.getpid()
                assert latest_snap.processName == "ransom_sim.exe"
                assert len(latest_snap.processTree) >= 1
                assert "filesModifiedPerMinute" in latest_snap.featureSnapshot

    def test_controller_benign_activity_does_not_create_forensic_snapshots(self):
        """When controller processes low-threat benign activity, no forensic snapshots are created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitored_dir = Path(tmpdir) / "watch_benign"
            monitored_dir.mkdir()
            db_path = Path(tmpdir) / "db.sqlite3"

            with DetectionController(monitoredPaths=[monitored_dir], databasePath=db_path) as controller:
                decision = controller.collectOnce()
                assert decision.level == ThreatLevel.low

                collector = ForensicCollector()
                snapshots = collector.getRecentSnapshots(controller.connection)
                assert len(snapshots) == 0


# ============================================================================
# Section 5: Data Retention Pruning & Database Optimization
# ============================================================================

class TestDataRetentionAndOptimization:
    """Test automated pruning and SQLite optimization routines."""

    def test_prune_old_data_removes_old_benign_records(self):
        """pruneOldData purges records older than cutoff while preserving active threats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)

            old_time = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
            recent_time = datetime.now(timezone.utc).isoformat()

            # Insert old and recent sessions
            conn.execute("INSERT INTO sessions (sessionId, startedAt, endedAt) VALUES (1, ?, ?)", (old_time, old_time))
            conn.execute("INSERT INTO sessions (sessionId, startedAt, endedAt) VALUES (2, ?, ?)", (recent_time, None))

            # Insert old and recent file events
            conn.execute(
                "INSERT INTO fileEvents (sessionId, occurredAt, action, pathHash, source) VALUES (1, ?, 'created', 'hash1', 'test')",
                (old_time,),
            )
            conn.execute(
                "INSERT INTO fileEvents (sessionId, occurredAt, action, pathHash, source) VALUES (2, ?, 'modified', 'hash2', 'test')",
                (recent_time,),
            )

            # Insert old and recent metric samples
            conn.execute(
                "INSERT INTO metricSamples (sessionId, occurredAt, schemaVersion, valuesJson) VALUES (1, ?, '1.0', '{}')",
                (old_time,),
            )
            conn.execute(
                "INSERT INTO metricSamples (sessionId, occurredAt, schemaVersion, valuesJson) VALUES (2, ?, '1.0', '{}')",
                (recent_time,),
            )
            conn.commit()

            # Verify 2 events before prune
            assert conn.execute("SELECT COUNT(*) FROM fileEvents").fetchone()[0] == 2
            assert conn.execute("SELECT COUNT(*) FROM metricSamples").fetchone()[0] == 2

            # Prune records older than 30 days
            counts = pruneOldData(conn, retentionDays=30, preserveThreats=True)
            assert counts["fileEvents"] == 1
            assert counts["metricSamples"] == 1
            assert counts["sessions"] == 1

            # Verify remaining events
            assert conn.execute("SELECT COUNT(*) FROM fileEvents").fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM metricSamples").fetchone()[0] == 1
            conn.close()

    def test_optimize_database_wal_checkpoint_and_vacuum(self):
        """optimizeDatabase executes PRAGMA optimize, analyze, and returns page stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)

            # Insert dummy data to populate pages
            for i in range(50):
                conn.execute(
                    "INSERT INTO fileEvents (occurredAt, action, pathHash, source) VALUES (datetime('now'), 'modified', 'hash', 'test')"
                )
            conn.commit()

            stats = optimizeDatabase(conn)
            assert stats["status"] == "optimized"
            assert stats["pageSizeBytes"] > 0
            assert stats["pageCount"] > 0
            assert stats["totalSizeBytes"] > 0
            assert "walCheckpoint" in stats
            conn.close()


# ============================================================================
# Section 6: CLI Forensic & Database Maintenance Endpoints
# ============================================================================

class TestCLIForensicEndpoints:
    """Test CLI commands for forensics display, database pruning, and optimization."""

    def test_cli_show_forensics_list(self, capsys):
        """showForensics displays formatted table of recent snapshots."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)
            collector = ForensicCollector()

            conn.execute("INSERT INTO sessions (startedAt) VALUES (datetime('now'))")
            conn.commit()

            snap = collector.collectSnapshot(
                decision=RiskDecision(level=ThreatLevel.critical, score=0.95, classification="ransomwareLike", action="quarantined"),
                processId=1234,
                processName="attacker.exe",
                sessionId=1,
            )
            collector.saveSnapshot(conn, snap)
            conn.commit()
            conn.close()
            closeDatabase()

            exit_code = showForensics(db_path, jsonOutput=False)
            assert exit_code == 0

            captured = capsys.readouterr()
            assert "FORENSIC EVIDENCE SNAPSHOTS" in captured.out
            assert "attacker.exe" in captured.out
            assert "RANSOMWARELIKE" in captured.out

    def test_cli_show_forensics_detail_by_id(self, capsys):
        """showForensics with snapshotId displays detailed forensic investigation report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)
            collector = ForensicCollector()

            conn.execute("INSERT INTO sessions (startedAt) VALUES (datetime('now'))")
            conn.commit()

            snap = collector.collectSnapshot(
                decision=RiskDecision(level=ThreatLevel.critical, score=0.98, classification="ransomwareLike", action="quarantined"),
                processId=4321,
                processName="payload.exe",
                sessionId=1,
            )
            snap_id = collector.saveSnapshot(conn, snap)
            conn.commit()
            conn.close()
            closeDatabase()

            exit_code = showForensics(db_path, snapshotId=snap_id, jsonOutput=False)
            assert exit_code == 0

            captured = capsys.readouterr()
            assert "FORENSIC INVESTIGATION REPORT" in captured.out
            assert f"Snapshot ID:       {snap_id}" in captured.out
            assert "payload.exe" in captured.out

    def test_cli_perform_database_pruning(self, capsys):
        """performDatabasePruning executes retention purge and prints summary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            initializeDatabase(db_path).close()

            exit_code = performDatabasePruning(db_path, days=15, jsonOutput=False)
            assert exit_code == 0

            captured = capsys.readouterr()
            assert "Database Retention Pruning" in captured.out
            assert "fileEvents" in captured.out

    def test_cli_perform_database_optimization(self, capsys):
        """performDatabaseOptimization executes database optimization and prints metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            initializeDatabase(db_path).close()

            exit_code = performDatabaseOptimization(db_path, jsonOutput=False)
            assert exit_code == 0

            captured = capsys.readouterr()
            assert "Database Optimization & Index Analysis Complete" in captured.out
            assert "Total DB Size" in captured.out


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
