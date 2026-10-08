"""Sprint 2.1 - Multi-Path Monitoring Support Test Suite.

Verifies:
1. Database schema enhancements (monitoredPaths table, pathId foreign key in fileEvents, indexes, and schema migration).
2. Event sources multi-path tracking with pathId and monitoredPath metadata.
3. DetectionController multi-path collection, path registry, and combined feature aggregation.
4. MonitoringWorker background multi-path orchestration and resource cleanup.
5. Backward compatibility with single-path initialization.
6. CLI and configuration multi-path validation and execution.
"""

import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.config.configuration import (
    ConfigurationError,
    loadConfiguration,
    resolveMonitoringPath,
    resolveMonitoringPaths,
)
from app.domain.schemas import FileAction, FileEvent, getCurrentTime
from app.features.windowing import FeatureWindow
from app.logging.logger import closeLogging, setSessionId
from app.main import performScan, showDetailedStatus
from app.monitoring.fileEvents import PollingFileEventSource, compareSnapshots
from app.runtime.controller import DetectionController
from app.runtime.genericWorker import MonitoringWorker
from app.storage.connectionPool import ConnectionPool
from app.storage.sqliteStore import (
    closeDatabase,
    getAllMonitoredPaths,
    getMonitoredPathId,
    initializeDatabase,
    migrateSchema,
    registerMonitoredPath,
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
# Section 1: Database Schema & Migration for Multi-Path Monitoring
# ============================================================================

class TestDatabaseMultiPathSchema:
    """Test database schema support for monitoredPaths and fileEvents.pathId."""

    def test_database_has_monitored_paths_table(self):
        """initializeDatabase creates monitoredPaths table with correct schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)

            cursor = conn.execute("PRAGMA table_info(monitoredPaths)")
            columns = {row[1]: row[2] for row in cursor.fetchall()}

            assert "pathId" in columns
            assert "path" in columns
            assert "enabled" in columns
            assert "createdAt" in columns
            conn.close()

    def test_file_events_has_path_id_column_and_index(self):
        """fileEvents table contains pathId column and fileEventsPathIdIndex index."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)

            cursor = conn.execute("PRAGMA table_info(fileEvents)")
            columns = [row[1] for row in cursor.fetchall()]
            assert "pathId" in columns

            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='fileEvents'"
            )
            indexes = [row[0] for row in cursor.fetchall()]
            assert "fileEventsPathIdIndex" in indexes
            conn.close()

    def test_schema_migration_adds_path_id_to_legacy_db(self):
        """migrateSchema automatically upgrades legacy schema missing pathId column."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "legacy.sqlite3"

            # Create legacy database without pathId in fileEvents
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
                CREATE TABLE monitoredPaths (
                    pathId INTEGER PRIMARY KEY,
                    path TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    createdAt TEXT NOT NULL
                );
                """
            )
            conn.commit()

            # Verify pathId missing initially
            cursor = conn.execute("PRAGMA table_info(fileEvents)")
            assert "pathId" not in [row[1] for row in cursor.fetchall()]

            # Run migration
            migrateSchema(conn)
            conn.commit()

            # Verify pathId added
            cursor = conn.execute("PRAGMA table_info(fileEvents)")
            assert "pathId" in [row[1] for row in cursor.fetchall()]
            conn.close()

    def test_register_monitored_path_idempotent(self):
        """registerMonitoredPath registers new path or returns existing pathId."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)

            dir1 = Path(tmpdir) / "monitored_one"
            dir1.mkdir()

            id1 = registerMonitoredPath(conn, dir1)
            assert isinstance(id1, int)
            assert id1 > 0

            # Registering same path returns same pathId
            id2 = registerMonitoredPath(conn, dir1)
            assert id1 == id2

            # Registering different path returns new pathId
            dir2 = Path(tmpdir) / "monitored_two"
            dir2.mkdir()
            id3 = registerMonitoredPath(conn, dir2)
            assert id3 != id1

            conn.close()

    def test_get_monitored_path_id_and_get_all(self):
        """getMonitoredPathId and getAllMonitoredPaths return accurate path metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.sqlite3"
            conn = initializeDatabase(db_path)

            dir1 = Path(tmpdir) / "dir1"
            dir2 = Path(tmpdir) / "dir2"
            dir1.mkdir()
            dir2.mkdir()

            id1 = registerMonitoredPath(conn, dir1)
            id2 = registerMonitoredPath(conn, dir2)

            assert getMonitoredPathId(conn, dir1) == id1
            assert getMonitoredPathId(conn, dir2) == id2
            assert getMonitoredPathId(conn, Path(tmpdir) / "nonexistent") is None

            all_paths = getAllMonitoredPaths(conn)
            assert len(all_paths) == 2
            path_ids = [p["pathId"] for p in all_paths]
            assert id1 in path_ids
            assert id2 in path_ids
            assert all(p["enabled"] is True for p in all_paths)

            conn.close()


# ============================================================================
# Section 2: Multi-Path Event Sources
# ============================================================================

class TestMultiPathEventSources:
    """Test event sources with multi-path context and pathId attribution."""

    def test_polling_event_source_attaches_path_id_and_monitored_path(self):
        """PollingFileEventSource tags collected events with pathId and monitoredPath."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitored_dir = Path(tmpdir) / "watch_dir"
            monitored_dir.mkdir()

            source = PollingFileEventSource(monitored_dir, pathId=42)

            # Create a file
            test_file = monitored_dir / "sample.txt"
            test_file.write_text("hello world", encoding="utf-8")

            events = source.collectEvents()
            assert len(events) == 1
            event = events[0]
            assert event.action == FileAction.created
            assert event.path == str(test_file)
            assert event.pathId == 42
            assert event.monitoredPath == str(monitored_dir.resolve())

    def test_multiple_polling_event_sources_isolated(self):
        """Multiple PollingFileEventSource instances operate independently across directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = Path(tmpdir) / "source1"
            dir2 = Path(tmpdir) / "source2"
            dir1.mkdir()
            dir2.mkdir()

            source1 = PollingFileEventSource(dir1, pathId=1)
            source2 = PollingFileEventSource(dir2, pathId=2)

            # Modify file in dir1 only
            file1 = dir1 / "file1.txt"
            file1.write_text("data 1", encoding="utf-8")

            events1 = source1.collectEvents()
            events2 = source2.collectEvents()

            assert len(events1) == 1
            assert events1[0].pathId == 1
            assert len(events2) == 0

            # Modify file in dir2
            file2 = dir2 / "file2.txt"
            file2.write_text("data 2", encoding="utf-8")

            events1_after = source1.collectEvents()
            events2_after = source2.collectEvents()

            assert len(events1_after) == 0
            assert len(events2_after) == 1
            assert events2_after[0].pathId == 2


# ============================================================================
# Section 3: Multi-Path DetectionController
# ============================================================================

class TestMultiPathDetectionController:
    """Test DetectionController multi-path orchestration, aggregation, and safety."""

    def test_controller_accepts_single_path_backwards_compatible(self):
        """DetectionController initializes with single Path and populates both monitoredPath and monitoredPaths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitored = Path(tmpdir) / "single_dir"
            monitored.mkdir()
            db_path = Path(tmpdir) / "db.sqlite3"

            controller = DetectionController(monitored, db_path)
            try:
                assert controller.monitoredPath == monitored.resolve()
                assert controller.monitoredPaths == [monitored.resolve()]
                assert len(controller.eventSources) == 1
                assert controller.eventSources[0][1] == monitored.resolve()
            finally:
                controller.close()

    def test_controller_accepts_multiple_monitored_paths(self):
        """DetectionController initializes with list of Paths and registers all in database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = Path(tmpdir) / "docs"
            dir2 = Path(tmpdir) / "downloads"
            dir3 = Path(tmpdir) / "desktop"
            dir1.mkdir()
            dir2.mkdir()
            dir3.mkdir()
            db_path = Path(tmpdir) / "db.sqlite3"

            controller = DetectionController(
                monitoredPaths=[dir1, dir2, dir3],
                databasePath=db_path,
            )
            try:
                assert len(controller.monitoredPaths) == 3
                assert len(controller.eventSources) == 3
                assert len(controller.pathRegistry) == 3

                # Check database records
                registered = getAllMonitoredPaths(controller.connection)
                registered_paths = [r["path"] for r in registered]
                assert str(dir1.resolve()) in registered_paths
                assert str(dir2.resolve()) in registered_paths
                assert str(dir3.resolve()) in registered_paths
            finally:
                controller.close()

    def test_controller_collects_and_stores_events_across_multiple_paths(self):
        """Controller collectOnce captures file events from multiple directories and inserts pathId."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = Path(tmpdir) / "folder1"
            dir2 = Path(tmpdir) / "folder2"
            dir1.mkdir()
            dir2.mkdir()
            db_path = Path(tmpdir) / "db.sqlite3"

            with DetectionController(monitoredPaths=[dir1, dir2], databasePath=db_path) as controller:
                # Create file in folder1 and folder2
                (dir1 / "alpha.txt").write_text("alpha content", encoding="utf-8")
                (dir2 / "beta.txt").write_text("beta content", encoding="utf-8")
                time.sleep(0.05)

                decision = controller.collectOnce()
                assert controller.lastCollectedEventCount >= 2

                # Verify events stored in SQLite with distinct pathId values
                rows = controller.connection.execute(
                    "SELECT pathId, action FROM fileEvents ORDER BY eventId ASC"
                ).fetchall()
                assert len(rows) >= 2
                path_ids = {row[0] for row in rows}
                assert len(path_ids) == 2  # Each event tagged with its respective pathId
                assert None not in path_ids

    def test_controller_aggregates_features_across_all_monitored_paths(self):
        """FeatureWindow accumulates modifications across all monitored directories into a single risk evaluation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = Path(tmpdir) / "dirA"
            dir2 = Path(tmpdir) / "dirB"
            dir1.mkdir()
            dir2.mkdir()
            db_path = Path(tmpdir) / "db.sqlite3"

            with DetectionController(monitoredPaths=[dir1, dir2], databasePath=db_path) as controller:
                # Populate initial files
                for i in range(5):
                    (dir1 / f"file_a_{i}.txt").write_text(f"initial a {i}", encoding="utf-8")
                    (dir2 / f"file_b_{i}.txt").write_text(f"initial b {i}", encoding="utf-8")

                # Baseline collection
                controller.collectOnce()

                # Simulate rapid multi-directory changes
                for i in range(5):
                    (dir1 / f"file_a_{i}.txt").write_text(f"modified a {i}" * 10, encoding="utf-8")
                    (dir2 / f"file_b_{i}.txt").write_text(f"modified b {i}" * 10, encoding="utf-8")

                decision = controller.collectOnce()
                assert controller.lastCollectedEventCount >= 10
                assert len(controller.featureWindow.events) >= 10

    def test_controller_graceful_shutdown_closes_all_event_sources(self):
        """Controller.close safely closes all open event sources without resource leaks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = Path(tmpdir) / "dir1"
            dir2 = Path(tmpdir) / "dir2"
            dir1.mkdir()
            dir2.mkdir()
            db_path = Path(tmpdir) / "db.sqlite3"

            controller = DetectionController(monitoredPaths=[dir1, dir2], databasePath=db_path)
            assert len(controller.eventSources) == 2
            assert controller._closed is False

            controller.close()
            assert controller._closed is True
            assert len(controller.eventSources) == 0
            assert controller.connection is None

            # Calling close again is idempotent and does not raise
            controller.close()


# ============================================================================
# Section 4: Configuration & Multi-Path Resolution
# ============================================================================

class TestMultiPathConfiguration:
    """Test configuration helpers for resolving and validating multiple paths."""

    def test_resolve_monitoring_paths_with_valid_list(self):
        """resolveMonitoringPaths resolves and canonicalizes multiple valid directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = Path(tmpdir) / "target1"
            dir2 = Path(tmpdir) / "target2"
            dir1.mkdir()
            dir2.mkdir()

            resolved = resolveMonitoringPaths([str(dir1), str(dir2)])
            assert len(resolved) == 2
            assert resolved[0] == dir1.resolve()
            assert resolved[1] == dir2.resolve()

    def test_resolve_monitoring_paths_empty_list_rejected(self):
        """resolveMonitoringPaths raises ConfigurationError when given empty list."""
        with pytest.raises(ConfigurationError) as exc_info:
            resolveMonitoringPaths([])
        assert "no monitoring paths provided" in str(exc_info.value).lower()

    def test_resolve_monitoring_paths_one_invalid_fails_all(self):
        """resolveMonitoringPaths fails atomically if any path is invalid (system directory)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            valid_dir = Path(tmpdir) / "valid"
            valid_dir.mkdir()

            with pytest.raises(ConfigurationError) as exc_info:
                resolveMonitoringPaths([str(valid_dir), r"C:\Windows\System32"])
            assert "invalid monitoring paths" in str(exc_info.value).lower()


# ============================================================================
# Section 5: GenericWorker & End-to-End Multi-Path Monitoring
# ============================================================================

class TestMultiPathWorkerAndCLI:
    """Test MonitoringWorker background thread and CLI multi-path commands."""

    def test_generic_worker_monitors_multiple_paths(self):
        """MonitoringWorker starts and collects events across multiple directories in background."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = Path(tmpdir) / "worker_dir1"
            dir2 = Path(tmpdir) / "worker_dir2"
            dir1.mkdir()
            dir2.mkdir()
            db_path = Path(tmpdir) / "worker.sqlite3"

            decisions = []

            def on_decision(decision, count, summary):
                decisions.append((decision, count, summary))

            worker = MonitoringWorker(
                monitoredPaths=[dir1, dir2],
                databasePath=db_path,
                intervalSeconds=0.1,
                onDecision=on_decision,
            )

            worker.start()
            assert worker.is_running() is True

            try:
                # Trigger changes in both dirs
                (dir1 / "fileA.txt").write_text("hello", encoding="utf-8")
                (dir2 / "fileB.txt").write_text("world", encoding="utf-8")

                # Wait for collection cycle
                time.sleep(0.4)

                assert len(decisions) > 0
            finally:
                worker.stop()
                assert worker.is_running() is False

    def test_perform_scan_multi_path(self):
        """performScan runs one-time scan across all configured paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = Path(tmpdir) / "scan_dir1"
            dir2 = Path(tmpdir) / "scan_dir2"
            dir1.mkdir()
            dir2.mkdir()
            db_path = Path(tmpdir) / "scan.sqlite3"

            config = {
                "monitoring": {
                    "paths": [str(dir1), str(dir2)],
                    "sensitivity": "balanced",
                    "intervalSeconds": 1,
                    "alertCooldownSeconds": 60,
                },
                "model": {"path": ""},
                "response": {"mode": "alertOnly"},
            }

            exit_code = performScan(config, db_path)
            assert exit_code == 0

    def test_show_detailed_status_displays_multi_path(self, capsys):
        """showDetailedStatus displays all active monitored paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = Path(tmpdir) / "status_dir1"
            dir2 = Path(tmpdir) / "status_dir2"
            dir1.mkdir()
            dir2.mkdir()
            db_path = Path(tmpdir) / "status.sqlite3"
            initializeDatabase(db_path).close()

            config = {
                "monitoring": {
                    "paths": [str(dir1), str(dir2)],
                    "sensitivity": "balanced",
                    "intervalSeconds": 1,
                },
                "model": {"path": ""},
                "response": {"mode": "alertOnly"},
            }

            exit_code = showDetailedStatus(config, db_path)
            assert exit_code == 0

            captured = capsys.readouterr()
            assert "Monitoring Paths" in captured.out
            assert "2 active" in captured.out
            assert str(dir1.resolve()) in captured.out
            assert str(dir2.resolve()) in captured.out


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
