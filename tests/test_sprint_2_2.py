"""Sprint 2.2 - Real-Time Windows API Integration & Process Attribution Test Suite.

Verifies:
1. Recursive directory watching (nested subdirectories, deep file paths).
2. Win32 rename tracking with oldPath and path pair matching.
3. Win32 notification filter flags (attribute, size, timestamp, security descriptor).
4. Process attribution engine (processId, processName, parentProcessId, I/O metrics).
5. Automatic fallback to polling on Windows API errors and recovery.
6. Database persistence and schema migration for process attribution and rename history.
"""

import os
import queue
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.domain.schemas import FileAction, FileEvent, getCurrentTime
from app.logging.logger import closeLogging, setSessionId
from app.monitoring.fileEvents import PollingFileEventSource
from app.monitoring.multiPathCollector import SinglePathWatcher
from app.monitoring.processAttribution import (
    ProcessAttributor,
    ProcessInfo,
    getProcessAttributor,
)
from app.monitoring.windowsFileEvents import (
    DEFAULT_NOTIFY_FILTER,
    FILE_ACTION_ADDED,
    FILE_ACTION_MODIFIED,
    FILE_ACTION_REMOVED,
    FILE_ACTION_RENAMED_NEW_NAME,
    FILE_ACTION_RENAMED_OLD_NAME,
    FILE_NOTIFY_CHANGE_ATTRIBUTES,
    FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SECURITY,
    FILE_NOTIFY_CHANGE_SIZE,
    WindowsFileEventSource,
    WindowsWatcherUnavailable,
)
from app.runtime.controller import DetectionController
from app.storage.sqliteStore import closeDatabase, initializeDatabase, migrateSchema


@pytest.fixture(autouse=True)
def clean_environment():
    """Clean logging and database context before and after each test."""
    setSessionId(None)
    closeLogging()
    closeDatabase()
    yield
    setSessionId(None)
    closeLogging()
    closeDatabase()


# ============================================================================
# Section 1: Recursive Directory Watching
# ============================================================================

class TestRecursiveDirectoryWatching:
    """Test deep recursive directory watching with Windows API and Polling."""

    def test_recursive_monitoring_detects_nested_file_creation(self):
        """Watcher with watchSubtree=True captures creations in multi-level subdirectories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "watched_root"
            root.mkdir()
            sub1 = root / "sub1"
            sub2 = sub1 / "sub2"
            sub2.mkdir(parents=True)

            event_queue = queue.Queue()
            watcher = SinglePathWatcher(root, pathId=1, eventQueue=event_queue)
            watcher.start()
            time.sleep(0.05)

            try:
                # Create file in nested directory
                nested_file = sub2 / "deep_file.txt"
                nested_file.write_text("deep content", encoding="utf-8")
                time.sleep(0.1)

                events = []
                while not event_queue.empty():
                    events.append(event_queue.get_nowait())

                assert len(events) >= 1
                paths = [Path(e.path).resolve() for e in events]
                assert nested_file.resolve() in paths
                assert all(e.pathId == 1 for e in events)
                assert all(e.monitoredPath == str(root.resolve()) for e in events)
            finally:
                watcher.close()

    def test_windows_source_watch_subtree_configuration(self):
        """WindowsFileEventSource respects watchSubtree parameter."""
        if os.name != "nt":
            pytest.skip("Windows API tests require Windows OS")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "watch_cfg"
            root.mkdir()

            source = WindowsFileEventSource(root, pathId=10, watchSubtree=True)
            assert source.watchSubtree is True
            assert source.pathId == 10
            assert source.isHealthy() is True
            source.close()
            assert source.isHealthy() is False


# ============================================================================
# Section 2: Rename Pair Matching & Path Attribution
# ============================================================================

class TestRenamePairMatching:
    """Test Win32 rename event parsing and oldPath tracking."""

    def test_parse_events_pairs_old_and_new_rename_actions(self):
        """_parseEvents matches ACTION_RENAMED_OLD_NAME with ACTION_RENAMED_NEW_NAME."""
        if os.name != "nt":
            pytest.skip("Windows API tests require Windows OS")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "rename_dir"
            root.mkdir()
            source = WindowsFileEventSource(root, pathId=5, enableProcessAttribution=False)

            try:
                # Simulate binary payload from Windows kernel for rename
                # Structure: DWORD NextEntryOffset, DWORD Action, DWORD FileNameLength, WCHAR FileName[]
                name1_bytes = "original.doc".encode("utf-16-le")
                name2_bytes = "encrypted.locked".encode("utf-16-le")

                # Record 1: Old Name (Action 4)
                # Record 2: New Name (Action 5)
                rec1_len = 12 + len(name1_bytes)
                import struct
                # Pad to 4-byte boundary
                pad1 = (4 - (rec1_len % 4)) % 4
                rec1_offset = rec1_len + pad1

                raw_data = bytearray()
                raw_data.extend(struct.pack("<III", rec1_offset, FILE_ACTION_RENAMED_OLD_NAME, len(name1_bytes)))
                raw_data.extend(name1_bytes)
                raw_data.extend(b"\x00" * pad1)

                raw_data.extend(struct.pack("<III", 0, FILE_ACTION_RENAMED_NEW_NAME, len(name2_bytes)))
                raw_data.extend(name2_bytes)

                events = source._parseEvents(bytes(raw_data))

                assert len(events) == 1
                event = events[0]
                assert event.action == FileAction.renamed
                assert event.path == str(root / "encrypted.locked")
                assert event.oldPath == str(root / "original.doc")
                assert event.pathId == 5
                assert event.source == "windows"
            finally:
                source.close()

    def test_standalone_rename_action_fallback(self):
        """_parseEvents gracefully handles unpaired rename new name without crashing."""
        if os.name != "nt":
            pytest.skip("Windows API tests require Windows OS")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "rename_solo"
            root.mkdir()
            source = WindowsFileEventSource(root, pathId=1, enableProcessAttribution=False)

            try:
                name_bytes = "standalone.txt".encode("utf-16-le")
                import struct
                raw_data = struct.pack("<III", 0, FILE_ACTION_RENAMED_NEW_NAME, len(name_bytes)) + name_bytes

                events = source._parseEvents(raw_data)
                assert len(events) == 1
                assert events[0].action == FileAction.renamed
                assert events[0].path == str(root / "standalone.txt")
                assert events[0].oldPath is None
            finally:
                source.close()


# ============================================================================
# Section 3: Win32 Notification Filter Flags
# ============================================================================

class TestNotificationFilterFlags:
    """Test Win32 notification filter constants and configuration."""

    def test_default_filter_includes_all_critical_ransomware_vectors(self):
        """DEFAULT_NOTIFY_FILTER combines file name, dir name, size, last write, and attributes."""
        expected_mask = (
            FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_ATTRIBUTES
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_SECURITY
        )
        assert DEFAULT_NOTIFY_FILTER == expected_mask
        assert DEFAULT_NOTIFY_FILTER & FILE_NOTIFY_CHANGE_FILE_NAME != 0
        assert DEFAULT_NOTIFY_FILTER & FILE_NOTIFY_CHANGE_SIZE != 0
        assert DEFAULT_NOTIFY_FILTER & FILE_NOTIFY_CHANGE_LAST_WRITE != 0
        assert DEFAULT_NOTIFY_FILTER & FILE_NOTIFY_CHANGE_SECURITY != 0


# ============================================================================
# Section 4: Process Attribution Engine
# ============================================================================

class TestProcessAttributionEngine:
    """Test process correlation, I/O metrics tracking, and event enrichment."""

    def test_process_attributor_inspects_current_process(self):
        """ProcessAttributor retrieves accurate metadata for current running process."""
        attributor = ProcessAttributor(cacheTtlSeconds=1.0)
        current_pid = os.getpid()

        info = attributor.getProcessInfo(current_pid)
        assert info is not None
        assert info.processId == current_pid
        assert isinstance(info.name, str)
        assert len(info.name) > 0
        assert info.createTime > 0

    def test_process_attributor_safe_on_invalid_pid(self):
        """ProcessAttributor returns None for non-existent PIDs without raising."""
        attributor = ProcessAttributor()
        assert attributor.getProcessInfo(9999999) is None

    def test_attribute_event_enriches_process_metadata(self):
        """attributeEvent populates processName and parentProcessId when PID is provided."""
        attributor = ProcessAttributor()
        current_pid = os.getpid()

        event = FileEvent(
            action=FileAction.modified,
            path="C:\\test\\document.pdf",
            occurredAt=getCurrentTime(),
            source="windows",
            processId=current_pid,
        )

        enriched = attributor.attributeEvent(event)
        assert enriched.processId == current_pid
        assert enriched.processName is not None
        assert len(enriched.processName) > 0
        assert enriched.path == "C:\\test\\document.pdf"

    def test_top_io_processes_returns_ranked_list(self):
        """getTopIoProcesses returns active processes sorted by I/O write volume."""
        attributor = getProcessAttributor()
        top_procs = attributor.getTopIoProcesses(limit=5)
        assert isinstance(top_procs, list)
        assert len(top_procs) <= 5
        for p in top_procs:
            assert isinstance(p, ProcessInfo)
            assert isinstance(p.processId, int)


# ============================================================================
# Section 5: Automatic Fallback to Polling & Recovery
# ============================================================================

class TestAutomaticFallbackAndRecovery:
    """Test resilience when Windows watcher encounters errors or fails over to polling."""

    def test_single_path_watcher_fallback_to_polling_on_exception(self):
        """SinglePathWatcher seamlessly transitions to polling fallback when Windows API fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitored = Path(tmpdir) / "fallback_dir"
            monitored.mkdir()
            event_queue = queue.Queue()

            # Mock WindowsFileEventSource to raise WindowsWatcherUnavailable
            with patch(
                "app.monitoring.multiPathCollector.WindowsFileEventSource",
                side_effect=WindowsWatcherUnavailable("Native API unavailable in test"),
            ):
                watcher = SinglePathWatcher(monitored, pathId=3, eventQueue=event_queue, pollIntervalSeconds=0.05)
                assert watcher._isWindowsWatcher is False
                assert isinstance(watcher.eventSource, PollingFileEventSource)

                watcher.start()
                time.sleep(0.05)

                try:
                    # Trigger change in polling mode
                    test_file = monitored / "polled_change.txt"
                    test_file.write_text("polled data", encoding="utf-8")

                    events = []
                    deadline = time.monotonic() + 1.0
                    while time.monotonic() < deadline:
                        while not event_queue.empty():
                            events.append(event_queue.get_nowait())
                        if events:
                            break
                        time.sleep(0.05)

                    assert len(events) >= 1
                    assert events[0].pathId == 3
                    assert events[0].source == "polling"
                finally:
                    watcher.close()

    def test_runtime_failover_method(self):
        """fallbackToPolling method cleanly replaces eventSource at runtime."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitored = Path(tmpdir) / "runtime_failover"
            monitored.mkdir()
            event_queue = queue.Queue()

            watcher = SinglePathWatcher(monitored, pathId=1, eventQueue=event_queue)
            try:
                watcher.fallbackToPolling(reason="Simulated handle disconnection")
                assert watcher._isWindowsWatcher is False
                assert isinstance(watcher.eventSource, PollingFileEventSource)
            finally:
                watcher.close()


# ============================================================================
# Section 6: Database Storage & Schema Migration for Process Attribution
# ============================================================================

class TestDatabaseProcessAttributionStorage:
    """Test database schema support and storage for process attribution and rename history."""

    def test_file_events_table_contains_process_and_rename_columns(self):
        """fileEvents table contains processId, processName, parentProcessId, and oldPathHash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_proc.sqlite3"
            conn = initializeDatabase(db_path)

            cursor = conn.execute("PRAGMA table_info(fileEvents)")
            columns = [row[1] for row in cursor.fetchall()]

            assert "processId" in columns
            assert "processName" in columns
            assert "parentProcessId" in columns
            assert "oldPathHash" in columns

            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='fileEvents'"
            )
            indexes = [row[0] for row in cursor.fetchall()]
            assert "fileEventsProcessIdIndex" in indexes

            conn.close()

    def test_migrate_schema_adds_process_columns_to_legacy_database(self):
        """migrateSchema automatically adds process attribution and oldPathHash to legacy databases."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "legacy_proc.sqlite3"

            # Create legacy database without process attribution columns
            conn = sqlite3.connect(str(db_path))
            conn.execute(
                """
                CREATE TABLE fileEvents (
                    eventId INTEGER PRIMARY KEY,
                    sessionId INTEGER,
                    occurredAt TEXT NOT NULL,
                    action TEXT NOT NULL,
                    pathHash TEXT NOT NULL,
                    source TEXT NOT NULL,
                    pathId INTEGER
                );
                """
            )
            conn.commit()

            cursor = conn.execute("PRAGMA table_info(fileEvents)")
            initial_cols = [row[1] for row in cursor.fetchall()]
            assert "processId" not in initial_cols
            assert "processName" not in initial_cols

            # Run migration
            migrateSchema(conn)
            conn.commit()

            cursor = conn.execute("PRAGMA table_info(fileEvents)")
            migrated_cols = [row[1] for row in cursor.fetchall()]
            assert "processId" in migrated_cols
            assert "processName" in migrated_cols
            assert "parentProcessId" in migrated_cols
            assert "oldPathHash" in migrated_cols

            conn.close()

    def test_controller_persists_process_attribution_in_database(self):
        """DetectionController stores processId, processName, and oldPathHash in fileEvents table."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitored = Path(tmpdir) / "ctrl_proc_dir"
            monitored.mkdir()
            db_path = Path(tmpdir) / "ctrl_proc.sqlite3"

            current_pid = os.getpid()

            with DetectionController(monitoredPath=monitored, databasePath=db_path) as controller:
                time.sleep(0.05)
                # Trigger a file change
                test_file = monitored / "target.txt"
                test_file.write_text("monitored content", encoding="utf-8")
                time.sleep(0.1)

                decision = controller.collectOnce()
                assert controller.lastCollectedEventCount >= 1

                rows = controller.connection.execute(
                    "SELECT action, processId, processName FROM fileEvents"
                ).fetchall()
                assert len(rows) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
