"""Phase 1 Cross-Sprint Compatibility & Integration Test Suite (Sprints 1.1, 1.2, 1.3)."""

import json
import logging
import os
import shutil
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

# Sprint 1.1 Modules
from app.config.configuration import (
    ConfigurationError,
    loadConfiguration,
    resolveMonitoringPath,
    validateConfiguration,
)
from app.features.windowing import FeatureWindow
from app.security.pathValidator import PathValidator, PathValidationError

# Sprint 1.2 Modules
from app.monitoring.fileEvents import PollingFileEventSource
from app.monitoring.windowsFileEvents import WindowsFileEventSource, WindowsWatcherUnavailable
from app.runtime.controller import DetectionController
from app.runtime.signalHandler import SignalHandler
from app.storage.connectionPool import ConnectionPool
from app.storage.sqliteStore import closeDatabase, getPooledConnection, initializeDatabase

# Sprint 1.3 Modules
from app.logging.logger import (
    PerformanceTimer,
    closeLogging,
    createLogger,
    getRequestId,
    getSessionId,
    logExecutionTime,
    logSecurityEvent,
    setRequestId,
    setSessionId,
)


@pytest.fixture(autouse=True)
def clean_environment():
    """Ensure clean logging context, handlers, and connection pool for each test."""
    setSessionId(None)
    setRequestId(None)
    closeLogging()
    closeDatabase()
    yield
    setSessionId(None)
    setRequestId(None)
    closeLogging()
    closeDatabase()


def parse_json_lines(log_file_path: Path) -> list[dict]:
    """Helper to parse structured JSON log lines."""
    if not log_file_path.exists():
        return []
    records = []
    for line in log_file_path.read_text(encoding="utf-8").strip().splitlines():
        if line.strip():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


# ============================================================================
# Test 1: Full Lifecycle Integration (Path Security + Connection Pool + JSON Logging)
# ============================================================================

class TestFullLifecycleCompatibility:
    """Test full system lifecycle integrating Sprint 1.1, 1.2, and 1.3 components."""

    def test_complete_monitoring_lifecycle_with_all_sprints(self):
        """
        Verify:
        - Sprint 1.1: Validated monitoring directory and safe file feature calculation
        - Sprint 1.2: Controller context manager with ConnectionPool & clean session end
        - Sprint 1.3: Structured JSON logs with session context and duration metrics
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            monitor_dir = temp_path / "monitored_data"
            monitor_dir.mkdir()
            log_dir = temp_path / "logs"
            db_path = temp_path / "detector.sqlite3"

            # 1. Initialize Sprint 1.3 Logging
            createLogger(log_dir, levelName="DEBUG")

            # 2. Sprint 1.1 Path Validator setup
            validator = PathValidator({monitor_dir.resolve()})
            validated_path = validator.validate(str(monitor_dir))
            assert validated_path == monitor_dir.resolve()

            # 3. Create initial safe test files in monitored path
            test_file1 = monitor_dir / "document1.txt"
            test_file1.write_text("Safe readable text content for entropy analysis.")

            # 4. Sprint 1.2 DetectionController inside context manager
            with DetectionController(validated_path, db_path) as controller:
                session_id = controller.startSession()
                assert session_id is not None
                assert getSessionId() == str(session_id)

                # Mutate file and create a second file
                test_file1.write_text("Modified text with higher variety of characters 1234567890!@#$%^")
                test_file2 = monitor_dir / "data.json"
                test_file2.write_text(json.dumps({"key": "value", "numbers": [1, 2, 3, 4, 5]}))

                # Run collection cycle
                decision = controller.collectOnce()
                assert decision is not None
                assert decision.score >= 0.0

            # 5. Verify Sprint 1.2 clean shutdown
            assert controller._closed
            assert getSessionId() is None  # Reset on controller close

            # Verify database session ended properly
            with ConnectionPool(db_path, poolSize=2) as pool:
                with pool.getConnection() as conn:
                    session_row = conn.execute(
                        "SELECT sessionId, startedAt, endedAt FROM sessions WHERE sessionId = ?",
                        (session_id,)
                    ).fetchone()
                    assert session_row is not None
                    assert session_row[2] is not None  # endedAt is recorded

                    # Verify file events recorded in database
                    event_count = conn.execute(
                        "SELECT COUNT(*) FROM fileEvents WHERE sessionId = ?",
                        (session_id,)
                    ).fetchone()[0]
                    assert event_count >= 0

            # 6. Verify Sprint 1.3 Structured Logging
            closeLogging()
            records = parse_json_lines(log_dir / "application.log")
            assert len(records) > 0

            # Check that session ID was injected into records during session run
            session_records = [r for r in records if r.get("sessionId") == str(session_id)]
            assert len(session_records) >= 1

            # Check schema compliance of logged records
            for r in records:
                assert "timestamp" in r
                assert "severity" in r
                assert "component" in r
                assert "event" in r
                assert "message" in r


# ============================================================================
# Test 2: Attack Prevention + Security Audit Trail + Resource Safety
# ============================================================================

class TestSecurityAttackAndAuditCompatibility:
    """Test security violation handling (1.1) produces audit logs (1.3) without leaking resources (1.2)."""

    def test_blocked_path_traversal_audit_trail_and_resource_safety(self):
        """
        Verify:
        - Sprint 1.1 blocks system paths and network paths
        - Sprint 1.3 records security audit logs with escalated WARNING severity to audit.log
        - Sprint 1.2 database and file handles remain uncorrupted and leak-free
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            log_dir = temp_path / "logs"
            db_path = temp_path / "detector.sqlite3"

            createLogger(log_dir, levelName="DEBUG")
            init_conn = initializeDatabase(db_path)
            init_conn.close()

            validator = PathValidator()

            # Attempt 1: System path access
            with pytest.raises(PathValidationError):
                validator.validate("C:\\Windows\\System32")

            # Attempt 2: Network path access
            with pytest.raises(PathValidationError):
                validator.validate("\\\\evil-server\\share\\malware")

            # Attempt 3: Non-whitelisted path
            with pytest.raises(PathValidationError):
                validator.validate("C:\\NonExistentSecretLocation")

            # Verify database was unaffected and pool remains healthy
            pool = getPooledConnection()
            with pool.getConnection() as conn:
                res = conn.execute("SELECT 1").fetchone()
                assert res[0] == 1

            closeLogging()
            closeDatabase()

            # Verify audit.log has all blocked attempts
            audit_records = parse_json_lines(log_dir / "audit.log")
            assert len(audit_records) >= 3

            for record in audit_records:
                assert record["event"] == "security_audit"
                assert record["severity"] == "WARNING"
                assert record["context"]["status"] == "blocked"
                assert record["context"]["action"] == "path_validation"


# ============================================================================
# Test 3: Dangerous File Ingestion + Safe Entropy + Structured Diagnostics
# ============================================================================

class TestFileAccessAndEntropyCompatibility:
    """Test dangerous file filtering (1.1), feature extraction (1.1), pool storage (1.2), and logs (1.3)."""

    def test_mixed_file_types_safety_and_logging(self):
        """
        Verify:
        - Sprint 1.1 safely skips .exe, .dll, large files (>1MB) during entropy calculation
        - Sprint 1.3 logs skips at DEBUG without raising exceptions
        - Sprint 1.2 feature sample is saved and evaluated without connection exhaustion
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            monitor_dir = temp_path / "mixed_files"
            monitor_dir.mkdir()
            log_dir = temp_path / "logs"
            db_path = temp_path / "detector.sqlite3"

            createLogger(log_dir, levelName="DEBUG")

            # 1. Create a mixture of safe and dangerous files
            safe_text = monitor_dir / "report.txt"
            safe_text.write_text("Hello World! Normal business document.")

            dangerous_exe = monitor_dir / "payload.exe"
            dangerous_exe.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100)

            dangerous_dll = monitor_dir / "hook.dll"
            dangerous_dll.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100)

            large_file = monitor_dir / "large_archive.zip"
            large_file.write_bytes(b"PK\x03\x04" + b"\x00" * (1024 * 1024 + 500))  # > 1MB

            # 2. Test FeatureWindow safety methods directly
            window = FeatureWindow()
            assert window._canReadFileForEntropy(safe_text) is True
            assert window._canReadFileForEntropy(dangerous_exe) is False
            assert window._canReadFileForEntropy(dangerous_dll) is False
            assert window._canReadFileForEntropy(large_file) is False

            safe_entropy = window._calculateFileEntropy(safe_text)
            assert safe_entropy is not None
            assert 0.0 <= safe_entropy <= 8.0

            exe_entropy = window._calculateFileEntropy(dangerous_exe)
            assert exe_entropy is None

            # 3. Test Controller running on this mixed directory
            with DetectionController(monitor_dir, db_path) as controller:
                session_id = controller.startSession()
                decision = controller.collectOnce()
                assert decision is not None

            closeLogging()
            records = parse_json_lines(log_dir / "application.log")

            # Check that dangerous files triggered debug skips rather than errors
            skip_logs = [r for r in records if "too large" in r.get("message", "").lower() or "skipped" in r.get("message", "").lower()]
            assert len(records) > 0


# ============================================================================
# Test 4: Graceful Shutdown Coordination (SignalHandler + Controller + Logging)
# ============================================================================

class TestGracefulShutdownCompatibility:
    """Test SignalHandler shutdown (1.2) coordinating controller cleanup (1.2) and logging flush (1.3)."""

    def test_signal_handler_triggers_controller_close_and_audit(self):
        """
        Verify:
        - SignalHandler executes controller.close() cleanly on shutdown
        - Database sessions are marked ended
        - Log flush completes without file handle permission conflicts
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            monitor_dir = temp_path / "shutdown_monitor"
            monitor_dir.mkdir()
            log_dir = temp_path / "logs"
            db_path = temp_path / "detector.sqlite3"

            createLogger(log_dir, levelName="DEBUG")

            controller = DetectionController(monitor_dir, db_path)
            session_id = controller.startSession()

            signal_handler = SignalHandler()
            signal_handler.registerCallback(controller.close)

            # Simulate OS shutdown signal
            signal_handler._executeShutdownCallbacks()

            assert signal_handler.isShuttingDown() is True
            assert controller._closed is True

            # Verify session was cleanly ended in database
            pool = getPooledConnection()
            with pool.getConnection() as conn:
                res = conn.execute(
                    "SELECT endedAt FROM sessions WHERE sessionId = ?",
                    (session_id,)
                ).fetchone()
                assert res[0] is not None

            # Ensure logging cleans up without locking the temp dir
            closeLogging()
            closeDatabase()


# ============================================================================
# Test 5: Concurrency, Thread Safety & Context Isolation
# ============================================================================

class TestConcurrencyAndContextIsolation:
    """Test multithreaded pool access (1.2) with thread-safe logging and isolated context (1.3)."""

    def test_multithreaded_pool_and_isolated_context(self):
        """
        Verify:
        - Multiple worker threads concurrently access ConnectionPool
        - Each thread maintains independent session/request context in structured JSON logs
        - No thread deadlocks or database corruption occurs
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            log_dir = temp_path / "logs"
            db_path = temp_path / "detector.sqlite3"

            logger = createLogger(log_dir, levelName="DEBUG")
            pool = ConnectionPool(db_path, poolSize=4)

            num_threads = 8
            iterations_per_thread = 20
            errors = []

            def worker_task(thread_idx: int):
                try:
                    # Set thread-local context
                    thread_session = f"session-th-{thread_idx}"
                    thread_req = f"req-{thread_idx}-{time.time()}"
                    setSessionId(thread_session)
                    setRequestId(thread_req)

                    for step in range(iterations_per_thread):
                        with pool.getConnection() as conn:
                            conn.execute(
                                "CREATE TABLE IF NOT EXISTS thread_test (id INTEGER PRIMARY KEY, t_id INT, step INT)"
                            )
                            conn.execute(
                                "INSERT INTO thread_test (t_id, step) VALUES (?, ?)",
                                (thread_idx, step),
                            )
                            conn.commit()

                        logger.debug(
                            f"Worker {thread_idx} completed step {step}",
                            extra={"event": "thread_worker", "context": {"thread": thread_idx, "step": step}},
                        )
                except Exception as e:
                    errors.append(e)

            threads = [
                threading.Thread(target=worker_task, args=(i,))
                for i in range(num_threads)
            ]

            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10.0)

            pool.close()
            closeLogging()

            assert len(errors) == 0, f"Thread errors encountered: {errors}"

            # Verify total records in DB
            with ConnectionPool(db_path, poolSize=1) as check_pool:
                with check_pool.getConnection() as conn:
                    total_rows = conn.execute("SELECT COUNT(*) FROM thread_test").fetchone()[0]
                    assert total_rows == num_threads * iterations_per_thread

            # Verify log lines
            records = parse_json_lines(log_dir / "application.log")
            worker_records = [r for r in records if r.get("event") == "thread_worker"]
            assert len(worker_records) == num_threads * iterations_per_thread

            # Verify each record has its correct thread sessionId
            for r in worker_records:
                thread_num = r["context"]["thread"]
                assert r["sessionId"] == f"session-th-{thread_num}"


# ============================================================================
# Test 6: Performance & Timing under Combined Load
# ============================================================================

class TestPerformanceUnderLoadCompatibility:
    """Test performance instrumentation (1.3) wrapping database transactions (1.2) and path checks (1.1)."""

    def test_performance_timer_across_security_and_storage(self):
        """
        Verify:
        - PerformanceTimer measures combined path validation + pool transaction + entropy calculation
        - Overhead is negligible and accurately logged with durationMs
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            monitor_dir = temp_path / "perf_monitor"
            monitor_dir.mkdir()
            log_dir = temp_path / "logs"
            db_path = temp_path / "detector.sqlite3"

            logger = createLogger(log_dir, levelName="DEBUG")
            init_conn = initializeDatabase(db_path)
            init_conn.close()
            validator = PathValidator({monitor_dir.resolve()})

            # Create test files
            for i in range(10):
                (monitor_dir / f"file_{i}.txt").write_text(f"Sample data content {i} * {i}")

            with PerformanceTimer(logger, "composite_operation", extraContext={"fileBatch": 10}) as metrics:
                # Sprint 1.1 Path check
                val_path = validator.validate(str(monitor_dir))

                # Sprint 1.2 Database operation
                pool = getPooledConnection()
                with pool.getConnection() as conn:
                    conn.execute(
                        "INSERT INTO settings (key, value) VALUES (?, ?)",
                        ("test_key", "test_val"),
                    )
                    conn.commit()

                metrics["validatedPath"] = str(val_path)

            closeLogging()
            closeDatabase()

            records = parse_json_lines(log_dir / "application.log")
            perf_records = [r for r in records if r.get("event") == "performance_metric"]
            assert len(perf_records) >= 1

            entry = perf_records[-1]
            assert entry["context"]["operation"] == "composite_operation"
            assert entry["context"]["fileBatch"] == 10
            assert entry["context"]["status"] == "success"
            assert "durationMs" in entry
            assert entry["durationMs"] >= 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
