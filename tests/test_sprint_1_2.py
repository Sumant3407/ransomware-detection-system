"""Sprint 1.2 - Resource Cleanup & Context Managers verification tests."""

import pytest
import tempfile
import threading
import time
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from app.storage.sqliteStore import initializeDatabase, getPooledConnection, closeDatabase
from app.storage.connectionPool import ConnectionPool, PooledDatabaseConnection
from app.runtime.controller import DetectionController
from app.runtime.signalHandler import SignalHandler


# ============================================================================
# Connection Pool Tests
# ============================================================================

class TestConnectionPool:
    """Test connection pooling and resource management."""

    def test_pool_creation_with_defaults(self):
        """Pool initializes with default size."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            pool = ConnectionPool(db_path, poolSize=5)
            assert pool.poolSize == 5
            assert len(pool._connections) == 0

    def test_pool_creates_connections_on_demand(self):
        """Pool creates connections when needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            pool = ConnectionPool(db_path, poolSize=3)
            try:
                # First connection should be created
                with pool.getConnection() as conn:
                    assert conn is not None
                    conn.execute("SELECT 1")

                # Connection returned to pool
                assert len(pool._connections) == 1
            finally:
                pool.close()

    def test_pool_reuses_connections(self):
        """Pool reuses connections from pool."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            pool = ConnectionPool(db_path, poolSize=3)
            try:
                # Get and release connection
                with pool.getConnection() as conn1:
                    conn1_id = id(conn1)

                # Get another connection - should be the same
                with pool.getConnection() as conn2:
                    conn2_id = id(conn2)

                assert conn1_id == conn2_id  # Same connection object reused
            finally:
                pool.close()

    def test_pool_respects_max_size(self):
        """Pool enforces maximum connections limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            pool = ConnectionPool(db_path, poolSize=2, timeout=1.0)
            try:
                # Hold 2 connections (max)
                ctx1 = pool.getConnection()
                ctx1.__enter__()

                ctx2 = pool.getConnection()
                ctx2.__enter__()

                try:
                    # Third connection should timeout
                    with pytest.raises(sqlite3.OperationalError):
                        with pool.getConnection():
                            pass
                finally:
                    ctx1.__exit__(None, None, None)
                    ctx2.__exit__(None, None, None)
            finally:
                pool.close()

    def test_pool_validates_connections_before_reuse(self):
        """Pool validates connections before returning them."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            pool = ConnectionPool(db_path, poolSize=1)
            try:
                # Manually add invalid connection to pool
                bad_conn = MagicMock()
                bad_conn.execute.side_effect = sqlite3.Error("Connection broken")
                pool._connections.append(bad_conn)

                # Getting connection should skip the invalid one and create fresh
                with pool.getConnection() as conn:
                    conn.execute("SELECT 1")

                # The bad connection should have been discarded
                assert id(bad_conn) not in [id(c) for c in pool._connections]
            finally:
                pool.close()

    def test_pool_closes_all_connections(self):
        """Pool closes all connections on close()."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            pool = ConnectionPool(db_path, poolSize=3)
            try:
                # Create some connections
                with pool.getConnection() as conn:
                    conn.execute("SELECT 1")

                with pool.getConnection() as conn:
                    conn.execute("SELECT 1")

                # Pool reuses the same connection, so only one is pooled
                assert len(pool._connections) == 1
            finally:
                pool.close()
                assert len(pool._connections) == 0

    def test_pool_context_manager(self):
        """Pool works as context manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            with ConnectionPool(db_path, poolSize=3) as pool:
                with pool.getConnection() as conn:
                    conn.execute("SELECT 1")

                # Pool still open inside context
                assert len(pool._connections) == 1

            # Pool closed after context exit
            assert len(pool._connections) == 0

    def test_pool_idempotent_close(self):
        """Pool close() is idempotent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            pool = ConnectionPool(db_path, poolSize=3)

            with pool.getConnection() as conn:
                conn.execute("SELECT 1")

            # Close multiple times
            pool.close()
            pool.close()  # Should not raise
            pool.close()  # Should not raise

            assert len(pool._connections) == 0

    def test_pool_thread_safety(self):
        """Pool is thread-safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            pool = ConnectionPool(db_path, poolSize=5)
            results = []

            def worker(thread_id):
                try:
                    with pool.getConnection() as conn:
                        conn.execute("SELECT ?", (thread_id,))
                        results.append(thread_id)
                except Exception as e:
                    results.append(f"error: {e}")

            try:
                # Spawn 10 threads (more than pool size)
                threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

                # All threads should complete successfully
                assert len(results) == 10
                assert all(isinstance(r, int) for r in results)
            finally:
                pool.close()


# ============================================================================
# Database Initialization Tests
# ============================================================================

class TestDatabaseInitialization:
    """Test database initialization with pooling."""

    def test_initialize_database_creates_schema(self):
        """initializeDatabase creates proper schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            # Initialize
            conn = initializeDatabase(db_path, poolSize=3)

            try:
                # Verify schema tables exist
                tables = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                table_names = [t[0] for t in tables]

                assert "sessions" in table_names
                assert "fileEvents" in table_names
                assert "detections" in table_names
                assert "alerts" in table_names
                assert "models" in table_names
                assert "monitoredPaths" in table_names
            finally:
                conn.close()
                closeDatabase()

    def test_initialize_database_creates_pool(self):
        """initializeDatabase creates connection pool."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            conn = initializeDatabase(db_path, poolSize=4)
            try:
                pool = getPooledConnection()
                assert pool is not None
                assert pool.poolSize == 4
            finally:
                conn.close()
                closeDatabase()

    def test_get_pooled_connection_requires_init(self):
        """getPooledConnection raises if database not initialized."""
        closeDatabase()  # Ensure pool is None

        with pytest.raises(RuntimeError, match="not initialized"):
            getPooledConnection()

    def test_close_database_is_idempotent(self):
        """closeDatabase() is idempotent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            conn = initializeDatabase(db_path)
            try:
                closeDatabase()
                closeDatabase()  # Should not raise
                closeDatabase()  # Should not raise
            finally:
                conn.close()


# ============================================================================
# DetectionController Resource Cleanup Tests
# ============================================================================

class TestDetectionControllerCleanup:
    """Test DetectionController resource cleanup and context manager."""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield db_path
            closeDatabase()

    def test_controller_context_manager(self, temp_db):
        """Controller works as context manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_path = Path(tmpdir) / "monitor"
            monitor_path.mkdir()

            with DetectionController(monitor_path, temp_db) as controller:
                assert controller is not None
                assert not controller._closed

            # After context exit, controller should be closed
            assert controller._closed

    def test_controller_close_is_idempotent(self, temp_db):
        """Controller close() is idempotent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_path = Path(tmpdir) / "monitor"
            monitor_path.mkdir()

            controller = DetectionController(monitor_path, temp_db)
            try:
                # Close multiple times
                controller.close()
                controller.close()  # Should not raise
                controller.close()  # Should not raise
                assert controller._closed
            finally:
                if not controller._closed:
                    controller.close()

    def test_controller_prevents_operations_when_closed(self, temp_db):
        """Controller raises RuntimeError on operations after close."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_path = Path(tmpdir) / "monitor"
            monitor_path.mkdir()

            controller = DetectionController(monitor_path, temp_db)
            controller.close()

            # Operations should raise RuntimeError
            with pytest.raises(RuntimeError, match="closed"):
                controller.startSession()

            with pytest.raises(RuntimeError, match="closed"):
                controller.collectOnce()

    def test_controller_cleans_up_on_exception(self, temp_db):
        """Controller cleanup runs even on exception."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_path = Path(tmpdir) / "monitor"
            monitor_path.mkdir()

            try:
                with DetectionController(monitor_path, temp_db) as controller:
                    raise ValueError("Test exception")
            except ValueError:
                pass

            # Controller should still be closed
            assert controller._closed

    def test_controller_del_cleanup(self, temp_db):
        """Controller __del__ ensures cleanup on garbage collection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_path = Path(tmpdir) / "monitor"
            monitor_path.mkdir()

            controller = DetectionController(monitor_path, temp_db)
            controller_id = id(controller)

            # Delete controller (trigger __del__)
            del controller

            # Give garbage collector a chance to run
            import gc
            gc.collect()

            # We can't directly verify closure since object is gone,
            # but this test verifies __del__ doesn't raise

    def test_controller_session_cleanup(self, temp_db):
        """Controller ends session on close."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_path = Path(tmpdir) / "monitor"
            monitor_path.mkdir()

            with DetectionController(monitor_path, temp_db) as controller:
                controller.startSession()
                session_id = controller.sessionId
                assert session_id is not None

            # Verify session was ended (check database)
            pool = getPooledConnection()
            with pool.getConnection() as conn:
                result = conn.execute(
                    "SELECT endedAt FROM sessions WHERE sessionId = ?",
                    (session_id,)
                ).fetchone()
                assert result is not None
                assert result[0] is not None  # endedAt should be set


# ============================================================================
# Signal Handler Tests
# ============================================================================

class TestSignalHandler:
    """Test signal handling for graceful shutdown."""

    def test_signal_handler_initialization(self):
        """SignalHandler initializes correctly."""
        handler = SignalHandler()
        assert len(handler._shutdown_callbacks) == 0
        assert not handler.isShuttingDown()

    def test_signal_handler_register_callback(self):
        """SignalHandler registers callbacks."""
        handler = SignalHandler()
        callback = Mock()

        handler.registerCallback(callback)
        assert len(handler._shutdown_callbacks) == 1

        handler.registerCallback(callback)
        assert len(handler._shutdown_callbacks) == 2

    def test_signal_handler_executes_callbacks_in_order(self):
        """SignalHandler executes callbacks in FIFO order."""
        handler = SignalHandler()
        call_order = []

        def callback1():
            call_order.append(1)

        def callback2():
            call_order.append(2)

        def callback3():
            call_order.append(3)

        handler.registerCallback(callback1)
        handler.registerCallback(callback2)
        handler.registerCallback(callback3)

        # Manually trigger shutdown
        handler._executeShutdownCallbacks()

        assert call_order == [1, 2, 3]

    def test_signal_handler_handles_callback_exceptions(self):
        """SignalHandler handles exceptions in callbacks."""
        handler = SignalHandler()

        def good_callback():
            pass

        def bad_callback():
            raise ValueError("Test error")

        handler.registerCallback(good_callback)
        handler.registerCallback(bad_callback)
        handler.registerCallback(good_callback)

        # Should not raise despite bad_callback exception
        handler._executeShutdownCallbacks()

        assert handler.isShuttingDown()

    def test_signal_handler_context_manager(self):
        """SignalHandler works as context manager."""
        with SignalHandler() as handler:
            assert handler is not None

    def test_signal_handler_start_stop_idempotent(self):
        """SignalHandler start/stop are safe."""
        handler = SignalHandler()

        handler.start()
        handler.start()  # Should not raise
        handler.stop()
        handler.stop()  # Should not raise

    def test_signal_handler_shutdown_state(self):
        """SignalHandler tracks shutdown state."""
        handler = SignalHandler()

        assert not handler.isShuttingDown()
        handler._executeShutdownCallbacks()
        assert handler.isShuttingDown()


# ============================================================================
# Integration Tests
# ============================================================================

class TestResourceCleanupIntegration:
    """Integration tests for resource cleanup across components."""

    def test_full_monitoring_lifecycle_with_cleanup(self):
        """Full monitoring lifecycle with proper resource cleanup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_path = Path(tmpdir) / "monitor"
            monitor_path.mkdir()
            db_path = Path(tmpdir) / "test.db"

            # Initialize with context manager
            with DetectionController(monitor_path, db_path) as controller:
                # Create session
                controller.startSession()

                # Collect events (will be empty but tests the path)
                decision = controller.collectOnce()
                assert decision is not None

            # After context exit, everything should be cleaned up
            assert controller._closed

            # Verify database connection pool closed
            closeDatabase()

    def test_signal_handler_with_controller_cleanup(self):
        """Signal handler coordinates with controller cleanup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_path = Path(tmpdir) / "monitor"
            monitor_path.mkdir()
            db_path = Path(tmpdir) / "test.db"

            controller = DetectionController(monitor_path, db_path)
            handler = SignalHandler()

            # Register controller cleanup as shutdown callback
            handler.registerCallback(controller.close)

            # Trigger shutdown
            handler._executeShutdownCallbacks()

            # Controller should be closed
            assert controller._closed


# ============================================================================
# Performance Tests
# ============================================================================

class TestResourceCleanupPerformance:
    """Test resource cleanup performance."""

    def test_connection_pool_throughput(self):
        """Connection pool handles many acquire/release cycles efficiently."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            pool = ConnectionPool(db_path, poolSize=5)

            start_time = time.time()
            iterations = 100

            for _ in range(iterations):
                with pool.getConnection() as conn:
                    conn.execute("SELECT 1")

            elapsed = time.time() - start_time
            ops_per_sec = iterations / elapsed

            # Should handle at least 50 ops/sec (very conservative)
            assert ops_per_sec > 50, f"Only {ops_per_sec:.1f} ops/sec"

            pool.close()

    def test_controller_cleanup_time(self):
        """Controller cleanup completes quickly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_path = Path(tmpdir) / "monitor"
            monitor_path.mkdir()
            db_path = Path(tmpdir) / "test.db"

            controller = DetectionController(monitor_path, db_path)
            controller.startSession()

            start_time = time.time()
            controller.close()
            elapsed = time.time() - start_time

            # Cleanup should be fast (< 1 second)
            assert elapsed < 1.0, f"Cleanup took {elapsed:.2f}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
