"""SQLite connection pooling and resource management."""

import sqlite3
import logging
import threading
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class ConnectionPool:
    """Simple connection pool for SQLite with thread-safety."""

    def __init__(self, databasePath: Path, poolSize: int = 5, timeout: float = 30.0):
        """
        Initialize connection pool.

        Args:
            databasePath: Path to SQLite database file
            poolSize: Maximum number of connections in pool
            timeout: Connection timeout in seconds
        """
        self.databasePath = databasePath
        self.poolSize = poolSize
        self.timeout = timeout
        self._connections = []
        self._lock = threading.RLock()
        self._available = threading.Semaphore(poolSize)
        self._initialized = False

        logger.debug(f"ConnectionPool initialized: path={databasePath}, poolSize={poolSize}")

    def _createConnection(self) -> sqlite3.Connection:
        """Create a new database connection."""
        try:
            # check_same_thread=False allows the pool to hand connections
            # between threads. Thread-safety is guaranteed by the pool's
            # RLock, which serializes all access to pooled connections.
            connection = sqlite3.connect(
                self.databasePath, timeout=self.timeout, check_same_thread=False
            )
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            logger.debug(f"Created new connection to {self.databasePath}")
            return connection
        except sqlite3.Error as error:
            logger.error(f"Failed to create database connection: {error}")
            raise

    @contextmanager
    def getConnection(self):
        """
        Get a connection from the pool as context manager.

        Usage:
            with pool.getConnection() as conn:
                conn.execute(...)
        """
        connection = None
        try:
            # Wait for available connection slot
            if not self._available.acquire(timeout=self.timeout):
                raise sqlite3.OperationalError("Connection pool exhausted")

            with self._lock:
                # Validate pooled connections on acquire - a connection left
                # in the pool may have gone stale (e.g. underlying file closed).
                while self._connections:
                    candidate = self._connections.pop()
                    try:
                        candidate.execute("SELECT 1")
                        connection = candidate
                        break
                    except sqlite3.Error:
                        logger.warning("Discarding stale pooled connection")
                        try:
                            candidate.close()
                        except Exception as closeError:
                            logger.debug(f"Error closing discarded connection: {closeError}")
                        candidate = None
                if connection is None:
                    connection = self._createConnection()

            logger.debug(f"Connection acquired from pool (remaining: {len(self._connections)})")
            yield connection

        except Exception as error:
            logger.error(f"Error getting connection from pool: {error}")
            if connection is not None:
                try:
                    connection.close()
                except Exception as closeError:
                    logger.debug(f"Error closing unreturned connection: {closeError}")
            raise

        finally:
            # Return connection to pool
            if connection is not None:
                try:
                    with self._lock:
                        # Verify connection is still valid
                        try:
                            connection.execute("SELECT 1")
                            self._connections.append(connection)
                            logger.debug(f"Connection returned to pool ({len(self._connections)}/{self.poolSize})")
                        except sqlite3.Error as error:
                            logger.warning(f"Connection invalid, closing: {error}")
                            connection.close()
                except Exception as error:
                    logger.error(f"Error returning connection to pool: {error}")

            # Release semaphore slot
            self._available.release()

    def close(self) -> None:
        """Close all connections in the pool."""
        with self._lock:
            for connection in self._connections:
                try:
                    connection.close()
                    logger.debug("Closed pooled connection")
                except Exception as error:
                    logger.warning(f"Error closing pooled connection: {error}")
            self._connections.clear()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.close()
        return False

    def __del__(self):
        """Ensure connections are closed on garbage collection."""
        try:
            self.close()
        except Exception as error:
            logger.debug(f"Error closing ConnectionPool in __del__: {error}")


class PooledDatabaseConnection:
    """Wrapper around pool-managed connection for transparent use."""

    def __init__(self, pool: ConnectionPool):
        """
        Initialize pooled connection wrapper.

        Args:
            pool: ConnectionPool instance
        """
        self.pool = pool
        self._connection = None
        self._context = None

    def execute(self, sql: str, parameters=None):
        """Execute SQL query."""
        if self._connection is None:
            raise RuntimeError("Connection not acquired")
        if parameters is None:
            return self._connection.execute(sql)
        return self._connection.execute(sql, parameters)

    def executescript(self, sql: str):
        """Execute SQL script."""
        if self._connection is None:
            raise RuntimeError("Connection not acquired")
        return self._connection.executescript(sql)

    def commit(self) -> None:
        """Commit transaction."""
        if self._connection is None:
            raise RuntimeError("Connection not acquired")
        self._connection.commit()

    def rollback(self) -> None:
        """Rollback transaction."""
        if self._connection is None:
            raise RuntimeError("Connection not acquired")
        self._connection.rollback()

    def close(self) -> None:
        """Close connection (returns to pool)."""
        if self._context is not None:
            try:
                self._context.__exit__(None, None, None)
            except Exception as error:
                logger.warning(f"Error closing pooled connection: {error}")
            self._context = None
            self._connection = None

    def __enter__(self):
        """Context manager entry - acquire connection from pool."""
        self._context = self.pool.getConnection()
        self._connection = self._context.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - return connection to pool."""
        if self._context is not None:
            return self._context.__exit__(exc_type, exc_val, exc_tb)
        return False

    def __del__(self):
        """Ensure connection is returned on garbage collection."""
        try:
            self.close()
        except Exception as error:
            logger.debug(f"Error closing PooledDatabaseConnection in __del__: {error}")
