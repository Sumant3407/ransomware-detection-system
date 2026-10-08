"""SQLite persistence foundation with connection pooling, performance indexes, and forensic storage."""

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from app.storage.connectionPool import ConnectionPool

logger = logging.getLogger(__name__)

schemaVersion = 1

# Global connection pool instance
_connectionPool: ConnectionPool | None = None


def initializeDatabase(databasePath: Path, poolSize: int = 5) -> sqlite3.Connection:
    """
    Initialize database schema and return a single connection.

    In production, use the pool via getPooledConnection() instead.
    This function creates the schema and returns a direct connection.

    Args:
        databasePath: Path to SQLite database file
        poolSize: Maximum connections in pool (used if pool created)

    Returns:
        sqlite3.Connection for direct use
    """
    global _connectionPool

    databasePath.parent.mkdir(parents=True, exist_ok=True)

    # Create a temporary connection for schema initialization
    connection = sqlite3.connect(str(databasePath), timeout=30.0)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")

    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS schemaVersion (
                version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                sessionId INTEGER PRIMARY KEY,
                startedAt TEXT NOT NULL,
                endedAt TEXT
            );
            CREATE TABLE IF NOT EXISTS fileEvents (
                eventId INTEGER PRIMARY KEY,
                sessionId INTEGER,
                occurredAt TEXT NOT NULL,
                action TEXT NOT NULL,
                pathHash TEXT NOT NULL,
                source TEXT NOT NULL,
                pathId INTEGER,
                processId INTEGER,
                processName TEXT,
                parentProcessId INTEGER,
                oldPathHash TEXT,
                FOREIGN KEY (sessionId) REFERENCES sessions(sessionId),
                FOREIGN KEY (pathId) REFERENCES monitoredPaths(pathId)
            );
            CREATE TABLE IF NOT EXISTS detections (
                detectionId INTEGER PRIMARY KEY,
                sessionId INTEGER,
                occurredAt TEXT NOT NULL,
                classification TEXT NOT NULL,
                riskScore REAL NOT NULL,
                actionTaken TEXT NOT NULL,
                FOREIGN KEY (sessionId) REFERENCES sessions(sessionId)
            );
            CREATE TABLE IF NOT EXISTS models (
                modelId INTEGER PRIMARY KEY,
                version TEXT NOT NULL UNIQUE,
                createdAt TEXT NOT NULL,
                artifactPath TEXT NOT NULL,
                checksum TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metricSamples (
                sampleId INTEGER PRIMARY KEY,
                sessionId INTEGER,
                occurredAt TEXT NOT NULL,
                schemaVersion TEXT NOT NULL,
                valuesJson TEXT NOT NULL,
                FOREIGN KEY (sessionId) REFERENCES sessions(sessionId)
            );
            CREATE TABLE IF NOT EXISTS alerts (
                alertId INTEGER PRIMARY KEY,
                detectionId INTEGER,
                occurredAt TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (detectionId) REFERENCES detections(detectionId)
            );
            CREATE TABLE IF NOT EXISTS modelMetrics (
                metricId INTEGER PRIMARY KEY,
                modelId INTEGER,
                metricName TEXT NOT NULL,
                metricValue REAL NOT NULL,
                FOREIGN KEY (modelId) REFERENCES models(modelId)
            );
            CREATE TABLE IF NOT EXISTS unlearningOperations (
                operationId INTEGER PRIMARY KEY,
                startedAt TEXT NOT NULL,
                completedAt TEXT,
                scope TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                reportJson TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS systemStatus (
                statusId INTEGER PRIMARY KEY CHECK (statusId = 1),
                updatedAt TEXT NOT NULL,
                protectionState TEXT NOT NULL,
                modelState TEXT NOT NULL,
                monitoringState TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS monitoredPaths (
                pathId INTEGER PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                createdAt TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS detectionFeedback (
                feedbackId INTEGER PRIMARY KEY,
                detectionId INTEGER,
                sampleValuesJson TEXT NOT NULL,
                predictedClass TEXT NOT NULL,
                actualLabel TEXT NOT NULL,
                confidence REAL,
                feedbackAt TEXT NOT NULL,
                usedInRetraining INTEGER NOT NULL DEFAULT 0,
                retrainedAt TEXT,
                FOREIGN KEY (detectionId) REFERENCES detections(detectionId)
            );
            CREATE TABLE IF NOT EXISTS retrainingRuns (
                runId INTEGER PRIMARY KEY,
                startedAt TEXT NOT NULL,
                completedAt TEXT,
                triggerType TEXT NOT NULL,
                sampleCount INTEGER NOT NULL,
                feedbackSampleCount INTEGER NOT NULL,
                baselineModelVersion TEXT NOT NULL,
                candidateModelVersion TEXT NOT NULL,
                cvAccuracy REAL NOT NULL,
                cvF1 REAL NOT NULL,
                cvRocAuc REAL,
                baselineF1 REAL,
                promoted INTEGER NOT NULL DEFAULT 0,
                rollbackReady INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL,
                reportJson TEXT
            );
            CREATE TABLE IF NOT EXISTS forensicSnapshots (
                snapshotId INTEGER PRIMARY KEY,
                detectionId INTEGER,
                sessionId INTEGER,
                capturedAt TEXT NOT NULL,
                processId INTEGER,
                processName TEXT,
                parentProcessId INTEGER,
                processCommandLine TEXT,
                processPath TEXT,
                processUser TEXT,
                processTreeJson TEXT,
                openHandlesCount INTEGER,
                cpuPercent REAL,
                memoryRssMb REAL,
                monitoredPath TEXT,
                targetFileHash TEXT,
                targetFilePath TEXT,
                featureSnapshotJson TEXT,
                riskScore REAL,
                classification TEXT,
                metadataJson TEXT,
                FOREIGN KEY (detectionId) REFERENCES detections(detectionId),
                FOREIGN KEY (sessionId) REFERENCES sessions(sessionId)
            );

            -- Core Query Performance Indexes
            CREATE INDEX IF NOT EXISTS fileEventsOccurredAtIndex ON fileEvents (occurredAt);
            CREATE INDEX IF NOT EXISTS fileEventsPathIdIndex ON fileEvents (pathId);
            CREATE INDEX IF NOT EXISTS fileEventsProcessIdIndex ON fileEvents (processId);
            CREATE INDEX IF NOT EXISTS fileEventsProcessNameIndex ON fileEvents (processName);
            CREATE INDEX IF NOT EXISTS fileEventsSessionOccurredIndex ON fileEvents (sessionId, occurredAt);
            CREATE INDEX IF NOT EXISTS detectionsOccurredAtIndex ON detections (occurredAt);
            CREATE INDEX IF NOT EXISTS detectionsRiskScoreIndex ON detections (riskScore);
            CREATE INDEX IF NOT EXISTS detectionsSessionIdIndex ON detections (sessionId);
            CREATE INDEX IF NOT EXISTS alertsOccurredAtIndex ON alerts (occurredAt);
            CREATE INDEX IF NOT EXISTS alertsSeverityIndex ON alerts (severity, occurredAt);
            CREATE INDEX IF NOT EXISTS alertsDetectionIdIndex ON alerts (detectionId);
            CREATE INDEX IF NOT EXISTS forensicSnapshotsDetectionIdIndex ON forensicSnapshots (detectionId);
            CREATE INDEX IF NOT EXISTS forensicSnapshotsCapturedAtIndex ON forensicSnapshots (capturedAt);
            CREATE INDEX IF NOT EXISTS forensicSnapshotsProcessIdIndex ON forensicSnapshots (processId);
            CREATE INDEX IF NOT EXISTS forensicSnapshotsSessionIdIndex ON forensicSnapshots (sessionId);
            CREATE INDEX IF NOT EXISTS detectionFeedbackUsedIndex ON detectionFeedback (usedInRetraining);
            CREATE INDEX IF NOT EXISTS detectionFeedbackAt ON detectionFeedback (feedbackAt);
            CREATE INDEX IF NOT EXISTS retrainingRunsStartedAtIndex ON retrainingRuns (startedAt);
            """
        )

        migrateSchema(connection)

        existingVersion = connection.execute(
            "SELECT version FROM schemaVersion LIMIT 1"
        ).fetchone()
        if existingVersion is None:
            connection.execute("INSERT INTO schemaVersion (version) VALUES (?)", (schemaVersion,))
        elif existingVersion[0] != schemaVersion:
            connection.close()
            raise RuntimeError("Unsupported database schema version")

        connection.commit()
        logger.info(f"Database initialized: {databasePath}")

    except Exception as error:
        connection.close()
        logger.error(f"Failed to initialize database: {error}")
        raise

    # Initialize global connection pool
    if _connectionPool is None:
        _connectionPool = ConnectionPool(databasePath, poolSize=poolSize, timeout=30.0)
        logger.debug(f"Connection pool created: poolSize={poolSize}")

    return connection


def migrateSchema(connection: sqlite3.Connection) -> None:
    """
    Migrate existing database schemas to support current feature set.

    Args:
        connection: Open SQLite connection
    """
    try:
        cursor = connection.execute("PRAGMA table_info(fileEvents)")
        columns = [row[1] for row in cursor.fetchall()]

        if "pathId" not in columns:
            logger.info("Migrating schema: Adding pathId column to fileEvents table")
            connection.execute(
                "ALTER TABLE fileEvents ADD COLUMN pathId INTEGER REFERENCES monitoredPaths(pathId)"
            )

        if "processId" not in columns:
            logger.info("Migrating schema: Adding processId column to fileEvents table")
            connection.execute(
                "ALTER TABLE fileEvents ADD COLUMN processId INTEGER"
            )

        if "processName" not in columns:
            logger.info("Migrating schema: Adding processName column to fileEvents table")
            connection.execute(
                "ALTER TABLE fileEvents ADD COLUMN processName TEXT"
            )

        if "parentProcessId" not in columns:
            logger.info("Migrating schema: Adding parentProcessId column to fileEvents table")
            connection.execute(
                "ALTER TABLE fileEvents ADD COLUMN parentProcessId INTEGER"
            )

        if "oldPathHash" not in columns:
            logger.info("Migrating schema: Adding oldPathHash column to fileEvents table")
            connection.execute(
                "ALTER TABLE fileEvents ADD COLUMN oldPathHash TEXT"
            )

        # Migrate and ensure modern tables exist before creating indexes
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                sessionId INTEGER PRIMARY KEY,
                startedAt TEXT NOT NULL,
                endedAt TEXT
            );
            CREATE TABLE IF NOT EXISTS monitoredPaths (
                pathId INTEGER PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                createdAt TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS detections (
                detectionId INTEGER PRIMARY KEY,
                sessionId INTEGER,
                occurredAt TEXT NOT NULL,
                classification TEXT NOT NULL,
                riskScore REAL NOT NULL,
                actionTaken TEXT NOT NULL,
                FOREIGN KEY (sessionId) REFERENCES sessions(sessionId)
            );
            CREATE TABLE IF NOT EXISTS alerts (
                alertId INTEGER PRIMARY KEY,
                detectionId INTEGER,
                occurredAt TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (detectionId) REFERENCES detections(detectionId)
            );
            CREATE TABLE IF NOT EXISTS forensicSnapshots (
                snapshotId INTEGER PRIMARY KEY,
                detectionId INTEGER,
                sessionId INTEGER,
                capturedAt TEXT NOT NULL,
                processId INTEGER,
                processName TEXT,
                parentProcessId INTEGER,
                processCommandLine TEXT,
                processPath TEXT,
                processUser TEXT,
                processTreeJson TEXT,
                openHandlesCount INTEGER,
                cpuPercent REAL,
                memoryRssMb REAL,
                monitoredPath TEXT,
                targetFileHash TEXT,
                targetFilePath TEXT,
                featureSnapshotJson TEXT,
                riskScore REAL,
                classification TEXT,
                metadataJson TEXT,
                FOREIGN KEY (detectionId) REFERENCES detections(detectionId),
                FOREIGN KEY (sessionId) REFERENCES sessions(sessionId)
            );
            CREATE TABLE IF NOT EXISTS detectionFeedback (
                feedbackId INTEGER PRIMARY KEY,
                detectionId INTEGER,
                sampleValuesJson TEXT NOT NULL,
                predictedClass TEXT NOT NULL,
                actualLabel TEXT NOT NULL,
                confidence REAL,
                feedbackAt TEXT NOT NULL,
                usedInRetraining INTEGER NOT NULL DEFAULT 0,
                retrainedAt TEXT,
                FOREIGN KEY (detectionId) REFERENCES detections(detectionId)
            );
            CREATE TABLE IF NOT EXISTS retrainingRuns (
                runId INTEGER PRIMARY KEY,
                startedAt TEXT NOT NULL,
                completedAt TEXT,
                triggerType TEXT NOT NULL,
                sampleCount INTEGER NOT NULL,
                feedbackSampleCount INTEGER NOT NULL,
                baselineModelVersion TEXT NOT NULL,
                candidateModelVersion TEXT NOT NULL,
                cvAccuracy REAL NOT NULL,
                cvF1 REAL NOT NULL,
                cvRocAuc REAL,
                baselineF1 REAL,
                promoted INTEGER NOT NULL DEFAULT 0,
                rollbackReady INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL,
                reportJson TEXT
            );

            -- Performance and lookup indexes
            CREATE INDEX IF NOT EXISTS fileEventsPathIdIndex ON fileEvents (pathId);
            CREATE INDEX IF NOT EXISTS fileEventsProcessIdIndex ON fileEvents (processId);
            CREATE INDEX IF NOT EXISTS fileEventsProcessNameIndex ON fileEvents (processName);
            CREATE INDEX IF NOT EXISTS fileEventsSessionOccurredIndex ON fileEvents (sessionId, occurredAt);
            CREATE INDEX IF NOT EXISTS detectionsOccurredAtIndex ON detections (occurredAt);
            CREATE INDEX IF NOT EXISTS detectionsRiskScoreIndex ON detections (riskScore);
            CREATE INDEX IF NOT EXISTS detectionsSessionIdIndex ON detections (sessionId);
            CREATE INDEX IF NOT EXISTS alertsOccurredAtIndex ON alerts (occurredAt);
            CREATE INDEX IF NOT EXISTS alertsSeverityIndex ON alerts (severity, occurredAt);
            CREATE INDEX IF NOT EXISTS alertsDetectionIdIndex ON alerts (detectionId);
            CREATE INDEX IF NOT EXISTS forensicSnapshotsDetectionIdIndex ON forensicSnapshots (detectionId);
            CREATE INDEX IF NOT EXISTS forensicSnapshotsCapturedAtIndex ON forensicSnapshots (capturedAt);
            CREATE INDEX IF NOT EXISTS forensicSnapshotsProcessIdIndex ON forensicSnapshots (processId);
            CREATE INDEX IF NOT EXISTS forensicSnapshotsSessionIdIndex ON forensicSnapshots (sessionId);
            CREATE INDEX IF NOT EXISTS detectionFeedbackUsedIndex ON detectionFeedback (usedInRetraining);
            CREATE INDEX IF NOT EXISTS detectionFeedbackAt ON detectionFeedback (feedbackAt);
            CREATE INDEX IF NOT EXISTS retrainingRunsStartedAtIndex ON retrainingRuns (startedAt);
            """
        )
    except Exception as error:
        logger.warning(f"Schema migration warning: {error}")


def registerMonitoredPath(connection: sqlite3.Connection, path: Path | str) -> int:
    """
    Register a path in monitoredPaths if not already registered and return its pathId.

    Args:
        connection: SQLite connection
        path: Directory path (as Path or str)

    Returns:
        Integer pathId
    """
    canonical = str(Path(path).resolve())
    cursor = connection.execute(
        "SELECT pathId FROM monitoredPaths WHERE path = ?", (canonical,)
    )
    row = cursor.fetchone()
    if row is not None:
        return row[0]

    cursor = connection.execute(
        "INSERT INTO monitoredPaths (path, enabled, createdAt) VALUES (?, 1, datetime('now'))",
        (canonical,),
    )
    return cursor.lastrowid


def getMonitoredPathId(connection: sqlite3.Connection, path: Path | str) -> int | None:
    """
    Get pathId for a monitored path, or None if not registered.

    Args:
        connection: SQLite connection
        path: Directory path

    Returns:
        Integer pathId or None
    """
    canonical = str(Path(path).resolve())
    cursor = connection.execute(
        "SELECT pathId FROM monitoredPaths WHERE path = ?", (canonical,)
    )
    row = cursor.fetchone()
    return row[0] if row is not None else None


def getAllMonitoredPaths(connection: sqlite3.Connection) -> list[dict]:
    """
    Get all registered monitored paths.

    Args:
        connection: SQLite connection

    Returns:
        List of dictionaries with pathId, path, enabled, createdAt
    """
    cursor = connection.execute(
        "SELECT pathId, path, enabled, createdAt FROM monitoredPaths ORDER BY pathId ASC"
    )
    return [
        {"pathId": row[0], "path": row[1], "enabled": bool(row[2]), "createdAt": row[3]}
        for row in cursor.fetchall()
    ]


def getPooledConnection() -> ConnectionPool:
    """
    Get the global connection pool for pooled database access.

    Usage:
        pool = getPooledConnection()
        with pool.getConnection() as conn:
            conn.execute(...)
            conn.commit()

    Returns:
        ConnectionPool instance for context manager usage

    Raises:
        RuntimeError: If database not initialized yet
    """
    global _connectionPool
    if _connectionPool is None:
        raise RuntimeError("Database not initialized. Call initializeDatabase() first.")
    return _connectionPool


def closeDatabase() -> None:
    """
    Close the connection pool and release all connections.

    Safe to call multiple times (idempotent).
    Should be called at application shutdown.
    """
    global _connectionPool
    if _connectionPool is not None:
        try:
            _connectionPool.close()
            logger.info("Connection pool closed")
        except Exception as error:
            logger.warning(f"Error closing connection pool: {error}")
        finally:
            _connectionPool = None


# ============================================================================
# Database Performance, Pruning & Maintenance Operations
# ============================================================================

def pruneOldData(
    connection: sqlite3.Connection,
    retentionDays: int = 30,
    preserveThreats: bool = True,
) -> dict[str, int]:
    """
    Purge telemetry events and metric samples older than the retention threshold.

    Args:
        connection: Open SQLite connection
        retentionDays: Number of days to retain historical events
        preserveThreats: If True, retains detections, alerts, forensic evidence, and threat events

    Returns:
        Dictionary mapping table name to number of rows pruned.
    """
    cutoffDate = (datetime.now(timezone.utc) - timedelta(days=max(1, retentionDays))).isoformat()
    prunedCounts: dict[str, int] = {}

    try:
        # 1. Prune metric samples older than cutoff
        cursor = connection.execute(
            "DELETE FROM metricSamples WHERE occurredAt < ?",
            (cutoffDate,),
        )
        prunedCounts["metricSamples"] = cursor.rowcount

        # 2. Prune benign file events older than cutoff
        if preserveThreats:
            # Delete fileEvents that are not attributed to active detections
            cursor = connection.execute(
                """
                DELETE FROM fileEvents
                WHERE occurredAt < ?
                  AND sessionId NOT IN (
                      SELECT DISTINCT sessionId FROM detections WHERE classification != 'benign'
                  )
                """,
                (cutoffDate,),
            )
        else:
            cursor = connection.execute(
                "DELETE FROM fileEvents WHERE occurredAt < ?",
                (cutoffDate,),
            )
        prunedCounts["fileEvents"] = cursor.rowcount

        # 3. Clean up inactive orphaned sessions
        cursor = connection.execute(
            """
            DELETE FROM sessions
            WHERE endedAt IS NOT NULL
              AND endedAt < ?
              AND sessionId NOT IN (SELECT DISTINCT sessionId FROM detections)
              AND sessionId NOT IN (SELECT DISTINCT sessionId FROM fileEvents)
              AND sessionId NOT IN (SELECT DISTINCT sessionId FROM metricSamples)
            """,
            (cutoffDate,),
        )
        prunedCounts["sessions"] = cursor.rowcount

        connection.commit()
        logger.info(
            f"Database pruning completed (retention: {retentionDays}d): {prunedCounts}"
        )
        return prunedCounts

    except Exception as error:
        connection.rollback()
        logger.error(f"Failed to prune old database records: {error}")
        raise


def optimizeDatabase(connection: sqlite3.Connection) -> dict[str, Any]:
    """
    Run SQLite query optimization, analyze statistics, and perform WAL maintenance.

    Returns:
        Dictionary containing optimization metrics and database page statistics.
    """
    try:
        # Run internal query optimizer and index statistics update
        connection.execute("PRAGMA optimize")
        connection.execute("PRAGMA analyze")

        # Checkpoint WAL log back to main database file
        walResult = connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        walCheckpointStatus = {
            "busy": walResult[0] if walResult else 0,
            "logPages": walResult[1] if walResult else 0,
            "checkpointedPages": walResult[2] if walResult else 0,
        }

        # Collect page allocation statistics
        pageSize = connection.execute("PRAGMA page_size").fetchone()[0]
        pageCount = connection.execute("PRAGMA page_count").fetchone()[0]
        freelistCount = connection.execute("PRAGMA freelist_count").fetchone()[0]

        totalSizeBytes = pageSize * pageCount
        freeSizeBytes = pageSize * freelistCount

        stats = {
            "pageSizeBytes": pageSize,
            "pageCount": pageCount,
            "freelistPages": freelistCount,
            "totalSizeBytes": totalSizeBytes,
            "freeSizeBytes": freeSizeBytes,
            "walCheckpoint": walCheckpointStatus,
            "status": "optimized",
        }
        logger.info(f"Database optimization complete: totalSize={totalSizeBytes} bytes")
        return stats

    except Exception as error:
        logger.error(f"Error optimizing database: {error}")
        return {"status": "error", "error": str(error)}


def getDatabaseStatistics(connection: sqlite3.Connection) -> dict[str, Any]:
    """
    Gather comprehensive table row counts and diagnostic metrics.

    Returns:
        Dictionary with record counts, index count, and storage details.
    """
    tables = [
        "fileEvents",
        "detections",
        "alerts",
        "forensicSnapshots",
        "metricSamples",
        "sessions",
        "monitoredPaths",
        "models",
        "detectionFeedback",
        "retrainingRuns",
    ]

    counts: dict[str, int] = {}
    for table in tables:
        try:
            row = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            counts[table] = row[0] if row else 0
        except Exception:
            counts[table] = 0

    try:
        indexRows = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index'"
        ).fetchone()
        indexCount = indexRows[0] if indexRows else 0
    except Exception:
        indexCount = 0

    pageSize = connection.execute("PRAGMA page_size").fetchone()[0]
    pageCount = connection.execute("PRAGMA page_count").fetchone()[0]

    return {
        "tableCounts": counts,
        "indexCount": indexCount,
        "databaseSizeBytes": pageSize * pageCount,
        "pageCount": pageCount,
        "pageSize": pageSize,
    }


# ============================================================================
# Detection Feedback & Retraining Operations
# ============================================================================

def recordDetectionFeedback(
    connection: sqlite3.Connection,
    sampleValues: dict[str, float],
    predictedClass: str,
    actualLabel: str,
    detectionId: int | None = None,
    confidence: float | None = None,
    feedbackAt: str | None = None,
) -> int:
    """
    Record user/analyst feedback on a detection or feature sample.

    Args:
        connection: SQLite connection
        sampleValues: Dictionary mapping feature column names to float values
        predictedClass: Model's predicted classification (e.g. 'ransomwareLike', 'benign')
        actualLabel: Confirmed true label ('Benign' or 'Ransomware')
        detectionId: Optional ID of the associated detection
        confidence: Optional confidence score
        feedbackAt: ISO timestamp of feedback (default: current UTC time)

    Returns:
        Integer feedbackId
    """
    import json
    from datetime import datetime, timezone

    now = feedbackAt or datetime.now(timezone.utc).isoformat()
    cursor = connection.execute(
        """
        INSERT INTO detectionFeedback (
            detectionId, sampleValuesJson, predictedClass, actualLabel, confidence, feedbackAt, usedInRetraining
        ) VALUES (?, ?, ?, ?, ?, ?, 0)
        """,
        (detectionId, json.dumps(sampleValues), predictedClass, actualLabel, confidence, now),
    )
    return cursor.lastrowid


def getUnusedDetectionFeedback(
    connection: sqlite3.Connection,
    limit: int | None = None,
) -> list[dict]:
    """
    Fetch all feedback records that have not yet been consumed in a retraining cycle.

    Args:
        connection: SQLite connection
        limit: Optional maximum number of records

    Returns:
        List of feedback dictionaries with parsed sampleValues
    """
    import json

    query = """
        SELECT feedbackId, detectionId, sampleValuesJson, predictedClass, actualLabel, confidence, feedbackAt
        FROM detectionFeedback
        WHERE usedInRetraining = 0
        ORDER BY feedbackId ASC
    """
    if limit is not None:
        query += f" LIMIT {int(limit)}"

    cursor = connection.execute(query)
    rows = cursor.fetchall()
    results = []
    for row in rows:
        results.append({
            "feedbackId": row[0],
            "detectionId": row[1],
            "sampleValues": json.loads(row[2]),
            "predictedClass": row[3],
            "actualLabel": row[4],
            "confidence": row[5],
            "feedbackAt": row[6],
        })
    return results


def markFeedbackUsedInRetraining(
    connection: sqlite3.Connection,
    feedbackIds: list[int],
    retrainedAt: str | None = None,
) -> int:
    """
    Mark feedback records as incorporated into a retraining cycle.

    Args:
        connection: SQLite connection
        feedbackIds: List of feedbackId integers
        retrainedAt: ISO timestamp of retraining completion

    Returns:
        Number of updated rows
    """
    from datetime import datetime, timezone

    if not feedbackIds:
        return 0

    now = retrainedAt or datetime.now(timezone.utc).isoformat()
    placeholders = ",".join("?" for _ in feedbackIds)
    cursor = connection.execute(
        f"UPDATE detectionFeedback SET usedInRetraining = 1, retrainedAt = ? WHERE feedbackId IN ({placeholders})",
        [now, *feedbackIds],
    )
    return cursor.rowcount


def recordRetrainingRun(
    connection: sqlite3.Connection,
    startedAt: str,
    completedAt: str | None,
    triggerType: str,
    sampleCount: int,
    feedbackSampleCount: int,
    baselineModelVersion: str,
    candidateModelVersion: str,
    cvAccuracy: float,
    cvF1: float,
    cvRocAuc: float | None,
    baselineF1: float | None,
    promoted: bool,
    status: str,
    rollbackReady: bool = True,
    reportJson: str | None = None,
) -> int:
    """
    Record an automated or manual model retraining cycle and its validation outcome.
    """
    cursor = connection.execute(
        """
        INSERT INTO retrainingRuns (
            startedAt, completedAt, triggerType, sampleCount, feedbackSampleCount,
            baselineModelVersion, candidateModelVersion, cvAccuracy, cvF1, cvRocAuc,
            baselineF1, promoted, rollbackReady, status, reportJson
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            startedAt,
            completedAt,
            triggerType,
            sampleCount,
            feedbackSampleCount,
            baselineModelVersion,
            candidateModelVersion,
            cvAccuracy,
            cvF1,
            cvRocAuc,
            baselineF1,
            1 if promoted else 0,
            1 if rollbackReady else 0,
            status,
            reportJson,
        ),
    )
    return cursor.lastrowid


def getLatestRetrainingRuns(
    connection: sqlite3.Connection,
    limit: int = 10,
) -> list[dict]:
    """
    Fetch the most recent model retraining runs and their outcomes.
    """
    import json

    cursor = connection.execute(
        """
        SELECT runId, startedAt, completedAt, triggerType, sampleCount, feedbackSampleCount,
               baselineModelVersion, candidateModelVersion, cvAccuracy, cvF1, cvRocAuc,
               baselineF1, promoted, rollbackReady, status, reportJson
        FROM retrainingRuns
        ORDER BY runId DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    results = []
    for row in rows:
        results.append({
            "runId": row[0],
            "startedAt": row[1],
            "completedAt": row[2],
            "triggerType": row[3],
            "sampleCount": row[4],
            "feedbackSampleCount": row[5],
            "baselineModelVersion": row[6],
            "candidateModelVersion": row[7],
            "cvAccuracy": row[8],
            "cvF1": row[9],
            "cvRocAuc": row[10],
            "baselineF1": row[11],
            "promoted": bool(row[12]),
            "rollbackReady": bool(row[13]),
            "status": row[14],
            "report": json.loads(row[15]) if row[15] else None,
        })
    return results
