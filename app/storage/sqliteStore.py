"""SQLite persistence foundation."""

import sqlite3
from pathlib import Path


schemaVersion = 1


def initializeDatabase(databasePath: Path) -> sqlite3.Connection:
    databasePath.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(databasePath)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
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
            FOREIGN KEY (sessionId) REFERENCES sessions(sessionId)
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
        CREATE INDEX IF NOT EXISTS fileEventsOccurredAtIndex ON fileEvents (occurredAt);
        CREATE INDEX IF NOT EXISTS detectionsOccurredAtIndex ON detections (occurredAt);
        CREATE INDEX IF NOT EXISTS alertsOccurredAtIndex ON alerts (occurredAt);
        """
    )
    existingVersion = connection.execute(
        "SELECT version FROM schemaVersion LIMIT 1"
    ).fetchone()
    if existingVersion is None:
        connection.execute("INSERT INTO schemaVersion (version) VALUES (?)", (schemaVersion,))
    elif existingVersion[0] != schemaVersion:
        connection.close()
        raise RuntimeError("Unsupported database schema version")
    connection.commit()
    return connection
