"""Headless monitoring controller with bounded polling and safe decisions."""

import time
from pathlib import Path

from app.storage.sqliteStore import initializeDatabase
from app.config.configuration import getDataDirectory
from app.security.pathPrivacy import getPathIdentifier
from app.detection.predictor import ModelPredictor, ModelValidationError
from app.detection.alertPolicy import AlertPolicy
from app.detection.riskEngine import RiskDecision, evaluateRisk
from app.features.windowing import FeatureWindow
from app.monitoring.fileEvents import PollingFileEventSource
from app.monitoring.systemMetrics import SystemMetricsSource
from app.monitoring.windowsFileEvents import WindowsFileEventSource, WindowsWatcherUnavailable


class DetectionController:
    """Headless monitoring controller with context manager support."""

    def __init__(self, monitoredPath: Path, databasePath: Path, modelPath: Path | None = None, alertCooldownSeconds: int = 60):
        self.monitoredPath = monitoredPath.resolve()
        self.databasePath = databasePath
        self.modelPredictor = None
        self.modelState = "unavailable"
        if modelPath is not None:
            try:
                self.modelPredictor = ModelPredictor(modelPath)
                self.modelState = "ready"
            except ModelValidationError as error:
                self.modelState = f"invalid: {error}"
        try:
            self.eventSource = WindowsFileEventSource(self.monitoredPath)
        except WindowsWatcherUnavailable:
            self.eventSource = PollingFileEventSource(self.monitoredPath)
        self.systemMetrics = SystemMetricsSource()
        self.featureWindow = FeatureWindow()
        self.alertPolicy = AlertPolicy(alertCooldownSeconds)
        self.pendingCommitCount = 0
        self.connection = initializeDatabase(databasePath)
        self.connection.execute(
            "INSERT OR REPLACE INTO systemStatus (statusId, updatedAt, protectionState, modelState, monitoringState) VALUES (1, datetime('now'), ?, ?, ?)",
            ("protected", self.modelState, "ready"),
        )
        self.connection.commit()
        self.sessionId = None
        self.lastEventSummary = "No recent file activity."
        self.lastCollectedEventCount = 0

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with guaranteed cleanup."""
        self.close()
        return False

    def startSession(self) -> int:
        cursor = self.connection.execute(
            "INSERT INTO sessions (startedAt) VALUES (datetime('now'))"
        )
        self.connection.commit()
        self.sessionId = cursor.lastrowid
        return self.sessionId

    def collectOnce(self) -> RiskDecision:
        if self.sessionId is None:
            self.startSession()
        events = self.eventSource.collectEvents()
        self.featureWindow.addEvents(events)
        for event in events:
            self.connection.execute(
                "INSERT INTO fileEvents (sessionId, occurredAt, action, pathHash, source) VALUES (?, ?, ?, ?, ?)",
                (
                    self.sessionId,
                    event.occurredAt.isoformat(),
                    event.action.value,
                    getPathIdentifier(event.path, getDataDirectory() / "path.key"),
                    event.source,
                ),
            )
        self.lastCollectedEventCount = len(events)
        if events:
            latestEvent = events[-1]
            self.lastEventSummary = (
                f"{latestEvent.action.value}  •  {Path(latestEvent.path).name}"
            )

        metrics = self.systemMetrics.collect()
        sample = self.featureWindow.createSample(
            processCpuUsage=metrics.cpuUsage,
            processMemoryUsage=metrics.memoryUsage,
            networkBytes=metrics.networkBytes,
            networkConnectionCount=metrics.networkConnectionCount,
        )
        probability = 0.0
        if self.modelPredictor is not None:
            probability = self.modelPredictor.predictProbability(sample.values)
        decision = evaluateRisk(
            probability,
            sample.values["filesModifiedPerMinute"],
            sample.values["fileRenameCount"],
            sample.values["fileDeleteCount"],
        )
        if decision.level.value != "low":
            self.connection.execute(
                "INSERT INTO detections (sessionId, occurredAt, classification, riskScore, actionTaken) VALUES (?, datetime('now'), ?, ?, ?)",
                (self.sessionId, decision.classification, decision.score, decision.action),
            )
            if self.alertPolicy.shouldAlert(decision):
                self.connection.execute(
                    "INSERT INTO alerts (detectionId, occurredAt, severity, message) VALUES (last_insert_rowid(), datetime('now'), ?, ?)",
                    (decision.level.value, f"Behavior classified as {decision.classification}"),
                )
                self.alertPolicy.recordAlert(decision)
        # Commit event rows immediately so the GUI can see every batch
        # without waiting for ten monitoring cycles.
        if events:
            self.connection.commit()
            self.pendingCommitCount = 0
        else:
            self.pendingCommitCount += 1
            if self.pendingCommitCount >= 10:
                self.connection.commit()
                self.pendingCommitCount = 0
        return decision

    def run(self, intervalSeconds: float = 1.0, sampleLimit: int | None = None) -> None:
        sampleCount = 0
        try:
            while sampleLimit is None or sampleCount < sampleLimit:
                self.collectOnce()
                sampleCount += 1
                time.sleep(max(0.1, intervalSeconds))
        finally:
            self.close()

    def close(self) -> None:
        if self.connection is not None:
            if self.sessionId is not None:
                self.connection.execute(
                    "UPDATE sessions SET endedAt = datetime('now') WHERE sessionId = ?",
                    (self.sessionId,),
                )
                self.connection.commit()
            self.connection.close()
            self.connection = None
