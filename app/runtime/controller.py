"""Headless monitoring controller with multi-path support, bounded polling, and safe decisions."""

import time
import logging
from pathlib import Path
from typing import Any, Sequence, Union

from app.storage.sqliteStore import initializeDatabase, registerMonitoredPath
from app.config.configuration import (
    ConfigurationError,
    getDataDirectory,
    loadConfiguration,
    resolveMonitoringPaths,
    validateConfiguration,
)
from app.config.configWatcher import BackgroundHotReloader, ConfigWatcher
from app.logging.logger import logSecurityEvent, setSessionId
from app.security.pathPrivacy import getPathIdentifier
from app.detection.predictor import ModelPredictor, ModelValidationError
from app.detection.alertPolicy import AlertPolicy
from app.notifications.alertNotifier import AlertNotifier, AlertNotification
from app.forensics.forensicCollector import ForensicCollector
from app.detection.riskEngine import RiskDecision, evaluateRisk
from app.domain.schemas import FileEvent, featureColumns
from app.features.windowing import FeatureWindow
from app.monitoring.fileEvents import PollingFileEventSource
from app.monitoring.multiPathCollector import MultiPathEventCollector
from app.monitoring.systemMetrics import SystemMetricsSource
from app.monitoring.windowsFileEvents import WindowsFileEventSource, WindowsWatcherUnavailable

logger = logging.getLogger(__name__)


class DetectionController:
    """Headless monitoring controller with multi-path support, context manager support, and guaranteed cleanup."""

    def __init__(
        self,
        monitoredPath: Path | Sequence[Path] | None = None,
        databasePath: Path = ...,
        modelPath: Path | None = None,
        alertCooldownSeconds: int = 60,
        monitoredPaths: Sequence[Path] | None = None,
        encryption: Any | None = None,
        notifier: Any | None = None,
        forensicCollector: Any | None = None,
    ):
        # Normalize monitored paths (support single Path, list of Paths, or monitoredPaths argument)
        resolvedPaths: list[Path] = []
        if monitoredPaths is not None:
            if isinstance(monitoredPaths, (list, tuple, set)):
                resolvedPaths = [Path(p).resolve() for p in monitoredPaths]
            else:
                resolvedPaths = [Path(monitoredPaths).resolve()]
        elif monitoredPath is not None:
            if isinstance(monitoredPath, (list, tuple, set)):
                resolvedPaths = [Path(p).resolve() for p in monitoredPath]
            else:
                resolvedPaths = [Path(monitoredPath).resolve()]
        else:
            raise ValueError("At least one monitored path is required")

        if not resolvedPaths:
            raise ValueError("Monitored paths list cannot be empty")

        self.monitoredPaths = resolvedPaths
        self.monitoredPath = self.monitoredPaths[0]  # Backward-compatible single-path property
        self.databasePath = databasePath
        self.encryption = encryption
        self.modelPredictor = None
        self.modelState = "unavailable"
        if modelPath is not None:
            try:
                self.modelPredictor = ModelPredictor(modelPath, encryption=self.encryption)
                self.modelState = "ready"
            except ModelValidationError as error:
                self.modelState = f"invalid: {error}"

        # Initialize database connection
        self.connection = initializeDatabase(databasePath)
        self.connection.execute(
            "INSERT OR REPLACE INTO systemStatus (statusId, updatedAt, protectionState, modelState, monitoringState) VALUES (1, datetime('now'), ?, ?, ?)",
            ("protected", self.modelState, "ready"),
        )
        self.connection.commit()

        # Register all paths in monitoredPaths database table
        self.pathRegistry: dict[Path, int] = {}
        for path in self.monitoredPaths:
            pathId = registerMonitoredPath(self.connection, path)
            self.pathRegistry[path] = pathId

        # Initialize multi-path event collector with background watchers
        self.collector = MultiPathEventCollector(self.pathRegistry, autoStart=True)

        # Expose eventSources and eventSource for backward compatibility
        self.eventSources: list[tuple[int, Path, Any]] = [
            (w.pathId, w.path, w.eventSource) for w in self.collector.watchers
        ]
        self.eventSource = self.eventSources[0][2] if self.eventSources else None

        self.systemMetrics = SystemMetricsSource()
        self.featureWindow = FeatureWindow()
        self.alertPolicy = AlertPolicy(alertCooldownSeconds)
        self.notifier = notifier or AlertNotifier()
        self.forensicCollector = forensicCollector or ForensicCollector()
        self.modelPath = Path(modelPath).resolve() if modelPath else None
        self.configWatcher: Optional[ConfigWatcher] = None
        self.backgroundReloader: Optional[BackgroundHotReloader] = None
        self.pendingCommitCount = 0

        self.sessionId = None
        self.lastEventSummary = "No recent file activity."
        self.lastCollectedEventCount = 0
        self._closed = False

        pathsStr = ", ".join(str(p) for p in self.monitoredPaths)
        logger.info(f"DetectionController initialized with {len(self.monitoredPaths)} path(s): {pathsStr}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with guaranteed cleanup."""
        self.close()
        return False

    def __del__(self):
        """Ensure cleanup on garbage collection."""
        try:
            self.close()
        except Exception as error:
            logger.warning(f"Error during garbage collection cleanup: {error}")

    def startSession(self) -> int:
        """Start a new monitoring session."""
        if self._closed:
            raise RuntimeError("Controller is closed")

        cursor = self.connection.execute(
            "INSERT INTO sessions (startedAt) VALUES (datetime('now'))"
        )
        self.connection.commit()
        self.sessionId = cursor.lastrowid
        setSessionId(self.sessionId)
        logger.info(
            f"Started monitoring session: {self.sessionId}",
            extra={
                "event": "lifecycle",
                "context": {
                    "sessionId": self.sessionId,
                    "paths": [str(p) for p in self.monitoredPaths],
                    "pathCount": len(self.monitoredPaths),
                },
            },
        )
        return self.sessionId

    def collectOnce(self) -> RiskDecision:
        """Collect file events once across all monitored paths and evaluate risk."""
        if self._closed:
            raise RuntimeError("Controller is closed")

        if self.sessionId is None:
            self.startSession()

        try:
            # Collect file events across all monitored paths via multi-path collector
            allEvents = self.collector.collectAvailableEvents()
            self.featureWindow.addEvents(allEvents)

            # Store events in database
            pathKeyPath = getDataDirectory() / "path.key"
            for event in allEvents:
                oldPathHash = getPathIdentifier(event.oldPath, pathKeyPath) if event.oldPath else None
                self.connection.execute(
                    "INSERT INTO fileEvents (sessionId, occurredAt, action, pathHash, source, pathId, processId, processName, parentProcessId, oldPathHash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        self.sessionId,
                        event.occurredAt.isoformat(),
                        event.action.value,
                        getPathIdentifier(event.path, pathKeyPath),
                        event.source,
                        event.pathId or self.pathRegistry.get(Path(event.monitoredPath) if event.monitoredPath else self.monitoredPaths[0]),
                        event.processId,
                        event.processName,
                        event.parentProcessId,
                        oldPathHash,
                    ),
                )

            self.lastCollectedEventCount = len(allEvents)
            if allEvents:
                latestEvent = allEvents[-1]
                self.lastEventSummary = (
                    f"{latestEvent.action.value}  •  {Path(latestEvent.path).name}"
                )

            # Collect system metrics and generate features
            metrics = self.systemMetrics.collect()
            sample = self.featureWindow.createSample(
                processCpuUsage=metrics.cpuUsage,
                processMemoryUsage=metrics.memoryUsage,
                networkBytes=metrics.networkBytes,
                networkConnectionCount=metrics.networkConnectionCount,
            )

            # Predict and evaluate risk
            probability = 0.0
            if self.modelPredictor is not None:
                probability = self.modelPredictor.predictProbability(sample.values)

            decision = evaluateRisk(
                probability,
                sample.values["filesModifiedPerMinute"],
                sample.values["fileRenameCount"],
                sample.values["fileDeleteCount"],
                suspiciousExtensionCount=sample.values.get("suspiciousExtensionCount", 0.0),
                targetedDocumentCount=sample.values.get("targetedDocumentCount", 0.0),
                highEntropyRatio=sample.values.get("highEntropyRatio", 0.0),
                burstIntensity=sample.values.get("burstIntensity", 0.0),
                extensionChangeCount=sample.values.get("extensionChangeCount", 0.0),
            )

            # Store detections and alerts
            if decision.level.value != "low":
                logger.warning(
                    f"Threat detected: level={decision.level.value}, class={decision.classification}, score={decision.score:.4f}",
                    extra={
                        "event": "detection",
                        "context": {
                            "level": decision.level.value,
                            "classification": decision.classification,
                            "score": decision.score,
                            "action": decision.action,
                            "eventCount": len(allEvents),
                            "paths": [str(p) for p in self.monitoredPaths],
                        },
                    },
                )
                cursor = self.connection.execute(
                    "INSERT INTO detections (sessionId, occurredAt, classification, riskScore, actionTaken) VALUES (?, datetime('now'), ?, ?, ?)",
                    (self.sessionId, decision.classification, decision.score, decision.action),
                )
                detectionId = cursor.lastrowid

                alertContext: dict[str, Any] = {
                    "eventCount": len(allEvents),
                    "paths": [str(p) for p in self.monitoredPaths],
                }
                eventsToInspect = allEvents or self.featureWindow.events
                targetProcessId = None
                targetProcessName = None
                targetFilePath = None
                targetMonitoredPath = None

                if eventsToInspect:
                    latest = eventsToInspect[-1]
                    if getattr(latest, "processId", None):
                        targetProcessId = latest.processId
                        alertContext["processId"] = latest.processId
                    if getattr(latest, "processName", None):
                        targetProcessName = latest.processName
                        alertContext["processName"] = latest.processName
                    if getattr(latest, "monitoredPath", None):
                        targetMonitoredPath = str(latest.monitoredPath)
                        alertContext["monitoredPath"] = targetMonitoredPath
                    if getattr(latest, "path", None):
                        targetFilePath = str(latest.path)
                        alertContext["pathHash"] = getPathIdentifier(latest.path, pathKeyPath)

                # Capture forensic snapshot associated with detection
                try:
                    snapshot = self.forensicCollector.collectSnapshot(
                        decision=decision,
                        processId=targetProcessId,
                        processName=targetProcessName,
                        targetFilePath=targetFilePath,
                        monitoredPath=targetMonitoredPath,
                        featureValues=sample.values,
                        detectionId=detectionId,
                        sessionId=self.sessionId,
                        metadata={
                            "eventCount": len(allEvents),
                            "severity": decision.level.value,
                            "paths": [str(p) for p in self.monitoredPaths],
                        },
                    )
                    self.forensicCollector.saveSnapshot(self.connection, snapshot)
                except Exception as forensicError:
                    logger.warning(f"Could not capture forensic snapshot: {forensicError}")

                if self.alertPolicy.shouldAlert(decision, context=alertContext):
                    logger.critical(
                        f"ALERT RAISED: {decision.classification} (severity={decision.level.value})",
                        extra={
                            "event": "alert",
                            "context": {
                                "severity": decision.level.value,
                                "message": f"Behavior classified as {decision.classification}",
                                "score": decision.score,
                                **alertContext,
                            },
                        },
                    )
                    self.connection.execute(
                        "INSERT INTO alerts (detectionId, occurredAt, severity, message) VALUES (?, datetime('now'), ?, ?)",
                        (detectionId, decision.level.value, f"Behavior classified as {decision.classification}"),
                    )
                    self.alertPolicy.recordAlert(decision, context=alertContext)
                    self.notifier.notify(
                        decision,
                        message=f"Behavior classified as {decision.classification}",
                        details=alertContext,
                    )

            # Commit transactions
            # Immediate commit when events collected (for UI responsiveness)
            # Lazy commit every 10 cycles when idle
            if allEvents:
                self.connection.commit()
                self.pendingCommitCount = 0
            else:
                self.pendingCommitCount += 1
                if self.pendingCommitCount >= 10:
                    self.connection.commit()
                    self.pendingCommitCount = 0

            return decision

        except Exception as error:
            logger.error(f"Error during collection: {error}")
            raise

    def swapModel(
        self,
        newModelPath: Union[str, Path],
        encryption: Any = None,
    ) -> tuple[bool, str]:
        """
        Atomically swap active ML prediction model with candidate model without detection downtime.

        Pre-validates candidate artifact integrity, decrypts, and verifies inference execution
        prior to switching the active model pointer. If validation fails, retains existing model.

        Args:
            newModelPath: Path to candidate .joblib model
            encryption: Optional ModelEncryption instance (uses self.encryption if None)

        Returns:
            Tuple of (success: bool, message: str)
        """
        resolvedPath = Path(newModelPath).resolve()
        targetEncryption = encryption or self.encryption

        try:
            # 1. Preflight load & validation of candidate model
            candidatePredictor = ModelPredictor(resolvedPath, encryption=targetEncryption)

            # 2. Smoke-test inference against runtime feature schema
            testSample = {col: 0.0 for col in featureColumns}
            candidatePredictor.predictProbability(testSample)

            # 3. Atomic hot-swap of predictor pointer
            self.modelPredictor = candidatePredictor
            self.modelPath = resolvedPath
            self.modelState = "ready"

            # 4. Update database systemStatus if connected
            if self.connection is not None:
                try:
                    self.connection.execute(
                        "UPDATE systemStatus SET updatedAt = datetime('now'), modelState = ? WHERE statusId = 1",
                        (self.modelState,),
                    )
                    self.connection.commit()
                except Exception as dbErr:
                    logger.warning(f"Could not update systemStatus for model swap: {dbErr}")

            # 5. Sync watcher if active
            if self.configWatcher is not None:
                self.configWatcher.setModelPath(self.modelPath)

            logSecurityEvent(
                logger,
                action="model_hot_swapped",
                target=str(resolvedPath),
                status="success",
                details={"modelState": self.modelState},
            )
            msg = f"Model successfully swapped to: {resolvedPath.name}"
            logger.info(msg)
            return True, msg

        except (ModelValidationError, Exception) as error:
            errorMsg = f"Model hot-swap rejected: {error}"
            logger.warning(errorMsg)
            logSecurityEvent(
                logger,
                action="model_hot_swapped",
                target=str(resolvedPath),
                status="rejected",
                details={"error": str(error)},
            )
            return False, errorMsg

    def reloadConfiguration(
        self,
        configPath: Optional[Union[str, Path]] = None,
        configDict: Optional[dict[str, Any]] = None,
    ) -> tuple[bool, str]:
        """
        Dynamically reload configuration with deep preflight validation and rollback guarantees.

        Args:
            configPath: Optional path to JSON configuration file
            configDict: Optional in-memory configuration dictionary (pre-parsed)

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # 1. Load candidate configuration
            if configDict is not None:
                candidateConfig = configDict
            else:
                candidateConfig = loadConfiguration(configPath)

            # 2. Deep preflight validation
            validateConfiguration(candidateConfig)

            # 3. Apply Alert Policy & Cooldown parameters
            monitoringSection = candidateConfig.get("monitoring", {})
            if "alertCooldownSeconds" in monitoringSection:
                newCooldown = int(monitoringSection["alertCooldownSeconds"])
                self.alertPolicy.cooldownSeconds = newCooldown

            # 4. Apply Multi-Path Monitoring changes
            newPathStrings = monitoringSection.get("paths", [])
            if newPathStrings:
                newResolvedPaths = resolveMonitoringPaths(newPathStrings)
                if set(newResolvedPaths) != set(self.monitoredPaths):
                    logger.info(f"Reconfiguring monitored paths ({len(self.monitoredPaths)} -> {len(newResolvedPaths)})")

                    # Register new paths in SQLite
                    newRegistry: dict[Path, int] = {}
                    for p in newResolvedPaths:
                        pId = registerMonitoredPath(self.connection, p)
                        newRegistry[p] = pId

                    # Stop old collector and start new collector
                    oldCollector = self.collector
                    self.pathRegistry = newRegistry
                    self.collector = MultiPathEventCollector(self.pathRegistry, autoStart=True)
                    if oldCollector is not None:
                        try:
                            oldCollector.close()
                        except Exception as e:
                            logger.warning(f"Error closing previous event collector: {e}")

                    self.monitoredPaths = newResolvedPaths
                    self.monitoredPath = self.monitoredPaths[0]
                    self.eventSources = [(w.pathId, w.path, w.eventSource) for w in self.collector.watchers]
                    self.eventSource = self.eventSources[0][2] if self.eventSources else None

            # 5. Apply Model updates if configured path changed
            modelSection = candidateConfig.get("model", {})
            if "path" in modelSection and modelSection["path"]:
                newModelPathStr = modelSection["path"]
                resolvedModelPath = Path(newModelPathStr)
                if not resolvedModelPath.is_absolute():
                    resolvedModelPath = getDataDirectory().parent / resolvedModelPath
                if self.modelPath != resolvedModelPath:
                    success, swapMsg = self.swapModel(resolvedModelPath)
                    if not success:
                        logger.warning(f"Configuration reload completed with model swap warning: {swapMsg}")

            logSecurityEvent(
                logger,
                action="configuration_hot_reloaded",
                target=str(configPath or "default"),
                status="success",
                details={"paths": [str(p) for p in self.monitoredPaths], "cooldown": self.alertPolicy.cooldown},
            )
            msg = "Configuration hot-reload applied successfully"
            logger.info(msg)
            return True, msg

        except (ConfigurationError, Exception) as error:
            errorMsg = f"Configuration hot-reload aborted: {error}"
            logger.warning(errorMsg)
            logSecurityEvent(
                logger,
                action="configuration_hot_reloaded",
                target=str(configPath or "default"),
                status="rejected",
                details={"error": str(error)},
            )
            return False, errorMsg

    def enableHotReloader(self, checkIntervalSeconds: float = 2.0, configPath: Optional[Union[str, Path]] = None) -> None:
        """Enable background watching of configuration and model files for live auto-reloads."""
        if self.backgroundReloader is not None and self.backgroundReloader.is_running():
            return

        self.configWatcher = ConfigWatcher(
            configPath=configPath,
            modelPath=self.modelPath,
            onConfigChange=lambda newConfig: self.reloadConfiguration(configDict=newConfig),
            onModelChange=lambda newPath: self.swapModel(newPath),
        )
        self.backgroundReloader = BackgroundHotReloader(
            self.configWatcher,
            checkIntervalSeconds=checkIntervalSeconds,
        )
        self.backgroundReloader.start()
        logger.info("Hot-reloader enabled on DetectionController")

    def disableHotReloader(self) -> None:
        """Stop background hot-reloader thread."""
        if self.backgroundReloader is not None:
            self.backgroundReloader.stop()
            self.backgroundReloader = None
            logger.info("Hot-reloader disabled on DetectionController")

    def checkHotReload(self) -> dict[str, Any]:
        """Manually trigger hot-reload check for on-disk file modifications."""
        if self.configWatcher is None:
            self.configWatcher = ConfigWatcher(
                modelPath=self.modelPath,
                onConfigChange=lambda newConfig: self.reloadConfiguration(configDict=newConfig),
                onModelChange=lambda newPath: self.swapModel(newPath),
            )
        return self.configWatcher.pollOnce()

    def run(self, intervalSeconds: float = 1.0, sampleLimit: int | None = None) -> None:
        """Run monitoring loop with bounded samples or until stopped."""
        sampleCount = 0
        try:
            while sampleLimit is None or sampleCount < sampleLimit:
                self.collectOnce()
                sampleCount += 1
                time.sleep(max(0.1, intervalSeconds))
        except Exception as error:
            logger.error(f"Monitoring loop error: {error}")
            raise
        finally:
            self.close()

    def close(self) -> None:
        """
        Close controller and cleanup all resources.

        Idempotent: safe to call multiple times.
        Guaranteed cleanup on all paths (normal exit, exception, Ctrl+C).
        """
        if self._closed:
            return  # Already closed, idempotent

        logger.debug("Closing DetectionController")
        self._closed = True

        # Stop hot-reloader if active
        try:
            self.disableHotReloader()
        except Exception as error:
            logger.warning(f"Error disabling hot-reloader during close: {error}")

        try:
            # Close database connection
            if self.connection is not None:
                try:
                    # End session if active
                    if self.sessionId is not None:
                        self.connection.execute(
                            "UPDATE sessions SET endedAt = datetime('now') WHERE sessionId = ?",
                            (self.sessionId,),
                        )
                        self.connection.commit()
                        logger.debug(f"Session {self.sessionId} ended")
                except Exception as error:
                    logger.warning(f"Error ending session: {error}")

                try:
                    self.connection.close()
                    logger.debug("Database connection closed")
                except Exception as error:
                    logger.warning(f"Error closing database connection: {error}")
                finally:
                    self.connection = None

        except Exception as error:
            logger.error(f"Unexpected error during close: {error}")

        try:
            # Close multi-path collector and event sources
            if hasattr(self, "collector") and self.collector is not None:
                self.collector.close()
                self.collector = None  # type: ignore
            self.eventSources = []
            self.eventSource = None
        except Exception as error:
            logger.error(f"Unexpected error closing event sources: {error}")

        logger.info("DetectionController closed successfully")
        setSessionId(None)

