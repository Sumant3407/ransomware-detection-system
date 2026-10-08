"""Health check and observability engine for the Ransomware Detection System."""

import json
import logging
import os
import shutil
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Optional, Union

import psutil

from app.config.configuration import (
    getDataDirectory,
    getProjectRoot,
    loadConfiguration,
    resolveMonitoringPath,
)
from app.detection.predictor import ModelPredictor, ModelValidationError
from app.logging.logger import logSecurityEvent
from app.security.modelEncryption import ModelEncryption, ModelTamperError
from app.security.pathValidator import PathValidator, PathValidationError
from app.storage.sqliteStore import getLatestRetrainingRuns, getPooledConnection, initializeDatabase

logger = logging.getLogger(__name__)


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    name: str
    status: HealthStatus
    message: str
    latencyMs: Optional[float] = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemMetrics:
    processCpuPercent: float
    processMemoryRssMb: float
    processMemoryVmsMb: float
    threadCount: int
    openFileHandles: int
    processUptimeSeconds: float
    totalFileEvents: int
    totalDetections: int
    totalAlerts: int
    totalSessions: int
    unconsumedFeedbackCount: int
    lastRetrainingStatus: Optional[str] = None


@dataclass
class HealthReport:
    status: HealthStatus
    timestamp: str
    components: dict[str, ComponentHealth]
    metrics: SystemMetrics
    issues: list[str] = field(default_factory=list)

    def toDict(self) -> dict[str, Any]:
        return {
            "status": str(self.status),
            "timestamp": self.timestamp,
            "components": {k: asdict(v) for k, v in self.components.items()},
            "metrics": asdict(self.metrics),
            "issues": self.issues,
        }


class HealthChecker:
    """Evaluates comprehensive subsystem health and collects system telemetry."""

    def __init__(
        self,
        configuration: Optional[dict[str, Any]] = None,
        databasePath: Optional[Union[str, Path]] = None,
        encryption: Optional[ModelEncryption] = None,
    ):
        self.config = configuration or loadConfiguration()
        if databasePath is not None:
            self.databasePath = Path(databasePath).resolve()
        else:
            dbPathStr = self.config.get("storage", {}).get(
                "databasePath", "data/database/detector.sqlite3"
            )
            self.databasePath = Path(dbPathStr)
            if not self.databasePath.is_absolute():
                self.databasePath = getProjectRoot() / self.databasePath

        self.encryption = encryption or ModelEncryption()
        self.process = psutil.Process(os.getpid())
        self.startTime = self.process.create_time()

    def checkModel(self) -> ComponentHealth:
        """Check active model existence, integrity, encryption, and predictor readiness."""
        startTime = time.perf_counter()
        modelPathStr = self.config.get("model", {}).get("path", "data/models/current/model.joblib")
        modelPath = Path(modelPathStr)
        if not modelPath.is_absolute():
            modelPath = getProjectRoot() / modelPath

        if not modelPath.is_file():
            latency = (time.perf_counter() - startTime) * 1000.0
            return ComponentHealth(
                name="model",
                status=HealthStatus.UNHEALTHY,
                message=f"Model artifact not found at {modelPath}",
                latencyMs=round(latency, 2),
                details={"path": str(modelPath), "exists": False},
            )

        try:
            isEncrypted = ModelEncryption.isEncryptedFile(modelPath)
            predictor = ModelPredictor(modelPath, encryption=self.encryption)
            classes = list(predictor.artifact.get("classes", []))
            modelVersion = str(predictor.artifact.get("modelVersion", "unknown"))
            importancesCount = len(predictor.getFeatureImportances())

            latency = (time.perf_counter() - startTime) * 1000.0
            return ComponentHealth(
                name="model",
                status=HealthStatus.HEALTHY,
                message="Model loaded and validated successfully",
                latencyMs=round(latency, 2),
                details={
                    "path": str(modelPath),
                    "isEncrypted": isEncrypted,
                    "modelVersion": modelVersion,
                    "classes": classes,
                    "featuresCount": importancesCount,
                },
            )
        except (ModelTamperError, ModelValidationError) as error:
            latency = (time.perf_counter() - startTime) * 1000.0
            return ComponentHealth(
                name="model",
                status=HealthStatus.UNHEALTHY,
                message=f"Model validation error: {error}",
                latencyMs=round(latency, 2),
                details={"path": str(modelPath), "error": str(error)},
            )
        except Exception as error:
            latency = (time.perf_counter() - startTime) * 1000.0
            return ComponentHealth(
                name="model",
                status=HealthStatus.UNHEALTHY,
                message=f"Unexpected error loading model: {error}",
                latencyMs=round(latency, 2),
                details={"path": str(modelPath), "error": str(error)},
            )

    def checkDatabase(self) -> ComponentHealth:
        """Check SQLite persistence, connection ping, and schema integrity."""
        startTime = time.perf_counter()
        if not self.databasePath.is_file():
            # Try initializing if missing
            try:
                initializeDatabase(self.databasePath)
            except Exception as error:
                latency = (time.perf_counter() - startTime) * 1000.0
                return ComponentHealth(
                    name="database",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Database file not found and initialization failed: {error}",
                    latencyMs=round(latency, 2),
                    details={"path": str(self.databasePath), "error": str(error)},
                )

        try:
            connection = sqlite3.connect(str(self.databasePath), timeout=5.0)
            cursor = connection.execute("SELECT 1")
            cursor.fetchone()

            # Check journal mode
            journalMode = connection.execute("PRAGMA journal_mode").fetchone()[0]

            # Query table counts
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]

            requiredTables = {"fileEvents", "detections", "alerts", "models", "sessions"}
            missingTables = requiredTables - set(tables)

            connection.close()
            latency = (time.perf_counter() - startTime) * 1000.0

            if missingTables:
                return ComponentHealth(
                    name="database",
                    status=HealthStatus.DEGRADED,
                    message=f"Database missing expected tables: {missingTables}",
                    latencyMs=round(latency, 2),
                    details={"missingTables": list(missingTables), "journalMode": journalMode},
                )

            return ComponentHealth(
                name="database",
                status=HealthStatus.HEALTHY,
                message="Database connectivity and schema operational",
                latencyMs=round(latency, 2),
                details={"path": str(self.databasePath), "journalMode": journalMode, "tables": tables},
            )
        except Exception as error:
            latency = (time.perf_counter() - startTime) * 1000.0
            return ComponentHealth(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {error}",
                latencyMs=round(latency, 2),
                details={"path": str(self.databasePath), "error": str(error)},
            )

    def checkMonitoringPaths(self) -> ComponentHealth:
        """Validate accessibility, permissions, and security of all monitored paths."""
        startTime = time.perf_counter()
        pathConfigs = self.config.get("monitoring", {}).get("paths", [])
        if not pathConfigs:
            latency = (time.perf_counter() - startTime) * 1000.0
            return ComponentHealth(
                name="monitoringPaths",
                status=HealthStatus.UNHEALTHY,
                message="No monitoring paths configured",
                latencyMs=round(latency, 2),
                details={"paths": []},
            )

        accessiblePaths: list[str] = []
        inaccessiblePaths: list[str] = []

        for pStr in pathConfigs:
            try:
                resolved = resolveMonitoringPath(pStr)
                if resolved.is_dir() and os.access(resolved, os.R_OK):
                    accessiblePaths.append(str(resolved))
                else:
                    inaccessiblePaths.append(str(resolved))
            except (PathValidationError, ValueError, OSError):
                inaccessiblePaths.append(str(pStr))

        latency = (time.perf_counter() - startTime) * 1000.0
        if not accessiblePaths:
            return ComponentHealth(
                name="monitoringPaths",
                status=HealthStatus.UNHEALTHY,
                message="All configured monitoring paths are inaccessible or invalid",
                latencyMs=round(latency, 2),
                details={"inaccessible": inaccessiblePaths},
            )

        if inaccessiblePaths:
            return ComponentHealth(
                name="monitoringPaths",
                status=HealthStatus.DEGRADED,
                message=f"{len(inaccessiblePaths)} of {len(pathConfigs)} paths are inaccessible",
                latencyMs=round(latency, 2),
                details={"accessible": accessiblePaths, "inaccessible": inaccessiblePaths},
            )

        return ComponentHealth(
            name="monitoringPaths",
            status=HealthStatus.HEALTHY,
            message=f"All {len(accessiblePaths)} monitoring paths are accessible",
            latencyMs=round(latency, 2),
            details={"accessible": accessiblePaths},
        )

    def checkStorage(self) -> ComponentHealth:
        """Check available disk space on the database and logging volume."""
        startTime = time.perf_counter()
        targetDir = self.databasePath.parent
        targetDir.mkdir(parents=True, exist_ok=True)

        try:
            usage = shutil.disk_usage(targetDir)
            freeMb = usage.free / (1024 * 1024)
            totalMb = usage.total / (1024 * 1024)
            freePct = (usage.free / usage.total) * 100.0

            latency = (time.perf_counter() - startTime) * 1000.0

            # Minimum 200 MB required for UNHEALTHY, < 1000 MB for DEGRADED
            if freeMb < 200.0:
                return ComponentHealth(
                    name="storage",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Critically low disk space: {freeMb:.1f} MB remaining",
                    latencyMs=round(latency, 2),
                    details={"freeMb": round(freeMb, 1), "totalMb": round(totalMb, 1), "freePercent": round(freePct, 2)},
                )
            elif freeMb < 1000.0:
                return ComponentHealth(
                    name="storage",
                    status=HealthStatus.DEGRADED,
                    message=f"Low disk space warning: {freeMb:.1f} MB remaining",
                    latencyMs=round(latency, 2),
                    details={"freeMb": round(freeMb, 1), "totalMb": round(totalMb, 1), "freePercent": round(freePct, 2)},
                )

            return ComponentHealth(
                name="storage",
                status=HealthStatus.HEALTHY,
                message=f"Adequate disk space: {freeMb:.1f} MB free ({freePct:.1f}%)",
                latencyMs=round(latency, 2),
                details={"freeMb": round(freeMb, 1), "totalMb": round(totalMb, 1), "freePercent": round(freePct, 2)},
            )
        except Exception as error:
            latency = (time.perf_counter() - startTime) * 1000.0
            return ComponentHealth(
                name="storage",
                status=HealthStatus.DEGRADED,
                message=f"Could not query disk space: {error}",
                latencyMs=round(latency, 2),
                details={"error": str(error)},
            )

    def checkLogging(self) -> ComponentHealth:
        """Check logging directory writability and log file status."""
        startTime = time.perf_counter()
        logDir = getDataDirectory() / "logs"
        logDir.mkdir(parents=True, exist_ok=True)

        try:
            testFile = logDir / ".health_test.tmp"
            testFile.write_text("health_check_probe", encoding="utf-8")
            testFile.unlink()

            appLog = logDir / "application.log"
            auditLog = logDir / "audit.log"

            latency = (time.perf_counter() - startTime) * 1000.0
            return ComponentHealth(
                name="logging",
                status=HealthStatus.HEALTHY,
                message="Logging subsystem operational and writable",
                latencyMs=round(latency, 2),
                details={
                    "logDirectory": str(logDir),
                    "applicationLogExists": appLog.is_file(),
                    "auditLogExists": auditLog.is_file(),
                },
            )
        except Exception as error:
            latency = (time.perf_counter() - startTime) * 1000.0
            return ComponentHealth(
                name="logging",
                status=HealthStatus.DEGRADED,
                message=f"Logging directory write failed: {error}",
                latencyMs=round(latency, 2),
                details={"logDirectory": str(logDir), "error": str(error)},
            )

    def collectMetrics(self) -> SystemMetrics:
        """Collect live process and database metrics."""
        cpu = 0.0
        rssMb = 0.0
        vmsMb = 0.0
        threads = 1
        handles = 0

        try:
            val = self.process.cpu_percent(interval=None)
            if val is not None:
                cpu = float(val)
        except BaseException:
            pass

        try:
            memInfo = self.process.memory_info()
            rssMb = memInfo.rss / (1024 * 1024)
            vmsMb = memInfo.vms / (1024 * 1024)
        except BaseException:
            pass

        try:
            threads = self.process.num_threads()
        except BaseException:
            pass

        try:
            handles = self.process.num_handles() if hasattr(self.process, "num_handles") else self.process.num_fds()
        except BaseException:
            handles = 0

        uptime = max(0.0, time.time() - self.startTime)

        totalEvents = 0
        totalDetections = 0
        totalAlerts = 0
        totalSessions = 0
        unconsumedFeedback = 0
        lastRetrainingStatus = None

        if self.databasePath.is_file():
            try:
                connection = sqlite3.connect(str(self.databasePath), timeout=2.0)
                totalEvents = connection.execute("SELECT COUNT(*) FROM fileEvents").fetchone()[0]
                totalDetections = connection.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
                totalAlerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                totalSessions = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

                feedbackRow = connection.execute(
                    "SELECT COUNT(*) FROM detectionFeedback WHERE usedInRetraining = 0"
                ).fetchone()
                if feedbackRow:
                    unconsumedFeedback = feedbackRow[0]

                retrainingRow = connection.execute(
                    "SELECT status FROM retrainingRuns ORDER BY runId DESC LIMIT 1"
                ).fetchone()
                if retrainingRow:
                    lastRetrainingStatus = retrainingRow[0]

                connection.close()
            except Exception as dbErr:
                logger.debug(f"Error querying database metrics: {dbErr}")

        return SystemMetrics(
            processCpuPercent=round(cpu, 2),
            processMemoryRssMb=round(rssMb, 2),
            processMemoryVmsMb=round(vmsMb, 2),
            threadCount=threads,
            openFileHandles=handles,
            processUptimeSeconds=round(uptime, 1),
            totalFileEvents=totalEvents,
            totalDetections=totalDetections,
            totalAlerts=totalAlerts,
            totalSessions=totalSessions,
            unconsumedFeedbackCount=unconsumedFeedback,
            lastRetrainingStatus=lastRetrainingStatus,
        )

    def runFullCheck(self) -> HealthReport:
        """Execute all subsystem health probes and return aggregate report."""
        timestamp = datetime.now(timezone.utc).isoformat()
        components: dict[str, ComponentHealth] = {
            "model": self.checkModel(),
            "database": self.checkDatabase(),
            "monitoringPaths": self.checkMonitoringPaths(),
            "storage": self.checkStorage(),
            "logging": self.checkLogging(),
        }

        issues: list[str] = []
        statuses = [comp.status for comp in components.values()]

        if any(s == HealthStatus.UNHEALTHY for s in statuses):
            overallStatus = HealthStatus.UNHEALTHY
        elif any(s == HealthStatus.DEGRADED for s in statuses):
            overallStatus = HealthStatus.DEGRADED
        else:
            overallStatus = HealthStatus.HEALTHY

        for comp in components.values():
            if comp.status != HealthStatus.HEALTHY:
                issues.append(f"[{comp.name.upper()}] {comp.message}")

        metrics = self.collectMetrics()

        report = HealthReport(
            status=overallStatus,
            timestamp=timestamp,
            components=components,
            metrics=metrics,
            issues=issues,
        )

        logger.info(
            f"Health check executed: status={overallStatus}, issues={len(issues)}",
            extra={
                "event": "health_check",
                "context": {
                    "status": str(overallStatus),
                    "issuesCount": len(issues),
                    "memoryRssMb": metrics.processMemoryRssMb,
                },
            },
        )

        return report


def runHealthCheck(
    configuration: Optional[dict[str, Any]] = None,
    databasePath: Optional[Union[str, Path]] = None,
    encryption: Optional[ModelEncryption] = None,
) -> HealthReport:
    """Convenience helper to run a full system health probe."""
    checker = HealthChecker(
        configuration=configuration,
        databasePath=databasePath,
        encryption=encryption,
    )
    return checker.runFullCheck()


def formatHealthSummary(report: HealthReport) -> str:
    """Render health report into clear terminal-formatted display."""
    statusColors = {
        HealthStatus.HEALTHY: "\033[92m[HEALTHY]\033[0m",
        HealthStatus.DEGRADED: "\033[93m[DEGRADED]\033[0m",
        HealthStatus.UNHEALTHY: "\033[91m[UNHEALTHY]\033[0m",
    }
    compStatusIcons = {
        HealthStatus.HEALTHY: "\033[92m[OK]\033[0m",
        HealthStatus.DEGRADED: "\033[93m[WARN]\033[0m",
        HealthStatus.UNHEALTHY: "\033[91m[FAIL]\033[0m",
    }

    lines = [
        "==================================================",
        f"       SYSTEM HEALTH STATUS: {statusColors.get(report.status, str(report.status))}        ",
        "==================================================",
        f"  Timestamp:         {report.timestamp}",
        f"  Overall Status:    {report.status.value.upper()}",
        "",
        "  Component Breakdown:",
    ]

    for name, comp in report.components.items():
        icon = compStatusIcons.get(comp.status, "[ - ]")
        latStr = f"({comp.latencyMs:.1f}ms)" if comp.latencyMs is not None else ""
        lines.append(f"    {icon:<12} {name:<18} {comp.status.value:<10} {latStr}")
        if comp.status != HealthStatus.HEALTHY:
            lines.append(f"      -> {comp.message}")

    lines.extend([
        "",
        "  Process & System Observability:",
        f"    CPU Usage:       {report.metrics.processCpuPercent:.1f}%",
        f"    Memory (RSS):    {report.metrics.processMemoryRssMb:.1f} MB",
        f"    Threads:         {report.metrics.threadCount}",
        f"    Open Handles:    {report.metrics.openFileHandles}",
        f"    Uptime:          {report.metrics.processUptimeSeconds:.1f}s",
        "",
        "  Detection Pipeline Telemetry:",
        f"    File Events:     {report.metrics.totalFileEvents}",
        f"    Detections:      {report.metrics.totalDetections}",
        f"    Alerts Raised:   {report.metrics.totalAlerts}",
        f"    Feedback Queued: {report.metrics.unconsumedFeedbackCount}",
        f"    Last Retraining: {report.metrics.lastRetrainingStatus or 'None'}",
        "==================================================",
    ])

    if report.issues:
        lines.append("  Active Issues & Warnings:")
        for issue in report.issues:
            lines.append(f"    * {issue}")
        lines.append("==================================================")

    return "\n".join(lines)
