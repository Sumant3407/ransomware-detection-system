"""Configuration and model artifact hot-reload watcher with deep validation and rollback guarantees."""

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Union

from app.config.configuration import (
    ConfigurationError,
    getDataDirectory,
    loadConfiguration,
    validateConfiguration,
)
from app.logging.logger import logSecurityEvent

logger = logging.getLogger(__name__)


@dataclass
class ReloadResult:
    """Outcome report for a configuration or model hot-reload operation."""

    success: bool
    target: str  # "configuration" or "model"
    occurredAt: str
    message: str
    previousHash: Optional[str] = None
    newHash: Optional[str] = None
    changedSections: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def toDict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "target": self.target,
            "occurredAt": self.occurredAt,
            "message": self.message,
            "previousHash": self.previousHash,
            "newHash": self.newHash,
            "changedSections": self.changedSections,
            "error": self.error,
        }


class ConfigWatcher:
    """
    Watches configuration and model files on disk for modifications.
    Ensures zero-downtime hot-reloading with strict pre-validation and rollback safety.
    """

    def __init__(
        self,
        configPath: Optional[Union[str, Path]] = None,
        modelPath: Optional[Union[str, Path]] = None,
        onConfigChange: Optional[Callable[[dict[str, Any]], None]] = None,
        onModelChange: Optional[Callable[[Path], None]] = None,
    ):
        self.configPath = Path(configPath).resolve() if configPath else (getDataDirectory() / "settings.json").resolve()
        self.modelPath = Path(modelPath).resolve() if modelPath else None
        self.onConfigChange = onConfigChange
        self.onModelChange = onModelChange

        self._lock = threading.RLock()
        self._lastConfigHash: Optional[str] = self._computeFileHash(self.configPath)
        self._lastModelHash: Optional[str] = self._computeFileHash(self.modelPath) if self.modelPath else None
        self._lastConfigMtime: float = self._getFileMtime(self.configPath)
        self._lastModelMtime: float = self._getFileMtime(self.modelPath) if self.modelPath else 0.0

        self._activeConfig: Optional[dict[str, Any]] = None
        self._reloadHistory: list[ReloadResult] = []

        # Load initial configuration baseline
        try:
            self._activeConfig = loadConfiguration(self.configPath if self.configPath.is_file() else None)
        except Exception as error:
            logger.warning(f"Could not load initial config in watcher: {error}")

    def _computeFileHash(self, path: Optional[Path]) -> Optional[str]:
        """Compute SHA-256 hash of a file if it exists."""
        if not path or not path.is_file():
            return None
        try:
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as error:
            logger.debug(f"Error hashing {path}: {error}")
            return None

    def _getFileMtime(self, path: Optional[Path]) -> float:
        """Get file modification timestamp."""
        if not path or not path.is_file():
            return 0.0
        try:
            return path.stat().st_mtime
        except Exception:
            return 0.0

    def checkConfigChanged(self) -> bool:
        """Check if configuration file has been modified on disk."""
        with self._lock:
            if not self.configPath or not self.configPath.is_file():
                return False

            currentMtime = self._getFileMtime(self.configPath)
            if currentMtime == self._lastConfigMtime:
                return False

            currentHash = self._computeFileHash(self.configPath)
            return currentHash != self._lastConfigHash

    def checkModelChanged(self) -> bool:
        """Check if model artifact file has been modified on disk."""
        with self._lock:
            if not self.modelPath or not self.modelPath.is_file():
                return False

            currentMtime = self._getFileMtime(self.modelPath)
            if currentMtime == self._lastModelMtime:
                return False

            currentHash = self._computeFileHash(self.modelPath)
            return currentHash != self._lastModelHash

    def setModelPath(self, newModelPath: Optional[Union[str, Path]]) -> None:
        """Update tracked model path."""
        with self._lock:
            self.modelPath = Path(newModelPath).resolve() if newModelPath else None
            self._lastModelHash = self._computeFileHash(self.modelPath) if self.modelPath else None
            self._lastModelMtime = self._getFileMtime(self.modelPath) if self.modelPath else 0.0

    def reloadConfiguration(self, customPath: Optional[Union[str, Path]] = None) -> tuple[bool, Optional[dict[str, Any]], ReloadResult]:
        """
        Validate and reload configuration.
        Guarantees rollback to active configuration if candidate fails validation.

        Returns:
            Tuple of (success: bool, newConfig: Optional[dict], resultReport: ReloadResult)
        """
        with self._lock:
            targetPath = Path(customPath).resolve() if customPath else self.configPath
            nowIso = datetime.now(timezone.utc).isoformat()
            prevHash = self._lastConfigHash

            try:
                # 1. Load and parse candidate configuration
                candidateConfig = loadConfiguration(targetPath if targetPath.is_file() else None)

                # 2. Deep preflight validation
                validateConfiguration(candidateConfig)

                # 3. Identify changed configuration sections
                changedSections = []
                if self._activeConfig:
                    for section, val in candidateConfig.items():
                        if self._activeConfig.get(section) != val:
                            changedSections.append(section)
                    for section in self._activeConfig:
                        if section not in candidateConfig and section not in changedSections:
                            changedSections.append(section)
                else:
                    changedSections = list(candidateConfig.keys())

                newHash = self._computeFileHash(targetPath) if targetPath.is_file() else None
                self._lastConfigHash = newHash
                self._lastConfigMtime = self._getFileMtime(targetPath)
                self._activeConfig = candidateConfig

                result = ReloadResult(
                    success=True,
                    target="configuration",
                    occurredAt=nowIso,
                    message=f"Configuration successfully reloaded ({len(changedSections)} section(s) changed: {', '.join(changedSections) or 'no structural changes'})",
                    previousHash=prevHash,
                    newHash=newHash,
                    changedSections=changedSections,
                )
                self._reloadHistory.append(result)

                logSecurityEvent(
                    logger,
                    action="configuration_hot_reloaded",
                    target=str(targetPath),
                    status="success",
                    details={"changedSections": changedSections, "hash": newHash},
                )

                if self.onConfigChange:
                    try:
                        self.onConfigChange(candidateConfig)
                    except Exception as cbErr:
                        logger.error(f"Error in config change callback: {cbErr}")

                return True, candidateConfig, result

            except (ConfigurationError, Exception) as error:
                # Rollback / Preserve active configuration
                errorMsg = f"Configuration reload rejected: {error}"
                logger.warning(errorMsg)

                result = ReloadResult(
                    success=False,
                    target="configuration",
                    occurredAt=nowIso,
                    message=errorMsg,
                    previousHash=prevHash,
                    newHash=prevHash,
                    changedSections=[],
                    error=str(error),
                )
                self._reloadHistory.append(result)

                logSecurityEvent(
                    logger,
                    action="configuration_hot_reloaded",
                    target=str(targetPath),
                    status="rejected",
                    details={"error": str(error)},
                )
                return False, self._activeConfig, result

    def pollOnce(self) -> dict[str, Any]:
        """
        Check for on-disk changes and execute registered callbacks.

        Returns:
            Dictionary summarizing reload actions taken.
        """
        actions: dict[str, Any] = {"configReloaded": False, "modelReloaded": False}

        if self.checkConfigChanged():
            success, _, report = self.reloadConfiguration()
            actions["configReloaded"] = success
            actions["configReport"] = report.toDict()

        if self.checkModelChanged():
            nowIso = datetime.now(timezone.utc).isoformat()
            prevHash = self._lastModelHash
            newHash = self._computeFileHash(self.modelPath)
            self._lastModelHash = newHash
            self._lastModelMtime = self._getFileMtime(self.modelPath)

            actions["modelReloaded"] = True
            logger.info(f"Detected model file update on disk: {self.modelPath}")

            if self.onModelChange and self.modelPath:
                try:
                    self.onModelChange(self.modelPath)
                except Exception as cbErr:
                    logger.error(f"Error in model change callback: {cbErr}")

        return actions

    def getReloadHistory(self) -> list[ReloadResult]:
        """Return history of configuration reload attempts."""
        with self._lock:
            return list(self._reloadHistory)


class BackgroundHotReloader:
    """
    Asynchronous background watcher thread that periodically checks for configuration
    and model file updates and applies them live.
    """

    def __init__(
        self,
        watcher: ConfigWatcher,
        checkIntervalSeconds: float = 2.0,
    ):
        self.watcher = watcher
        self.interval = max(0.2, float(checkIntervalSeconds))
        self._thread: Optional[threading.Thread] = None
        self._stopEvent = threading.Event()
        self._running = False

    def start(self) -> None:
        """Start the background hot-reload watcher thread."""
        if self._running:
            return

        self._stopEvent.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._runLoop,
            name="HotReloaderWatcherThread",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"Background hot-reloader started (interval: {self.interval}s)")

    def stop(self, timeout: float = 2.0) -> None:
        """Stop background watcher thread."""
        if not self._running:
            return

        self._stopEvent.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._running = False
        logger.info("Background hot-reloader stopped")

    def _runLoop(self) -> None:
        """Continuous background polling loop."""
        while not self._stopEvent.is_set():
            try:
                self.watcher.pollOnce()
            except Exception as error:
                logger.warning(f"Error during hot-reloader poll: {error}")

            self._stopEvent.wait(timeout=self.interval)

    def is_running(self) -> bool:
        return self._running and (self._thread.is_alive() if self._thread else False)

    def __enter__(self) -> "BackgroundHotReloader":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.stop()
        return False
