"""Thread-per-path multi-directory event aggregation with thread-safe event queuing."""

import logging
import os
import queue
import threading
import time
from pathlib import Path
from typing import Any, Sequence

from app.domain.schemas import FileEvent
from app.monitoring.fileEvents import PollingFileEventSource
from app.monitoring.windowsFileEvents import (
    WindowsFileEventSource,
    WindowsWatcherUnavailable,
)

logger = logging.getLogger(__name__)


class SinglePathWatcher:
    """Watches a single directory in a background thread and queues file events with auto-fallback."""

    def __init__(self, path: Path, pathId: int, eventQueue: queue.Queue, pollIntervalSeconds: float = 0.2):
        self.path = path.resolve()
        self.pathId = pathId
        self.eventQueue = eventQueue
        self.pollInterval = max(0.05, pollIntervalSeconds)
        self.running = False
        self.thread: threading.Thread | None = None
        self.eventSource: Any = None
        self._isWindowsWatcher = False
        self._lastRecoveryAttempt: float = time.monotonic()

        self._initEventSource()

    def _initEventSource(self) -> None:
        """Initialize the underlying event source (Windows API or Polling fallback)."""
        try:
            self.eventSource = WindowsFileEventSource(self.path, pathId=self.pathId)
            self._isWindowsWatcher = True
            logger.debug(f"Using Windows ReadDirectoryChangesW for {self.path} (pathId={self.pathId})")
        except (WindowsWatcherUnavailable, Exception) as error:
            self.eventSource = PollingFileEventSource(self.path, pathId=self.pathId)
            self._isWindowsWatcher = False
            logger.info(f"Using polling event source fallback for {self.path} (pathId={self.pathId}): {error}")

    def fallbackToPolling(self, reason: str = "error") -> None:
        """Seamlessly transition from Windows API watcher to polling fallback."""
        if not self._isWindowsWatcher:
            return
        logger.warning(
            f"Failing over from Windows watcher to polling for {self.path}: {reason}",
            extra={"event": "watcher_fallback", "path": str(self.path), "pathId": self.pathId, "reason": reason},
        )
        if self.eventSource is not None and hasattr(self.eventSource, "close"):
            try:
                self.eventSource.close()
            except Exception:
                pass
        self.eventSource = PollingFileEventSource(self.path, pathId=self.pathId)
        self._isWindowsWatcher = False

    def attemptRecoveryToWindowsWatcher(self) -> bool:
        """Attempt to restore real-time Windows watcher if conditions recovered."""
        now = time.monotonic()
        if (now - self._lastRecoveryAttempt) < 10.0:
            return False
        self._lastRecoveryAttempt = now

        try:
            newSource = WindowsFileEventSource(self.path, pathId=self.pathId)
            oldSource = self.eventSource
            self.eventSource = newSource
            self._isWindowsWatcher = True
            if oldSource is not None and hasattr(oldSource, "close"):
                try:
                    oldSource.close()
                except Exception:
                    pass
            logger.info(f"Successfully recovered Windows watcher for {self.path} (pathId={self.pathId})")
            return True
        except Exception:
            return False

    def start(self) -> None:
        """Start background watching thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(
            target=self._run,
            name=f"PathWatcher-{self.pathId}-{self.path.name}",
            daemon=True,
        )
        self.thread.start()

    def _run(self) -> None:
        """Background thread loop collecting and queuing events with automatic fallback."""
        while self.running:
            try:
                events = []
                if self._isWindowsWatcher:
                    try:
                        events = self.eventSource.collectEvents(timeoutMilliseconds=100)
                    except WindowsWatcherUnavailable as winError:
                        self.fallbackToPolling(str(winError))
                        continue
                else:
                    events = self.eventSource.collectEvents()
                    # Periodically try to recover to Windows watcher if on Windows
                    if os.name == "nt":
                        self.attemptRecoveryToWindowsWatcher()
                    time.sleep(self.pollInterval)

                for event in events:
                    if event.pathId is None or event.monitoredPath is None:
                        event = FileEvent(
                            action=event.action,
                            path=event.path,
                            occurredAt=event.occurredAt,
                            source=event.source,
                            oldPath=event.oldPath,
                            processId=event.processId,
                            pathId=self.pathId,
                            monitoredPath=str(self.path),
                            processName=event.processName,
                            parentProcessId=event.parentProcessId,
                        )
                    self.eventQueue.put(event)
            except Exception as error:
                if self.running:
                    logger.warning(f"Error in watcher thread for {self.path}: {error}")
                    time.sleep(0.1)

    def collectDirect(self) -> list[FileEvent]:
        """Collect events directly in caller thread (synchronous fallback)."""
        try:
            if self.eventSource is not None:
                if self._isWindowsWatcher:
                    return self.eventSource.collectEvents(timeoutMilliseconds=50)
                return self.eventSource.collectEvents()
        except Exception as error:
            logger.warning(f"Direct collection error for {self.path}: {error}")
        return []

    def close(self) -> None:
        """Stop background thread and close event source."""
        self.running = False
        if self.eventSource is not None:
            try:
                if hasattr(self.eventSource, "close"):
                    self.eventSource.close()
            except Exception as error:
                logger.warning(f"Error closing event source for {self.path}: {error}")
            finally:
                self.eventSource = None

        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=1.0)
            self.thread = None


class MultiPathEventCollector:
    """Orchestrates multi-threaded event collection across multiple paths with an aggregated queue."""

    def __init__(self, pathMap: dict[Path, int], autoStart: bool = True):
        """
        Initialize multi-path collector.

        Args:
            pathMap: Dictionary mapping Path -> pathId
            autoStart: If True, starts background watcher threads immediately
        """
        self.pathMap = {p.resolve(): pathId for p, pathId in pathMap.items()}
        self.eventQueue: queue.Queue[FileEvent] = queue.Queue(maxsize=10000)
        self.watchers: list[SinglePathWatcher] = []
        self._closed = False

        for path, pathId in self.pathMap.items():
            watcher = SinglePathWatcher(path, pathId, self.eventQueue)
            self.watchers.append(watcher)
            if autoStart:
                watcher.start()

        logger.info(f"MultiPathEventCollector initialized with {len(self.watchers)} path watcher(s)")

    def collectAvailableEvents(self, timeoutSeconds: float = 0.1) -> list[FileEvent]:
        """
        Drain all queued events from all watchers.
        Collects all available events, allowing concurrent watcher threads to push simultaneous events.

        Returns:
            List of collected FileEvent objects
        """
        events: list[FileEvent] = []
        endTime = time.monotonic() + max(0.01, timeoutSeconds)

        while True:
            # Drain whatever is currently queued
            while not self.eventQueue.empty():
                try:
                    events.append(self.eventQueue.get_nowait())
                except queue.Empty:
                    break

            remaining = endTime - time.monotonic()
            if remaining > 0:
                try:
                    event = self.eventQueue.get(timeout=min(remaining, 0.05))
                    events.append(event)
                except queue.Empty:
                    pass
            else:
                break

        # Final drain of any queued events
        while not self.eventQueue.empty():
            try:
                events.append(self.eventQueue.get_nowait())
            except queue.Empty:
                break

        return events

    def close(self) -> None:
        """Stop all path watchers and release resources."""
        if self._closed:
            return
        self._closed = True

        for watcher in self.watchers:
            try:
                watcher.close()
            except Exception as error:
                logger.warning(f"Error stopping watcher: {error}")

        self.watchers = []
        logger.debug("MultiPathEventCollector closed")
