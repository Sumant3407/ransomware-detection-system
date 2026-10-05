"""Generic background monitoring worker without Qt dependencies."""

import threading
import time
from pathlib import Path
from typing import Callable, Optional

from app.runtime.controller import DetectionController
from app.detection.riskEngine import RiskDecision


class MonitoringWorker:
    """Background monitoring worker using standard threading."""

    def __init__(
        self,
        monitoredPath: Path,
        databasePath: Path,
        modelPath: Optional[Path] = None,
        intervalSeconds: float = 1.0,
        onDecision: Optional[Callable[[RiskDecision, int, str], None]] = None,
        onError: Optional[Callable[[str], None]] = None,
        onFinished: Optional[Callable[[], None]] = None,
    ):
        """
        Initialize monitoring worker.

        Args:
            monitoredPath: Directory to monitor
            databasePath: SQLite database path
            modelPath: Path to trained model (optional)
            intervalSeconds: Seconds between monitoring samples
            onDecision: Callback for risk decisions (decision, eventCount, summary)
            onError: Callback for errors
            onFinished: Callback when monitoring stops
        """
        self.monitoredPath = monitoredPath
        self.databasePath = databasePath
        self.modelPath = modelPath
        self.intervalSeconds = max(0.1, intervalSeconds)
        self.onDecision = onDecision
        self.onError = onError
        self.onFinished = onFinished

        self.controller: Optional[DetectionController] = None
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start monitoring in background thread."""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        """Main monitoring loop (runs in background thread)."""
        try:
            self.controller = DetectionController(
                self.monitoredPath,
                self.databasePath,
                self.modelPath,
            )

            while self.running:
                decision = self.controller.collectOnce()

                if self.onDecision:
                    self.onDecision(
                        decision,
                        self.controller.lastCollectedEventCount,
                        self.controller.lastEventSummary,
                    )

                time.sleep(self.intervalSeconds)

        except Exception as error:
            if self.onError:
                self.onError(str(error))
        finally:
            if self.controller is not None:
                self.controller.close()
            if self.onFinished:
                self.onFinished()

    def stop(self) -> None:
        """Stop monitoring."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

    def is_running(self) -> bool:
        """Check if worker is currently running."""
        return self.running and self.thread is not None and self.thread.is_alive()
