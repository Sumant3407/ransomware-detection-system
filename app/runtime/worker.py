"""Qt worker boundary for background monitoring."""

from PySide6.QtCore import QObject, Signal, Slot, QThread

from pathlib import Path

from app.runtime.controller import DetectionController


class MonitoringWorker(QObject):
    decisionReady = Signal(str, float, int, str)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, monitoredPath: Path, databasePath: Path, modelPath: Path | None = None, intervalSeconds: float = 1.0):
        super().__init__()
        self.monitoredPath = monitoredPath
        self.databasePath = databasePath
        self.modelPath = modelPath
        self.controller: DetectionController | None = None
        self.intervalSeconds = intervalSeconds
        self.running = False

    @Slot()
    def run(self) -> None:
        self.running = True
        self.controller = DetectionController(
            self.monitoredPath,
            self.databasePath,
            self.modelPath,
        )
        try:
            while self.running:
                decision = self.controller.collectOnce()
                self.decisionReady.emit(
                    decision.level.value,
                    decision.score,
                    self.controller.lastCollectedEventCount,
                    self.controller.lastEventSummary,
                )
                QThread.msleep(max(100, int(self.intervalSeconds * 1000)))
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            if self.controller is not None:
                self.controller.close()
            self.finished.emit()

    @Slot()
    def stop(self) -> None:
        self.running = False