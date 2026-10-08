"""Qt worker boundary for background monitoring with multi-path support."""

from typing import Optional, Sequence, Union
from pathlib import Path
from PySide6.QtCore import QObject, Signal, Slot, QThread

from app.runtime.controller import DetectionController


class MonitoringWorker(QObject):
    decisionReady = Signal(str, float, int, str)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        monitoredPath: Path | Sequence[Path] | None = None,
        databasePath: Path = ...,
        modelPath: Path | None = None,
        intervalSeconds: float = 1.0,
        monitoredPaths: Optional[Sequence[Path]] = None,
    ):
        super().__init__()
        if monitoredPaths is not None:
            self.monitoredPaths = [Path(p).resolve() for p in (monitoredPaths if isinstance(monitoredPaths, (list, tuple, set)) else [monitoredPaths])]
        elif monitoredPath is not None:
            self.monitoredPaths = [Path(p).resolve() for p in (monitoredPath if isinstance(monitoredPath, (list, tuple, set)) else [monitoredPath])]
        else:
            raise ValueError("At least one monitored path is required")

        self.monitoredPath = self.monitoredPaths[0]
        self.databasePath = databasePath
        self.modelPath = modelPath
        self.controller: DetectionController | None = None
        self.intervalSeconds = intervalSeconds
        self.running = False

    @Slot()
    def run(self) -> None:
        self.running = True
        self.controller = DetectionController(
            monitoredPaths=self.monitoredPaths,
            databasePath=self.databasePath,
            modelPath=self.modelPath,
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