from __future__ import annotations

import sys
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot, Qt
from PySide6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QVBoxLayout, QWidget
)

from simulator import DemoSimulator, FILE_COUNT, MAX_SIZE


class Worker(QObject):
    progress = Signal(int, int, str)
    done = Signal(str)
    failed = Signal(str)

    def __init__(self, simulator, operation):
        super().__init__()
        self.simulator = simulator
        self.operation = operation

    def run(self):
        try:
            if self.operation == "generate":
                n = self.simulator.generate(lambda i, total, name, size: self.progress_signal.emit(i, total, name))
                self.done.emit(f"Generated {n} files.")
            elif self.operation == "simulate":
                self.simulator.simulate(lambda i, total, name: self.progress_signal.emit(i, total, name))
                self.done.emit("Simulation stopped/completed.")
            elif self.operation == "restore":
                n = self.simulator.restore(lambda i, total, name: self.progress_signal.emit(i, total, name))
                self.done.emit(f"Restored {n} files.")
        except Exception as exc:
            self.failed.emit(str(exc))


class DemoWindow(QMainWindow):
    progress_signal = Signal(int, int, str)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ransomware Detection — Safe Demo")
        self.resize(720, 430)
        self.simulator = DemoSimulator()
        self.thread = None
        self.worker = None

        self.status = QLabel("Ready")
        self.path = QLabel(f"Sandbox: {self.simulator.root}")
        self.path.setWordWrap(True)
        self.progress_bar = QProgressBar()
        self.detail = QLabel("Creates 300 dummy files, then performs a reversible byte transformation only inside the sandbox.")

        self.generate_btn = QPushButton("Generate 300 Files")
        self.start_btn = QPushButton("Start Simulation")
        self.stop_btn = QPushButton("Stop")
        self.restore_btn = QPushButton("Restore Files")

        self.generate_btn.clicked.connect(lambda: self.start_operation("generate"))
        self.start_btn.clicked.connect(lambda: self.start_operation("simulate"))
        self.stop_btn.clicked.connect(self.simulator.stop)
        self.restore_btn.clicked.connect(lambda: self.start_operation("restore"))

        self.progress_signal.connect(self.update_progress, Qt.ConnectionType.QueuedConnection)

        root = QWidget()
        layout = QVBoxLayout(root)
        title = QLabel("Safe Ransomware Workload Demo")
        title.setStyleSheet("font-size: 24px; font-weight: 700;")
        layout.addWidget(title)
        layout.addWidget(QLabel(f"Workload: {FILE_COUNT} files • maximum file size: {MAX_SIZE / (1024*1024):.0f} MB"))
        layout.addWidget(self.path)
        layout.addSpacing(12)
        layout.addWidget(self.detail)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.status)

        buttons = QHBoxLayout()
        buttons.addWidget(self.generate_btn)
        buttons.addWidget(self.start_btn)
        buttons.addWidget(self.stop_btn)
        buttons.addWidget(self.restore_btn)
        layout.addLayout(buttons)
        self.setCentralWidget(root)

        self.setStyleSheet("""
            QWidget { background: #090909; color: #eeeeee; }
            QPushButton { background: #171717; border: 1px solid #444; padding: 10px 16px; border-radius: 6px; }
            QPushButton:hover { background: #222; }
            QProgressBar { border: 1px solid #444; height: 18px; text-align: center; }
        """)

    def start_operation(self, operation):
        if self.thread is not None:
            QMessageBox.information(self, "Busy", "An operation is already running.")
            return

        self.generate_btn.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.restore_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status.setText(f"Running: {operation}")

        self.thread = threading.Thread(target=self._run_operation, args=(operation,), daemon=True)
        self.thread.start()

    def _run_operation(self, operation):
        try:
            if operation == "generate":
                n = self.simulator.generate(lambda i, total, name, size: self.progress_signal.emit(i, total, name))
                self._finish(f"Generated {n} files.")
            elif operation == "simulate":
                self.simulator.simulate(lambda i, total, name: self.progress_signal.emit(i, total, name))
                self._finish("Simulation completed/stopped.")
            else:
                n = self.simulator.restore(lambda i, total, name: self.progress_signal.emit(i, total, name))
                self._finish(f"Restored {n} files.")
        except Exception as exc:
            self._fail(str(exc))

    @Slot(int, int, str)
    def update_progress(self, current, total, name):
        if total:
            self.progress_bar.setValue(int(current * 100 / total))
        self.status.setText(f"Processing {current}/{total}: {name}")

    def _finish(self, message):
        self.done_signal.emit(message)

    def _fail(self, message):
        self.error_signal.emit(message)

    done_signal = Signal(str)
    error_signal = Signal(str)

    def showEvent(self, event):
        super().showEvent(event)
        try:
            self.done_signal.connect(self.operation_done, Qt.ConnectionType.QueuedConnection)
            self.error_signal.connect(self.operation_failed, Qt.ConnectionType.QueuedConnection)
        except Exception:
            pass

    @Slot(str)
    def operation_done(self, message):
        self.status.setText(message)
        self.generate_btn.setEnabled(True)
        self.start_btn.setEnabled(True)
        self.restore_btn.setEnabled(True)
        self.thread = None

    @Slot(str)
    def operation_failed(self, message):
        self.status.setText("Operation failed")
        self.generate_btn.setEnabled(True)
        self.start_btn.setEnabled(True)
        self.restore_btn.setEnabled(True)
        self.thread = None
        QMessageBox.critical(self, "Demo error", message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DemoWindow()
    window.show()
    sys.exit(app.exec())
