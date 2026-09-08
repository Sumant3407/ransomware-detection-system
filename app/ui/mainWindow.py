"""Minimal production dashboard for the ransomware detector.

The UI is intentionally lightweight: it reads aggregate state from SQLite and only
loads the ML stack when model validation or an explicit scan requires it.
"""

import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, Qt, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.config.configuration import (
    getDataDirectory,
    getProjectRoot,
    loadConfiguration,
    resolveMonitoringPath,
)
from app.detection.predictor import ModelPredictor, ModelValidationError
from app.monitoring.fileEvents import getSnapshot
from app.runtime.controller import DetectionController
from app.runtime.worker import MonitoringWorker


class StatusCard(QFrame):
    def __init__(self, title: str, value: str = "—", object_name: str = "statusCard"):
        super().__init__()
        self.setObjectName(object_name)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)
        title_label = QLabel(title.upper())
        title_label.setObjectName("cardTitle")
        self.valueLabel = QLabel(value)
        self.valueLabel.setObjectName("cardValue")
        layout.addWidget(title_label)
        layout.addWidget(self.valueLabel)

    def setValue(self, value: str, state: str = "normal") -> None:
        self.valueLabel.setText(value)
        self.valueLabel.setProperty("state", state)
        self.valueLabel.style().unpolish(self.valueLabel)
        self.valueLabel.style().polish(self.valueLabel)


class MainWindow(QMainWindow):
    decisionChanged = Signal(str, float)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ransomware Detector")
        self.setMinimumSize(980, 680)
        self.resize(1080, 720)
        self.workerThread: QThread | None = None
        self.worker: MonitoringWorker | None = None
        self.configuration = loadConfiguration()
        self.databasePath = getDataDirectory() / "database" / "detector.sqlite3"
        self.monitoringPath = resolveMonitoringPath(
            self.configuration["monitoring"]["paths"][0]
        )
        self.modelPath = self.getModelPath()
        self.modelAvailable = False
        self.isProtected = bool(
            self.configuration["monitoring"].get("enabled", True)
        )
        self.currentThreatLevel = "low"
        self.currentRiskScore = 0.0
        self.buildInterface()
        self.applyTheme()
        self.refreshAll()

        # Lightweight live dashboard refresh. It reads SQLite rather than
        # rescanning the protected directory, so the UI remains responsive.
        self.dashboardTimer = QTimer(self)
        self.dashboardTimer.setInterval(200)
        self.dashboardTimer.timeout.connect(self.refreshAll)
        self.dashboardTimer.start()

    def getModelPath(self) -> Path:
        model_path = Path(self.configuration["model"].get("path", ""))
        return model_path if model_path.is_absolute() else getProjectRoot() / model_path

    def buildInterface(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(24, 22, 24, 20)
        root_layout.setSpacing(14)

        # Header
        header = QHBoxLayout()
        brand = QVBoxLayout()
        title = QLabel("Ransomware Detector")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Behavioral protection")
        subtitle.setObjectName("subtitle")
        brand.addWidget(title)
        brand.addWidget(subtitle)
        header.addLayout(brand)
        header.addStretch()

        self.statusPill = QLabel("● PROTECTED")
        self.statusPill.setObjectName("statusPill")
        header.addWidget(self.statusPill)
        self.settingsButton = QPushButton("Settings")
        self.settingsButton.setObjectName("secondaryButton")
        self.settingsButton.clicked.connect(lambda: self.showPage(2))
        header.addWidget(self.settingsButton)
        self.protectionButton = QPushButton("Stop")
        self.protectionButton.setObjectName("primaryButton")
        self.protectionButton.clicked.connect(self.toggleProtection)
        header.addWidget(self.protectionButton)
        root_layout.addLayout(header)

        # Compact status line
        self.statusBanner = QLabel("Protection is ready.")
        self.statusBanner.setObjectName("statusBanner")
        root_layout.addWidget(self.statusBanner)

        self.warningBanner = QLabel("")
        self.warningBanner.setObjectName("warningBanner")
        self.warningBanner.setWordWrap(True)
        self.warningBanner.hide()
        root_layout.addWidget(self.warningBanner)

        # Main metrics
        metrics = QHBoxLayout()
        metrics.setSpacing(10)
        self.protectionCard = StatusCard("Protection", "Protected")
        self.threatCard = StatusCard("Threat level", "Low")
        self.filesCard = StatusCard("Files changed", "0")
        self.detectionsCard = StatusCard("Detections", "0")
        for card in (
            self.protectionCard,
            self.threatCard,
            self.filesCard,
            self.detectionsCard,
        ):
            metrics.addWidget(card, 1)
        root_layout.addLayout(metrics)

        # Two-column activity area
        activity = QHBoxLayout()
        activity.setSpacing(10)

        recent_panel = QFrame()
        recent_panel.setObjectName("panel")
        recent_layout = QVBoxLayout(recent_panel)
        recent_layout.setContentsMargins(16, 14, 16, 14)
        recent_layout.addWidget(self.sectionLabel("Recent activity"))
        self.historyList = QListWidget()
        self.historyList.setObjectName("activityList")
        self.historyList.setMaximumHeight(300)
        self.historyList.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        recent_layout.addWidget(self.historyList, 1)
        activity.addWidget(recent_panel, 2)

        details_panel = QFrame()
        details_panel.setObjectName("panel")
        details_layout = QVBoxLayout(details_panel)
        details_layout.setContentsMargins(16, 14, 16, 14)
        details_layout.addWidget(self.sectionLabel("Protection details"))
        self.detailsLabel = QLabel()
        self.detailsLabel.setObjectName("details")
        self.detailsLabel.setWordWrap(True)
        details_layout.addWidget(self.detailsLabel)
        details_layout.addStretch()
        activity.addWidget(details_panel, 1)
        root_layout.addLayout(activity, 1)

        actions = QHBoxLayout()
        scan = QPushButton("Scan now")
        scan.setObjectName("secondaryButton")
        scan.clicked.connect(self.scanNow)
        refresh = QPushButton("Refresh")
        refresh.setObjectName("secondaryButton")
        refresh.clicked.connect(self.refreshAll)
        history = QPushButton("Detection history")
        history.setObjectName("secondaryButton")
        history.clicked.connect(lambda: self.showPage(1))
        actions.addWidget(scan)
        actions.addWidget(refresh)
        actions.addWidget(history)
        actions.addStretch()
        root_layout.addLayout(actions)

        self.pages = QStackedWidget()
        self.pages.addWidget(self.createDashboardPage(root))
        self.pages.addWidget(self.createHistoryPage())
        self.pages.addWidget(self.createSettingsPage())
        # Keep dashboard as the central widget while allowing settings/history to replace it.
        self.dashboardPage = self.pages.widget(0)
        self.setCentralWidget(self.pages)
        self.showPage(0)

    def createDashboardPage(self, root: QWidget) -> QWidget:
        return root

    def createHistoryPage(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 20)
        top = QHBoxLayout()
        top.addWidget(self.sectionLabel("Detection history"))
        top.addStretch()
        back = QPushButton("Back")
        back.setObjectName("secondaryButton")
        back.clicked.connect(lambda: self.showPage(0))
        export = QPushButton("Export CSV")
        export.setObjectName("secondaryButton")
        export.clicked.connect(self.exportHistory)
        clear = QPushButton("Clear")
        clear.setObjectName("secondaryButton")
        clear.clicked.connect(self.clearHistory)
        top.addWidget(export)
        top.addWidget(clear)
        top.addWidget(back)
        layout.addLayout(top)
        self.fullHistoryList = QListWidget()
        self.fullHistoryList.setObjectName("activityList")
        layout.addWidget(self.fullHistoryList, 1)
        return page

    def createSettingsPage(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 20)
        top = QHBoxLayout()
        top.addWidget(self.sectionLabel("Settings"))
        top.addStretch()
        back = QPushButton("Back to dashboard")
        back.setObjectName("secondaryButton")
        back.clicked.connect(lambda: self.showPage(0))
        top.addWidget(back)
        layout.addLayout(top)

        form = QFormLayout()
        form.setVerticalSpacing(12)

        self.modelInput = QComboBox()
        self.modelInput.setMinimumWidth(380)
        self.populateModels()
        form.addRow("Active model", self.modelInput)

        self.intervalInput = QSpinBox()
        self.intervalInput.setRange(1, 60)
        self.intervalInput.setSuffix(" sec")
        self.intervalInput.setValue(
            int(self.configuration["monitoring"].get("intervalSeconds", 1))
        )
        form.addRow("Monitoring interval", self.intervalInput)

        self.sensitivityInput = QComboBox()
        self.sensitivityInput.addItems(["conservative", "balanced", "aggressive"])
        self.sensitivityInput.setCurrentText(
            self.configuration["monitoring"]["sensitivity"]
        )
        form.addRow("Detection sensitivity", self.sensitivityInput)

        self.notificationsInput = QCheckBox("Show desktop notifications")
        self.notificationsInput.setChecked(
            self.configuration["notifications"]["enabled"]
        )
        form.addRow("", self.notificationsInput)

        self.startupInput = QCheckBox("Start protection with Windows")
        self.startupInput.setChecked(
            self.configuration.get("startup", {}).get("enabled", True)
        )
        form.addRow("", self.startupInput)

        self.usbInput = QCheckBox("Scan automatically when the trusted emergency USB is inserted")
        self.usbInput.setChecked(
            self.configuration.get("emergencyUsb", {}).get("enabled", True)
        )
        form.addRow("", self.usbInput)

        directory_row = QWidget()
        directory_layout = QHBoxLayout(directory_row)
        directory_layout.setContentsMargins(0, 0, 0, 0)
        self.directoryLabel = QLabel(str(self.monitoringPath))
        self.directoryLabel.setObjectName("pathLabel")
        browse = QPushButton("Browse")
        browse.setObjectName("secondaryButton")
        browse.clicked.connect(self.browseMonitoringDirectory)
        directory_layout.addWidget(self.directoryLabel, 1)
        directory_layout.addWidget(browse)
        form.addRow("Primary protected folder", directory_row)

        layout.addLayout(form)
        self.settingsStatusLabel = QLabel("Changes are saved locally.")
        self.settingsStatusLabel.setObjectName("muted")
        layout.addWidget(self.settingsStatusLabel)

        save = QPushButton("Save settings")
        save.setObjectName("primaryButton")
        save.clicked.connect(self.saveSettings)
        layout.addWidget(save, 0, Qt.AlignmentFlag.AlignLeft)

        # Advanced model page is still available without putting it on the dashboard.
        model_info = QFrame()
        model_info.setObjectName("panel")
        model_layout = QVBoxLayout(model_info)
        model_layout.addWidget(self.sectionLabel("Model information"))
        self.modelStatusLabel = QLabel("Checking model…")
        self.modelStatusLabel.setObjectName("details")
        self.modelStatusLabel.setWordWrap(True)
        model_layout.addWidget(self.modelStatusLabel)
        validate = QPushButton("Validate selected model")
        validate.setObjectName("secondaryButton")
        validate.clicked.connect(self.validateModel)
        model_layout.addWidget(validate, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(model_info)
        layout.addStretch()
        return page

    def sectionLabel(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("sectionTitle")
        return label

    def populateModels(self) -> None:
        self.modelInput.clear()
        model_root = getDataDirectory() / "models"
        candidates = []
        if model_root.exists():
            candidates.extend(model_root.rglob("*.joblib"))
        configured = self.getModelPath()
        if configured.is_file() and configured not in candidates:
            candidates.append(configured)
        if not candidates:
            self.modelInput.addItem("No model installed", "")
            return
        for path in sorted(candidates, key=str):
            self.modelInput.addItem(str(path), str(path))
        index = self.modelInput.findData(str(configured))
        if index >= 0:
            self.modelInput.setCurrentIndex(index)

    def showPage(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        if index == 0:
            self.refreshAll()
        elif index == 1:
            self.loadFullHistory()
        elif index == 2:
            self.populateModels()
            self.validateModel()

    def applyTheme(self) -> None:
        self.setStyleSheet(
            """
            QWidget#root, QStackedWidget, QWidget {
                background: #050505;
                color: #ededed;
                font-family: "Segoe UI";
                font-size: 13px;
            }
            QMainWindow { background: #050505; }
            QLabel { background: transparent; border: 0; }
            #pageTitle { font-size: 25px; font-weight: 700; }
            #subtitle, #muted, #cardTitle { color: #777777; }
            #subtitle { font-size: 12px; }
            #statusPill {
                padding: 7px 10px;
                border-radius: 12px;
                color: #8ee8a7;
                background: #0b1710;
                border: 1px solid #193a24;
                font-size: 11px;
                font-weight: 700;
            }
            #warningBanner {
                background: #21120a;
                border: 1px solid #6b3a16;
                border-radius: 8px;
                padding: 11px 13px;
                color: #f0c674;
                font-weight: 700;
            }
            #warningBanner[severity="critical"] {
                background: #260b0b;
                border: 1px solid #7a2020;
                color: #ff8f8f;
            }
            #statusBanner {
                background: #090909;
                border: 1px solid #171717;
                border-radius: 8px;
                padding: 10px 12px;
                color: #bcbcbc;
            }
            #statusCard, #panel {
                background: #0b0b0b;
                border: 1px solid #181818;
                border-radius: 9px;
            }
            #statusCard { min-height: 76px; }
            #cardTitle {
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 1px;
            }
            #cardValue {
                font-size: 22px;
                font-weight: 700;
                color: #ededed;
            }
            #cardValue[state="good"] { color: #8ee8a7; }
            #cardValue[state="warn"] { color: #e8c37a; }
            #cardValue[state="bad"] { color: #ff8585; }
            #sectionTitle { font-size: 16px; font-weight: 700; }
            #details, #pathLabel { color: #b0b0b0; line-height: 1.4; }
            #activityList {
                background: #080808;
                border: 0;
                border-radius: 6px;
                padding: 6px;
                outline: 0;
            }
            #activityList::item {
                padding: 9px;
                border-bottom: 1px solid #151515;
                background: #080808;
            }
            #activityList::item:selected {
                background: #111111;
                color: #ffffff;
            }
            QPushButton {
                min-height: 32px;
                padding: 0 13px;
                border-radius: 7px;
                font-weight: 600;
                background: #111111;
                color: #dddddd;
                border: 1px solid #202020;
            }
            QPushButton:hover { background: #171717; }
            #primaryButton {
                background: #e8e8e8;
                color: #090909;
                border: 0;
            }
            #primaryButton:hover { background: #ffffff; }
            QComboBox, QSpinBox, QLineEdit {
                background: #0d0d0d;
                color: #eeeeee;
                border: 1px solid #252525;
                border-radius: 6px;
                padding: 7px;
                min-height: 28px;
            }
            QCheckBox { spacing: 8px; padding: 4px 0; }
            QTabWidget::pane, QTabBar { border: 0; }
            QScrollBar:vertical {
                background: #050505; width: 8px; margin: 0;
            }
            QScrollBar::handle:vertical { background: #252525; border-radius: 4px; }
            """
        )

    def refreshAll(self) -> None:
        self.refreshStatus()
        self.loadHistory()

    def refreshStatus(self) -> None:
        connection = sqlite3.connect(self.databasePath)
        try:
            # Cumulative count for the active/latest monitoring session.
            # This increments as new events are committed instead of rolling
            # back to zero every second.
            changed_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM fileEvents
                WHERE sessionId = (
                    SELECT sessionId
                    FROM sessions
                    ORDER BY sessionId DESC
                    LIMIT 1
                )
                """
            ).fetchone()[0]

            detection_count = connection.execute(
                """
                SELECT count(*)
                FROM detections
                WHERE classification != 'benign'
                """
            ).fetchone()[0]

            latest = connection.execute(
                """
                SELECT occurredAt, action, pathHash
                FROM fileEvents
                ORDER BY eventId DESC
                LIMIT 1
                """
            ).fetchone()

            latest_detection = connection.execute(
                """
                SELECT occurredAt, classification, riskScore
                FROM detections
                ORDER BY detectionId DESC
                LIMIT 1
                """
            ).fetchone()

            self.filesCard.setValue(str(changed_count))
            self.detectionsCard.setValue(str(detection_count))
            self.modelAvailable = self.isModelValid(self.modelPath)
        finally:
            connection.close()

        if self.isProtected:
            self.protectionCard.setValue("Protected", "good")
            self.statusPill.setText("● PROTECTED")
        else:
            self.protectionCard.setValue("Stopped", "warn")
            self.statusPill.setText("● STOPPED")

        threat = self.currentThreatLevel
        score = self.currentRiskScore

        if latest_detection and threat == "low":
            score = float(latest_detection[2])
            if score >= 0.85:
                threat = "critical"
            elif score >= 0.65:
                threat = "high"
            elif score >= 0.40:
                threat = "medium"

        state = (
            "good"
            if threat == "low"
            else "warn"
            if threat == "medium"
            else "bad"
        )
        self.threatCard.setValue(threat.capitalize(), state)

        if threat in {"high", "critical"}:
            self.warningBanner.setText(
                f"⚠  RANSOMWARE-LIKE ACTIVITY DETECTED  •  "
                f"Risk {score:.2f}  •  {changed_count} file events this session"
            )
            self.warningBanner.setProperty("severity", "critical")
            self.warningBanner.show()
        elif threat == "medium":
            self.warningBanner.setText(
                f"⚠  SUSPICIOUS FILE ACTIVITY  •  "
                f"Risk {score:.2f}  •  {changed_count} file events this session"
            )
            self.warningBanner.setProperty("severity", "warning")
            self.warningBanner.show()
        else:
            self.warningBanner.hide()

        if latest:
            timestamp, action, path_hash = latest
            self.statusBanner.setText(
                f"Last file event: {action}  •  {timestamp}"
            )
            self.detailsLabel.setText(
                f"Protected folder\n{self.monitoringPath}\n\n"
                f"Active model\n"
                f"{self.modelPath if self.modelAvailable else 'No validated model'}\n\n"
                f"File events (this session)\n{changed_count}"
            )
        else:
            self.statusBanner.setText(
                "No file activity recorded yet."
            )
            self.detailsLabel.setText(
                f"Protected folder\n{self.monitoringPath}\n\n"
                f"Active model\n"
                f"{self.modelPath if self.modelAvailable else 'No validated model'}"
            )

        self.protectionButton.setText(
            "Stop" if self.isProtected else "Start"
        )

    def isModelValid(self, path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            ModelPredictor(path)
            return True
        except ModelValidationError:
            return False

    def loadHistory(self) -> None:
        connection = sqlite3.connect(self.databasePath)
        try:
            rows = connection.execute(
                "SELECT occurredAt, classification, riskScore "
                "FROM detections ORDER BY detectionId DESC LIMIT 8"
            ).fetchall()
        finally:
            connection.close()
        self.historyList.clear()
        if not rows:
            self.historyList.addItem("No detections recorded.")
            return
        for occurred_at, classification, score in rows:
            self.historyList.addItem(
                f"{occurred_at}   {classification}   risk {float(score):.2f}"
            )

    def loadFullHistory(self) -> None:
        connection = sqlite3.connect(self.databasePath)
        try:
            rows = connection.execute(
                "SELECT occurredAt, classification, riskScore, actionTaken "
                "FROM detections ORDER BY detectionId DESC LIMIT 250"
            ).fetchall()
        finally:
            connection.close()
        self.fullHistoryList.clear()
        for occurred_at, classification, score, action in rows:
            self.fullHistoryList.addItem(
                f"{occurred_at}   {classification}   risk {float(score):.3f}   {action}"
            )

    @Slot()
    def toggleProtection(self) -> None:
        if self.workerThread is not None:
            self.worker.stop()
            self.statusBanner.setText("Stopping protection…")
            return
        if not self.configuration["monitoring"].get("enabled", True):
            self.statusBanner.setText("Monitoring is disabled in Settings.")
            return
        self.workerThread = QThread(self)
        self.worker = MonitoringWorker(
            self.monitoringPath,
            self.databasePath,
            self.modelPath if self.modelAvailable else None,
            intervalSeconds=float(
                self.configuration["monitoring"].get("intervalSeconds", 1)
            ),
        )
        self.worker.moveToThread(self.workerThread)
        self.workerThread.started.connect(self.worker.run)
        self.worker.decisionReady.connect(self.handleDecision)
        self.worker.failed.connect(self.handleWorkerError)
        self.worker.finished.connect(self.workerThread.quit)
        self.worker.finished.connect(self.clearWorker)
        self.workerThread.finished.connect(self.workerThread.deleteLater)
        self.workerThread.start()
        self.isProtected = True
        self.refreshStatus()
        self.statusBanner.setText("Protection is monitoring the configured folder.")

    @Slot()
    def clearWorker(self) -> None:
        self.worker = None
        if self.workerThread:
            self.workerThread.deleteLater()
        self.workerThread = None
        self.isProtected = False
        self.refreshStatus()
        self.statusBanner.setText("Protection stopped.")

    @Slot(str, float, int, str)
    def handleDecision(
        self,
        level: str,
        score: float,
        eventCount: int,
        eventSummary: str,
    ) -> None:
        self.currentThreatLevel = level
        self.currentRiskScore = score

        state = (
            "good"
            if level == "low"
            else "warn"
            if level == "medium"
            else "bad"
        )
        self.threatCard.setValue(
            level.capitalize(),
            state,
        )

        if eventCount:
            self.statusBanner.setText(
                f"Live activity: {eventCount} file event(s)  •  {eventSummary}"
            )

        if level in {"high", "critical"}:
            self.warningBanner.setText(
                f"⚠  RANSOMWARE-LIKE ACTIVITY DETECTED  •  "
                f"Risk {score:.2f}  •  {eventCount} new file events"
            )
            self.warningBanner.setProperty("severity", "critical")
            self.warningBanner.style().unpolish(self.warningBanner)
            self.warningBanner.style().polish(self.warningBanner)
            self.warningBanner.show()

            self.historyList.insertItem(
                0,
                f"{datetime.now().strftime('%H:%M:%S')}   "
                f"{level.upper()}   risk {score:.2f}",
            )
        elif level == "medium":
            self.warningBanner.setText(
                f"⚠  SUSPICIOUS FILE ACTIVITY  •  "
                f"Risk {score:.2f}  •  {eventCount} new file events"
            )
            self.warningBanner.setProperty("severity", "warning")
            self.warningBanner.style().unpolish(self.warningBanner)
            self.warningBanner.style().polish(self.warningBanner)
            self.warningBanner.show()

        while self.historyList.count() > 8:
            self.historyList.takeItem(self.historyList.count() - 1)

        self.loadHistory()

    @Slot(str)
    def handleWorkerError(self, message: str) -> None:
        self.statusBanner.setText(f"Monitoring unavailable: {message}")
        self.isProtected = False
        self.refreshStatus()

    @Slot()
    def scanNow(self) -> None:
        try:
            controller = DetectionController(
                self.monitoringPath,
                self.databasePath,
                self.modelPath if self.modelAvailable else None,
            )
            try:
                decision = controller.collectOnce()
            finally:
                controller.close()
            self.currentThreatLevel = decision.level.value
            self.currentRiskScore = decision.score
            self.refreshStatus()
            self.statusBanner.setText("Scan completed.")
        except Exception as error:
            self.statusBanner.setText(f"Scan unavailable: {error}")

    @Slot()
    def saveSettings(self) -> None:
        settings_path = getDataDirectory() / "settings.json"
        updated = json.loads(json.dumps(self.configuration))
        updated.setdefault("monitoring", {})
        updated.setdefault("notifications", {})
        updated.setdefault("startup", {})
        updated.setdefault("emergencyUsb", {})
        selected_model = self.modelInput.currentData()
        if selected_model:
            updated["model"]["path"] = selected_model
            updated["model"]["version"] = Path(selected_model).stem
            self.modelPath = Path(selected_model)
        updated["monitoring"]["intervalSeconds"] = self.intervalInput.value()
        updated["monitoring"]["sensitivity"] = self.sensitivityInput.currentText()
        updated["notifications"]["enabled"] = self.notificationsInput.isChecked()
        updated["startup"]["enabled"] = self.startupInput.isChecked()
        updated["emergencyUsb"]["enabled"] = self.usbInput.isChecked()
        updated["monitoring"]["paths"] = [str(self.monitoringPath)]
        settings_path.write_text(json.dumps(updated, indent=2), encoding="utf-8")
        self.configuration = updated
        self.settingsStatusLabel.setText("Settings saved.")
        self.validateModel()
        self.refreshStatus()

    @Slot()
    def browseMonitoringDirectory(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self, "Choose protected folder", str(self.monitoringPath)
        )
        if not selected:
            return
        try:
            self.monitoringPath = resolveMonitoringPath(selected)
        except ValueError as error:
            self.settingsStatusLabel.setText(f"Invalid folder: {error}")
            return
        self.directoryLabel.setText(str(self.monitoringPath))

    @Slot()
    def validateModel(self) -> None:
        self.modelPath = Path(self.modelInput.currentData() or self.getModelPath())
        if not self.modelPath.is_absolute():
            self.modelPath = getProjectRoot() / self.modelPath
        try:
            ModelPredictor(self.modelPath)
            self.modelAvailable = True
            self.modelStatusLabel.setText(
                f"Ready\n{self.modelPath}"
            )
        except ModelValidationError as error:
            self.modelAvailable = False
            self.modelStatusLabel.setText(
                f"Unavailable\n{error}\n{self.modelPath}"
            )

    @Slot()
    def clearHistory(self) -> None:
        connection = sqlite3.connect(self.databasePath)
        try:
            connection.execute("DELETE FROM alerts")
            connection.execute("DELETE FROM detections")
            connection.commit()
        finally:
            connection.close()
        self.loadFullHistory()
        self.refreshStatus()
        self.statusBanner.setText("Detection history cleared.")

    @Slot()
    def exportHistory(self) -> None:
        output, _ = QFileDialog.getSaveFileName(
            self, "Export detection history", "detections.csv", "CSV files (*.csv)"
        )
        if not output:
            return
        connection = sqlite3.connect(self.databasePath)
        try:
            rows = connection.execute(
                "SELECT occurredAt, classification, riskScore, actionTaken "
                "FROM detections ORDER BY detectionId"
            ).fetchall()
        finally:
            connection.close()
        with open(output, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp", "classification", "riskScore", "actionTaken"])
            writer.writerows(rows)

    def runUnlearning(self) -> None:
        # Retained as a programmatic compatibility hook; unlearning remains a
        # training-time operation and is intentionally not loaded into the dashboard.
        raise RuntimeError("Run unlearning from the trainingModel workflow.")

    def closeEvent(self, event) -> None:
        if self.worker is not None:
            self.worker.stop()
        if self.workerThread is not None:
            self.workerThread.quit()
            self.workerThread.wait(2500)
        event.accept()


def runGui() -> int:
    application = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return application.exec()
