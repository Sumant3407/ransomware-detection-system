import tempfile
import unittest
import sqlite3
from pathlib import Path

from app.detection.riskEngine import RiskDecision, ThreatLevel
from app.runtime.controller import DetectionController


class ControllerTests(unittest.TestCase):
    def testControllerPersistsSafeDecision(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            rootPath = Path(temporaryDirectory)
            monitoredPath = rootPath / "monitored"
            monitoredPath.mkdir()
            databasePath = rootPath / "detector.sqlite3"
            controller = DetectionController(monitoredPath, databasePath)
            decision = controller.collectOnce()
            controller.close()
            connection = sqlite3.connect(databasePath)
            detectionCount = connection.execute(
                "SELECT count(*) FROM detections"
            ).fetchone()[0]
            connection.close()
            self.assertEqual(decision.action, "logOnly")
            self.assertEqual(detectionCount, 0)

    def testControllerDeduplicatesAlertsDuringCooldown(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            rootPath = Path(temporaryDirectory)
            monitoredPath = rootPath / "monitored"
            monitoredPath.mkdir()
            controller = DetectionController(monitoredPath, rootPath / "detector.sqlite3")
            decision = RiskDecision(ThreatLevel.high, 0.8, "ransomwareLike", "alertOnly")
            controller.alertPolicy.recordAlert(decision)
            self.assertFalse(controller.alertPolicy.shouldAlert(decision))
            controller.close()


if __name__ == "__main__":
    unittest.main()
