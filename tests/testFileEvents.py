import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.features.windowing import FeatureWindow
from app.monitoring.fileEvents import compareSnapshots, getSnapshot


class FileEventTests(unittest.TestCase):
    def testSnapshotComparisonAndFeatureWindow(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            directory = Path(temporaryDirectory)
            samplePath = directory / "sample.txt"
            beforeSnapshot = getSnapshot(directory)
            samplePath.write_text("before", encoding="utf-8")
            afterSnapshot = getSnapshot(directory)
            eventTime = datetime.now(timezone.utc)
            events = compareSnapshots(beforeSnapshot, afterSnapshot, eventTime)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].action.value, "created")

            samplePath.write_text("after", encoding="utf-8")
            changedSnapshot = getSnapshot(directory)
            events = compareSnapshots(afterSnapshot, changedSnapshot, eventTime)
            window = FeatureWindow()
            window.addEvents(events)
            sample = window.createSample(eventTime)
            self.assertEqual(sample.values["fileWriteCount"], 1.0)
            self.assertEqual(sample.schemaVersion, "1.0")

    def testHiddenDirectoriesAreNotMonitored(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            hiddenDirectory = Path(temporaryDirectory) / ".hidden"
            hiddenDirectory.mkdir()
            (hiddenDirectory / "secret.txt").write_text("x", encoding="utf-8")
            self.assertEqual(getSnapshot(Path(temporaryDirectory)), {})


if __name__ == "__main__":
    unittest.main()
