import os
import unittest
from pathlib import Path

from app.monitoring.windowsFileEvents import WindowsFileEventSource, WindowsWatcherUnavailable


class WindowsFileEventTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Portable fallback assertion applies off Windows")
    def testNativeWatcherRequiresWindows(self):
        with self.assertRaises(WindowsWatcherUnavailable):
            WindowsFileEventSource(Path("testFiles"))


if __name__ == "__main__":
    unittest.main()