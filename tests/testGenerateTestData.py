import tempfile
import unittest
from pathlib import Path

from scripts.generateTestData import generateTestFiles


class GenerateTestDataTests(unittest.TestCase):
    def testGeneratorCreatesRequestedSafeFiles(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            count = generateTestFiles(Path(temporaryDirectory), 12)
            files = list(Path(temporaryDirectory).iterdir())
            self.assertEqual(count, 12)
            self.assertEqual(len(files), 12)
            self.assertTrue(all(filePath.is_file() for filePath in files))


if __name__ == "__main__":
    unittest.main()
