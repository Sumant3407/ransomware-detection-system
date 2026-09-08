import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.config.configuration import ConfigurationError, loadConfiguration, resolveMonitoringPath
from app.storage.sqliteStore import initializeDatabase


class FoundationTests(unittest.TestCase):
    def testConfigurationLoadsAndResolvesProjectPath(self):
        configuration = loadConfiguration()
        self.assertEqual(configuration["response"]["mode"], "alertOnly")
        self.assertTrue(resolveMonitoringPath("testFiles").is_relative_to(Path.cwd()))

    def testConfigurationRejectsApplicationDirectories(self):
        with self.assertRaises(ConfigurationError):
            resolveMonitoringPath("app")

    def testConfigurationRejectsProjectRootAndOutsidePath(self):
        with self.assertRaises(ConfigurationError):
            resolveMonitoringPath(".")
        with self.assertRaises(ConfigurationError):
            resolveMonitoringPath("../outside")

    def testDatabaseInitializesVersionedSchema(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            databasePath = Path(temporaryDirectory) / "detector.sqlite3"
            connection = initializeDatabase(databasePath)
            version = connection.execute(
                "SELECT version FROM schemaVersion"
            ).fetchone()[0]
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            connection.close()

        self.assertEqual(version, 1)
        self.assertTrue(
            {
                "fileEvents",
                "detections",
                "models",
                "alerts",
                "metricSamples",
                "unlearningOperations",
                "systemStatus",
            }.issubset(tables)
        )

    def testConfigurationRejectsUnsafeResponseMode(self):
        with tempfile.TemporaryDirectory() as temporaryDirectory:
            configPath = Path(temporaryDirectory) / "config.json"
            config = loadConfiguration()
            config["response"]["mode"] = "deleteFiles"
            configPath.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                loadConfiguration(configPath)


if __name__ == "__main__":
    unittest.main()