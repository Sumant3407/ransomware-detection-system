"""Command-line entry point for the detection application foundation."""

import argparse
from pathlib import Path

from app import applicationVersion
from app.config.configuration import getDataDirectory, getProjectRoot, initializeDirectories, loadConfiguration, resolveMonitoringPath
from app.storage.sqliteStore import initializeDatabase
from app.logging.logger import createLogger
from app.runtime.controller import DetectionController


def getArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline ransomware behavior detector")
    parser.add_argument("--status", action="store_true", help="Show protection status")
    parser.add_argument("--version", action="store_true", help="Show application version")
    parser.add_argument("--gui", action="store_true", help="Launch the desktop dashboard")
    parser.add_argument("--monitor", action="store_true", help="Run a bounded headless monitoring session")
    parser.add_argument("--samples", type=int, default=1, help="Number of monitoring samples")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between monitoring samples")
    return parser.parse_args()


def initializeApplication() -> tuple[dict, Path]:
    configuration = loadConfiguration()
    initializeDirectories()
    for pathValue in configuration["monitoring"]["paths"]:
        resolvedPath = resolveMonitoringPath(pathValue)
        resolvedPath.mkdir(parents=True, exist_ok=True)
    databasePath = getDataDirectory() / "database" / "detector.sqlite3"
    connection = initializeDatabase(databasePath)
    connection.close()
    createLogger(getDataDirectory() / "logs", configuration["logging"]["level"])
    return configuration, databasePath


def main() -> int:
    arguments = getArguments()
    if arguments.version:
        print(applicationVersion)
        return 0
    try:
        configuration, databasePath = initializeApplication()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Protection limited: {error}")
        return 1
    if arguments.status:
        monitoringEnabled = configuration["monitoring"]["enabled"]
        print("Protected" if monitoringEnabled else "Protection disabled")
        print(f"Database: {databasePath}")
        print("Response policy: alertOnly")
        return 0
    if arguments.gui:
        try:
            from app.ui.mainWindow import runGui
        except ImportError as error:
            print(f"Desktop UI unavailable: {error}")
            return 1
        return runGui()
    if arguments.monitor:
        monitoringPath = resolveMonitoringPath(configuration["monitoring"]["paths"][0])
        modelPathValue = configuration["model"].get("path")
        modelPath = Path(modelPathValue)
        if not modelPath.is_absolute():
            modelPath = getProjectRoot() / modelPath
        controller = DetectionController(monitoringPath, databasePath, modelPath)
        try:
            controller.run(arguments.interval, max(1, arguments.samples))
        except (OSError, ValueError) as error:
            print(f"Monitoring unavailable: {error}")
            return 1
        print("Monitoring session completed")
        return 0
    print("Foundation initialized. Runtime monitoring is not enabled yet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
