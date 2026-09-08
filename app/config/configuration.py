"""Application configuration and safe path handling."""

import json
from pathlib import Path
from typing import Any


class ConfigurationError(ValueError):
    """Raised when configuration is invalid."""


def getProjectRoot() -> Path:
    return Path(__file__).resolve().parents[2]


def getDataDirectory() -> Path:
    return getProjectRoot() / "data"


def loadConfiguration(configPath: Path | None = None) -> dict[str, Any]:
    resolvedPath = configPath or Path(__file__).with_name("defaultConfig.json")
    try:
        with resolvedPath.open("r", encoding="utf-8") as configFile:
            configuration = json.load(configFile)
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"Unable to load configuration: {error}") from error
    validateConfiguration(configuration)
    userSettingsPath = getDataDirectory() / "settings.json"
    if configPath is None and userSettingsPath.is_file():
        try:
            userSettings = json.loads(userSettingsPath.read_text(encoding="utf-8"))
            for section in ("monitoring", "notifications", "ui", "startup", "emergencyUsb", "model"):
                if isinstance(userSettings.get(section), dict):
                    configuration.setdefault(section, {}).update(userSettings[section])
            validateConfiguration(configuration)
        except (OSError, json.JSONDecodeError) as error:
            raise ConfigurationError(f"Unable to load saved settings: {error}") from error
    return configuration


def validateConfiguration(configuration: dict[str, Any]) -> None:
    monitoring = configuration.get("monitoring")
    if not isinstance(monitoring, dict):
        raise ConfigurationError("monitoring configuration is required")
    if monitoring.get("sensitivity") not in {"conservative", "balanced", "aggressive"}:
        raise ConfigurationError("monitoring.sensitivity is invalid")
    if not isinstance(monitoring.get("alertCooldownSeconds", 60), int) or monitoring.get("alertCooldownSeconds", 60) < 0:
        raise ConfigurationError("monitoring.alertCooldownSeconds is invalid")
    interval = monitoring.get("intervalSeconds", 2)
    if not isinstance(interval, (int, float)) or interval < 1 or interval > 60:
        raise ConfigurationError("monitoring.intervalSeconds must be between 1 and 60 seconds")
    if not isinstance(configuration.get("notifications", {}).get("enabled", True), bool):
        raise ConfigurationError("notifications.enabled is invalid")
    if not isinstance(configuration.get("startup", {}).get("enabled", True), bool):
        raise ConfigurationError("startup.enabled is invalid")
    if not isinstance(configuration.get("emergencyUsb", {}).get("enabled", True), bool):
        raise ConfigurationError("emergencyUsb.enabled is invalid")
    if configuration.get("response", {}).get("mode") != "alertOnly":
        raise ConfigurationError("Only alertOnly response mode is supported")
    if not isinstance(monitoring.get("paths"), list) or not monitoring["paths"]:
        raise ConfigurationError("At least one monitoring path is required")


def resolveMonitoringPath(pathValue: str) -> Path:
    projectRoot = getProjectRoot().resolve()
    requestedPath = Path(pathValue)
    resolvedPath = (requestedPath if requestedPath.is_absolute() else projectRoot / requestedPath).resolve()
    allowedRoots = {
        (projectRoot / "testFiles").resolve(),
        (projectRoot / "ransomwareDemo" / "demo_files").resolve(),
        (getDataDirectory() / "monitoring").resolve(),
    }
    homeDirectory = Path.home().resolve()
    isUserDirectory = (
        (resolvedPath == homeDirectory or homeDirectory in resolvedPath.parents)
        and requestedPath.is_absolute()
        and resolvedPath != projectRoot
        and projectRoot not in resolvedPath.parents
    )
    if not any(resolvedPath == root or root in resolvedPath.parents for root in allowedRoots) and not isUserDirectory:
        raise ConfigurationError("Monitoring paths must remain inside an approved directory")
    return resolvedPath


def initializeDirectories() -> list[Path]:
    dataDirectory = getDataDirectory()
    directories = [
        dataDirectory / "database",
        dataDirectory / "logs",
        dataDirectory / "models",
        dataDirectory / "quarantine",
        dataDirectory / "backups",
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    return directories
