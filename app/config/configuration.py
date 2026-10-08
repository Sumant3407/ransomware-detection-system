"""Application configuration, safe path handling, and deep preflight validation."""

import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.security.pathValidator import PathValidator, PathValidationError

logger = logging.getLogger(__name__)


class ConfigurationError(ValueError):
    """Raised when configuration is invalid or preflight checks fail."""


def getProjectRoot() -> Path:
    return Path(__file__).resolve().parents[2]


def getDataDirectory() -> Path:
    return getProjectRoot() / "data"


def loadConfiguration(configPath: Path | str | None = None) -> dict[str, Any]:
    resolvedPath = Path(configPath) if configPath is not None else Path(__file__).with_name("defaultConfig.json")
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
            for section in ("monitoring", "notifications", "ui", "startup", "emergencyUsb", "model", "logging"):
                if isinstance(userSettings.get(section), dict):
                    configuration.setdefault(section, {}).update(userSettings[section])
            validateConfiguration(configuration)
        except (OSError, json.JSONDecodeError) as error:
            raise ConfigurationError(f"Unable to load saved settings: {error}") from error

    return configuration


def validateConfiguration(configuration: dict[str, Any]) -> None:
    """
    Validate configuration structure, value types, and bounds.

    Args:
        configuration: Dictionary of configuration settings

    Raises:
        ConfigurationError: If any configuration value is invalid or out of bounds
    """
    if not isinstance(configuration, dict):
        raise ConfigurationError("Configuration must be a dictionary")

    # 1. Monitoring Section
    monitoring = configuration.get("monitoring")
    if not isinstance(monitoring, dict):
        raise ConfigurationError("monitoring configuration is required")

    if monitoring.get("sensitivity") not in {"conservative", "balanced", "aggressive"}:
        raise ConfigurationError("monitoring.sensitivity must be one of: conservative, balanced, aggressive")

    cooldown = monitoring.get("alertCooldownSeconds", 60)
    if not isinstance(cooldown, (int, float)) or cooldown < 0 or cooldown > 86400:
        raise ConfigurationError("monitoring.alertCooldownSeconds must be between 0 and 86400 seconds")

    interval = monitoring.get("intervalSeconds", 2)
    if not isinstance(interval, (int, float)) or interval < 0.1 or interval > 60:
        raise ConfigurationError("monitoring.intervalSeconds must be between 0.1 and 60 seconds")

    if not isinstance(monitoring.get("paths"), list) or not monitoring["paths"]:
        raise ConfigurationError("At least one monitoring path is required in monitoring.paths")

    # 2. Boolean Flags
    for section in ("notifications", "startup", "emergencyUsb"):
        if section in configuration:
            secDict = configuration[section]
            if isinstance(secDict, dict) and "enabled" in secDict:
                if not isinstance(secDict["enabled"], bool):
                    raise ConfigurationError(f"{section}.enabled must be a boolean (true/false)")

    # 3. Response Mode
    if configuration.get("response", {}).get("mode") != "alertOnly":
        raise ConfigurationError("Only 'alertOnly' response mode is supported")

    # 4. Logging Configuration
    if "logging" in configuration:
        loggingConfig = configuration["logging"]
        if isinstance(loggingConfig, dict):
            level = loggingConfig.get("level", "INFO")
            if not isinstance(level, str) or level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
                raise ConfigurationError(f"Invalid logging.level '{level}'. Must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")

            retention = loggingConfig.get("retentionDays", 30)
            if not isinstance(retention, int) or retention < 1 or retention > 3650:
                raise ConfigurationError("logging.retentionDays must be an integer between 1 and 3650")

    # 5. Path Validation
    projectRoot = getProjectRoot()
    allowedBasePaths = {
        (projectRoot / "testFiles").resolve(),
        (projectRoot / "ransomwareDemo" / "demo_files").resolve(),
        (getDataDirectory() / "monitoring").resolve(),
    }
    validator = PathValidator(allowedBasePaths)

    for pathValue in monitoring["paths"]:
        try:
            validator.validate(str(pathValue))
        except PathValidationError as error:
            raise ConfigurationError(f"Invalid monitoring path '{pathValue}': {error}") from error

    # 6. Model Path Validation
    if "model" in configuration and "path" in configuration["model"]:
        modelPath = configuration["model"]["path"]
        if modelPath:
            try:
                modelPathResolved = Path(modelPath)
                if not modelPathResolved.is_absolute():
                    modelPathResolved = projectRoot / modelPathResolved
                if modelPathResolved.exists() and not modelPathResolved.is_file():
                    raise ConfigurationError(f"Model path is not a file: {modelPathResolved}")
            except Exception as error:
                raise ConfigurationError(f"Invalid model path: {modelPath} - {error}") from error

    logger.debug("Configuration validation passed")


def resolveMonitoringPath(pathValue: str) -> Path:
    """
    Resolve and validate a single monitoring path with security checks.

    Args:
        pathValue: Path string (relative or absolute)

    Returns:
        Validated canonical Path object

    Raises:
        ConfigurationError: If path fails validation
    """
    projectRoot = getProjectRoot()
    allowedBasePaths = {
        (projectRoot / "testFiles").resolve(),
        (projectRoot / "ransomwareDemo" / "demo_files").resolve(),
        (getDataDirectory() / "monitoring").resolve(),
    }

    validator = PathValidator(allowedBasePaths)
    try:
        resolvedPath = validator.validate(pathValue)
        logger.debug(f"Monitoring path resolved successfully: {resolvedPath}")
        return resolvedPath
    except PathValidationError as error:
        logger.warning(f"Path validation failed: {error}")
        raise ConfigurationError(f"Invalid monitoring path: {error}") from error


def resolveMonitoringPaths(paths: list[str] | None = None) -> list[Path]:
    """
    Resolve and validate multiple monitoring paths with security checks.

    Args:
        paths: List of path strings. If None, loads from configuration.

    Returns:
        List of validated canonical Path objects

    Raises:
        ConfigurationError: If any path fails validation or list is empty
    """
    if paths is None:
        config = loadConfiguration()
        paths = config.get("monitoring", {}).get("paths", [])

    if not paths:
        raise ConfigurationError("No monitoring paths provided")

    projectRoot = getProjectRoot()
    allowedBasePaths = {
        (projectRoot / "testFiles").resolve(),
        (projectRoot / "ransomwareDemo" / "demo_files").resolve(),
        (getDataDirectory() / "monitoring").resolve(),
    }

    validator = PathValidator(allowedBasePaths)
    try:
        resolvedPaths = validator.validateBatch([str(p) for p in paths])
        logger.debug(f"Resolved {len(resolvedPaths)} monitoring paths successfully")
        return resolvedPaths
    except PathValidationError as error:
        logger.warning(f"Batch path validation failed: {error}")
        raise ConfigurationError(f"Invalid monitoring paths: {error}") from error


def initializeDirectories() -> list[Path]:
    """Create and return required application data directories."""
    dataDirectory = getDataDirectory()
    directories = [
        dataDirectory / "database",
        dataDirectory / "logs",
        dataDirectory / "models",
        dataDirectory / "quarantine",
        dataDirectory / "backups",
        dataDirectory / "monitoring",
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    return directories


def performSystemPreflightCheck(
    configuration: Optional[dict[str, Any]] = None,
    minFreeDiskBytes: int = 50 * 1024 * 1024,  # 50 MB
) -> dict[str, Any]:
    """
    Execute deep preflight validation across configuration, storage, disk space, and permissions.

    Args:
        configuration: Optional configuration dictionary (loads defaultConfig if None)
        minFreeDiskBytes: Minimum free disk space required in bytes

    Returns:
        Dictionary containing preflight check status, check details, and actionable recommendations.

    Raises:
        ConfigurationError: If any critical preflight check fails.
    """
    if configuration is None:
        configuration = loadConfiguration()
    else:
        validateConfiguration(configuration)

    errors: list[str] = []
    warnings: list[str] = []
    checks: dict[str, dict[str, Any]] = {}

    # 1. Storage Directories & Permissions Check
    dataDir = getDataDirectory()
    try:
        createdDirs = initializeDirectories()
        # Verify write permission on data directory
        testFile = dataDir / ".preflight_write_test"
        testFile.write_text("ok", encoding="utf-8")
        testFile.unlink()
        checks["storagePermissions"] = {
            "passed": True,
            "dataDirectory": str(dataDir),
            "initializedDirs": [str(d) for d in createdDirs],
        }
    except Exception as error:
        err = f"Data directory write permission check failed: {error}"
        errors.append(err)
        checks["storagePermissions"] = {"passed": False, "error": str(error)}

    # 2. Disk Space Check
    try:
        total, used, free = shutil.disk_usage(dataDir)
        freeMb = round(free / (1024 * 1024), 2)
        minMb = round(minFreeDiskBytes / (1024 * 1024), 2)

        if free < minFreeDiskBytes:
            err = f"Insufficient disk space on {dataDir}: {freeMb}MB available, minimum required is {minMb}MB"
            errors.append(err)
            checks["diskSpace"] = {"passed": False, "freeMb": freeMb, "requiredMb": minMb}
        else:
            checks["diskSpace"] = {"passed": True, "freeMb": freeMb, "requiredMb": minMb}
    except Exception as error:
        warnings.append(f"Unable to verify disk space: {error}")
        checks["diskSpace"] = {"passed": True, "warning": str(error)}

    # 3. Monitored Paths Accessibility Check
    monitoringPaths = configuration.get("monitoring", {}).get("paths", [])
    validatedPaths = []
    for pathStr in monitoringPaths:
        try:
            resolved = resolveMonitoringPath(str(pathStr))
            if not resolved.exists():
                errors.append(f"Monitored path does not exist: {pathStr}")
            else:
                validatedPaths.append(str(resolved))
        except Exception as error:
            errors.append(f"Monitored path '{pathStr}' failed validation: {error}")

    checks["monitoringPaths"] = {
        "passed": len(validatedPaths) == len(monitoringPaths),
        "validatedPaths": validatedPaths,
    }

    # 4. Model Artifact Check (if configured)
    modelConfig = configuration.get("model", {})
    modelPathStr = modelConfig.get("path")
    if modelPathStr:
        modelPath = Path(modelPathStr)
        if not modelPath.is_absolute():
            modelPath = getProjectRoot() / modelPath

        if not modelPath.exists():
            warnings.append(f"Configured model artifact not found at {modelPath} (will require initial training)")
            checks["modelArtifact"] = {"passed": False, "warning": "model_not_found", "path": str(modelPath)}
        else:
            checks["modelArtifact"] = {"passed": True, "path": str(modelPath)}
    else:
        checks["modelArtifact"] = {"passed": True, "path": None}

    status = "HEALTHY" if not errors and not warnings else ("DEGRADED" if not errors else "ERROR")

    result = {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
    }

    if errors:
        raise ConfigurationError(f"System preflight checks failed: {'; '.join(errors)}")

    return result
