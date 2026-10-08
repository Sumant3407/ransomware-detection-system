"""Configuration package with hot-reloading and schema validation."""

from app.config.configuration import (
    ConfigurationError,
    getDataDirectory,
    getProjectRoot,
    initializeDirectories,
    loadConfiguration,
    resolveMonitoringPath,
    resolveMonitoringPaths,
    validateConfiguration,
)
from app.config.configWatcher import (
    BackgroundHotReloader,
    ConfigWatcher,
    ReloadResult,
)

__all__ = [
    "ConfigurationError",
    "getDataDirectory",
    "getProjectRoot",
    "initializeDirectories",
    "loadConfiguration",
    "resolveMonitoringPath",
    "resolveMonitoringPaths",
    "validateConfiguration",
    "ConfigWatcher",
    "BackgroundHotReloader",
    "ReloadResult",
]
