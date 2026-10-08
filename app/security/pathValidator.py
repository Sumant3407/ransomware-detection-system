"""Centralized path validation for secure monitoring directory access with deep security hardening."""

import logging
import os
import re
import urllib.parse
from pathlib import Path
from typing import Set

logger = logging.getLogger(__name__)

# Windows DOS reserved device names
DOS_DEVICE_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


class PathValidationError(ValueError):
    """Raised when a path fails validation checks."""


class PathValidator:
    """Validates monitoring paths against whitelist and blocks dangerous directories and attack vectors."""

    # System directories that should never be monitored (including 8.3 variations)
    BLOCKED_SYSTEM_PATHS = {
        r"C:\Windows",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
        r"C:\System Volume Information",
        r"C:\$Recycle.Bin",
        r"C:\Recovery",
        r"C:\Boot",
        r"C:\EFI",
        r"C:\PROGRA~1",
        r"C:\PROGRA~2",
        r"C:\WINDOW~1",
    }

    # Device & Network path prefixes
    BLOCKED_NETWORK_PATTERNS = {"\\\\", "smb://", "nfs://", "//"}
    BLOCKED_DEVICE_PREFIXES = {"\\\\.\\", "\\\\?\\", "\\??\\", "//./", "//?/", "\\\\.", "\\\\?"}

    def __init__(self, allowedBasePaths: Set[Path] | None = None):
        """
        Initialize path validator with allowed base directories.

        Args:
            allowedBasePaths: Set of Path objects representing approved monitoring directories.
                            If None, only home directory and default locations allowed.
        """
        self.allowedBasePaths = allowedBasePaths or set()
        logger.debug(f"PathValidator initialized with {len(self.allowedBasePaths)} allowed base paths")

    def _sanitizeAndUnquote(self, pathStr: str) -> str:
        """
        Unquote URL encoding and detect null byte / malicious character injections.

        Args:
            pathStr: Raw input path string

        Returns:
            Sanitized path string

        Raises:
            PathValidationError: If null bytes or invalid control characters detected
        """
        # Check for null bytes before and after unquoting
        if "\x00" in pathStr or "%00" in pathStr.lower():
            logger.warning(
                f"Null byte injection detected in path: {repr(pathStr)}",
                extra={"event": "security_audit", "context": {"status": "blocked", "reason": "null_byte_injection"}},
            )
            raise PathValidationError("Null byte injection detected in path")

        # Recursively unquote percent-encoded sequences (up to 3 passes to prevent double encoding)
        current = pathStr
        for _ in range(3):
            unquoted = urllib.parse.unquote(current)
            if unquoted == current:
                break
            current = unquoted
            if "\x00" in current:
                raise PathValidationError("Null byte injection detected after unquoting")

        return current

    def validate(self, path: str) -> Path:
        """
        Validate a path string and return canonicalized Path object.

        Args:
            path: Path string to validate (relative or absolute)

        Returns:
            Canonical Path object if valid

        Raises:
            PathValidationError: If path fails any validation check
        """
        if not path or not str(path).strip():
            raise PathValidationError("Path cannot be empty")

        rawPathStr = str(path).strip()
        sanitizedPath = self._sanitizeAndUnquote(rawPathStr)

        # Check for DOS Device Prefixes (\\.\, \\?\, \??\) first
        for devPrefix in self.BLOCKED_DEVICE_PREFIXES:
            if sanitizedPath.startswith(devPrefix) or rawPathStr.startswith(devPrefix):
                logger.warning(
                    f"Device namespace path blocked: {sanitizedPath}",
                    extra={"event": "security_audit", "context": {"action": "path_validation", "target": sanitizedPath, "status": "blocked", "reason": "device_namespace"}},
                )
                raise PathValidationError(f"Device namespace paths not allowed: {sanitizedPath}")

        # Check against network paths (UNC or smb:// / nfs:// protocols)
        if self._isNetworkPath(rawPathStr, sanitizedPath):
            logger.warning(
                f"Network path detected: {rawPathStr}",
                extra={"event": "security_audit", "context": {"action": "path_validation", "target": rawPathStr, "status": "blocked", "reason": "network_path"}},
            )
            raise PathValidationError(f"Network path monitoring not allowed: {rawPathStr}")

        # Check for DOS reserved device names (CON, NUL, AUX, etc.)
        pathParts = re.split(r"[/\\]", sanitizedPath)
        for part in pathParts:
            baseName = part.split(".")[0].upper()
            if baseName in DOS_DEVICE_NAMES:
                logger.warning(
                    f"DOS reserved device name detected: {part}",
                    extra={"event": "security_audit", "context": {"action": "path_validation", "target": sanitizedPath, "status": "blocked", "reason": "dos_device_name"}},
                )
                raise PathValidationError(f"DOS reserved device name not allowed: {part}")

        # Check for NTFS Alternate Data Streams (ADS) (e.g. file.txt:stream or C:\path:stream)
        # Exclude standard Windows drive letter colon (e.g., C:\) and URI protocols
        withoutDriveOrProtocol = re.sub(r"^[a-zA-Z]:", "", sanitizedPath)
        withoutDriveOrProtocol = re.sub(r"^[a-zA-Z]+://", "", withoutDriveOrProtocol)
        if ":" in withoutDriveOrProtocol:
            logger.warning(
                f"NTFS Alternate Data Stream (ADS) detected: {sanitizedPath}",
                extra={"event": "security_audit", "context": {"action": "path_validation", "target": sanitizedPath, "status": "blocked", "reason": "alternate_data_stream"}},
            )
            raise PathValidationError(f"Alternate Data Stream paths not allowed: {sanitizedPath}")

        # Convert to Path object
        try:
            requestedPath = Path(sanitizedPath)
        except (ValueError, TypeError) as error:
            logger.warning(f"Invalid path format: {sanitizedPath} - {error}")
            raise PathValidationError(f"Invalid path format: {sanitizedPath}") from error

        # Resolve to absolute canonical path
        try:
            resolvedPath = requestedPath.resolve()
        except (OSError, RuntimeError) as error:
            logger.warning(f"Cannot resolve path: {sanitizedPath} - {error}")
            raise PathValidationError(f"Cannot resolve path: {sanitizedPath}") from error

        # Check against blocked system paths
        if self._isBlockedSystemPath(resolvedPath):
            logger.warning(
                f"Path is a blocked system directory: {resolvedPath}",
                extra={"event": "security_audit", "context": {"action": "path_validation", "target": str(resolvedPath), "status": "blocked", "reason": "system_directory"}},
            )
            raise PathValidationError(f"System directory monitoring not allowed: {resolvedPath}")

        # Check against network paths
        if self._isNetworkPath(rawPathStr, resolvedPath):
            logger.warning(
                f"Network path detected: {rawPathStr}",
                extra={"event": "security_audit", "context": {"action": "path_validation", "target": rawPathStr, "status": "blocked", "reason": "network_path"}},
            )
            raise PathValidationError(f"Network path monitoring not allowed: {rawPathStr}")

        # Check against whitelist
        if not self._isAllowedPath(resolvedPath):
            logger.warning(
                f"Path not in allowed directories: {resolvedPath}",
                extra={"event": "security_audit", "context": {"action": "path_validation", "target": str(resolvedPath), "status": "blocked", "reason": "not_whitelisted"}},
            )
            raise PathValidationError(
                f"Path must be in an approved monitoring directory: {resolvedPath}"
            )

        # Verify path accessibility
        if not self._isPathAccessible(resolvedPath):
            logger.warning(
                f"Path is not accessible: {resolvedPath}",
                extra={"event": "security_audit", "context": {"action": "path_validation", "target": str(resolvedPath), "status": "blocked", "reason": "not_accessible"}},
            )
            raise PathValidationError(f"Path is not accessible or does not exist: {resolvedPath}")

        logger.debug(
            f"Path validation successful: {resolvedPath}",
            extra={"event": "security_audit", "context": {"action": "path_validation", "target": str(resolvedPath), "status": "allowed"}},
        )
        return resolvedPath

    def _isBlockedSystemPath(self, path: Path) -> bool:
        """Check if path is a blocked system directory or a subdirectory thereof."""
        pathStr = str(path).upper()
        for blocked in self.BLOCKED_SYSTEM_PATHS:
            try:
                blockedStr = str(Path(blocked).resolve()).upper()
            except Exception:
                blockedStr = str(Path(blocked)).upper()

            if pathStr == blockedStr or pathStr.startswith(blockedStr + "\\") or pathStr.startswith(blockedStr + "/"):
                return True
        return False

    def _isNetworkPath(self, originalPath: str, resolvedPath: Path) -> bool:
        """Check if path is a network path."""
        pathStr = str(originalPath).lower()
        resolvedStr = str(resolvedPath).lower()

        # Check for UNC paths (\\server\share or //server/share)
        if pathStr.startswith("\\\\") or pathStr.startswith("//") or resolvedStr.startswith("\\\\"):
            return True

        # Check for network protocol strings
        for pattern in self.BLOCKED_NETWORK_PATTERNS:
            if pattern.lower() in pathStr or pattern.lower() in resolvedStr:
                return True

        return False

    def _isAllowedPath(self, path: Path) -> bool:
        """Check if path is within allowed base directories."""
        # Always allow user home directory
        homeDir = Path.home().resolve()
        if path == homeDir or homeDir in path.parents:
            logger.debug(f"Path is within home directory: {path}")
            return True

        # Check against configured allowed paths
        for allowedPath in self.allowedBasePaths:
            allowedResolved = allowedPath.resolve()
            if path == allowedResolved or allowedResolved in path.parents:
                logger.debug(f"Path is within allowed directory: {path} <- {allowedResolved}")
                return True

        return False

    def _isPathAccessible(self, path: Path) -> bool:
        """Check if path exists and is accessible."""
        try:
            path.stat()
            return True
        except (OSError, PermissionError) as error:
            logger.debug(f"Path access denied: {path} - {error}")
            return False

    def validateBatch(self, paths: list[str]) -> list[Path]:
        """
        Validate multiple paths and return all valid paths.

        Args:
            paths: List of path strings to validate

        Returns:
            List of validated Path objects

        Raises:
            PathValidationError: If any path fails validation (all-or-nothing)
        """
        validatedPaths = []
        for path in paths:
            try:
                validatedPaths.append(self.validate(path))
            except PathValidationError as error:
                logger.error(f"Batch validation failed at path {path}: {error}")
                raise PathValidationError(f"Batch validation failed at path {path}") from error

        logger.info(f"Successfully validated {len(validatedPaths)} paths")
        return validatedPaths
