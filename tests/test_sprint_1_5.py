"""Sprint 1.5 - Deep Configuration Validation, Security Penetration Testing, and System Preflight checks."""

import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.config.configuration import (
    ConfigurationError,
    getDataDirectory,
    getProjectRoot,
    loadConfiguration,
    performSystemPreflightCheck,
    resolveMonitoringPath,
    validateConfiguration,
)
from app.logging.logger import closeLogging, createLogger, setSessionId
from app.security.pathPrivacy import getPathIdentifier
from app.security.pathValidator import PathValidator, PathValidationError
from app.storage.connectionPool import ConnectionPool
from app.storage.sqliteStore import closeDatabase, initializeDatabase


@pytest.fixture(autouse=True)
def clean_environment():
    """Ensure clean logging context and closed database for each test."""
    setSessionId(None)
    closeLogging()
    closeDatabase()
    yield
    setSessionId(None)
    closeLogging()
    closeDatabase()


# ============================================================================
# Section 1: Deep Configuration Validation & System Preflight Checks
# ============================================================================

class TestDeepConfigurationValidation:
    """Test deep configuration constraints, threshold bounds, and preflight health checks."""

    def test_valid_configuration_passes_preflight(self):
        """Standard valid configuration completes preflight checks successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_dir = Path(tmpdir) / "monitored"
            monitor_dir.mkdir()

            config = {
                "monitoring": {
                    "paths": [str(monitor_dir)],
                    "sensitivity": "balanced",
                    "alertCooldownSeconds": 60,
                    "intervalSeconds": 2,
                },
                "logging": {"level": "INFO", "retentionDays": 30},
                "notifications": {"enabled": True},
                "startup": {"enabled": True},
                "emergencyUsb": {"enabled": False},
                "response": {"mode": "alertOnly"},
            }

            result = performSystemPreflightCheck(config)
            assert result["status"] in ("HEALTHY", "DEGRADED")
            assert result["checks"]["storagePermissions"]["passed"] is True
            assert result["checks"]["monitoringPaths"]["passed"] is True

    def test_preflight_fails_on_insufficient_disk_space(self):
        """Preflight check raises ConfigurationError when free disk space is below minimum."""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor_dir = Path(tmpdir) / "monitored"
            monitor_dir.mkdir()

            config = {
                "monitoring": {
                    "paths": [str(monitor_dir)],
                    "sensitivity": "balanced",
                    "alertCooldownSeconds": 30,
                    "intervalSeconds": 2,
                },
                "response": {"mode": "alertOnly"},
            }

            # Request impossibly high free disk space requirement (10,000 Terabytes)
            huge_requirement = 10_000 * 1024 * 1024 * 1024 * 1024
            with pytest.raises(ConfigurationError) as exc_info:
                performSystemPreflightCheck(config, minFreeDiskBytes=huge_requirement)
            assert "insufficient disk space" in str(exc_info.value).lower()

    def test_invalid_sensitivity_setting_rejected(self):
        """Invalid monitoring.sensitivity raises ConfigurationError."""
        config = {
            "monitoring": {
                "paths": ["testFiles"],
                "sensitivity": "hyper-paranoid",  # Invalid
                "alertCooldownSeconds": 60,
                "intervalSeconds": 2,
            },
            "response": {"mode": "alertOnly"},
        }
        with pytest.raises(ConfigurationError) as exc_info:
            validateConfiguration(config)
        assert "sensitivity" in str(exc_info.value).lower()

    def test_negative_alert_cooldown_rejected(self):
        """Negative alert cooldown seconds raises ConfigurationError."""
        config = {
            "monitoring": {
                "paths": ["testFiles"],
                "sensitivity": "balanced",
                "alertCooldownSeconds": -10,  # Invalid
                "intervalSeconds": 2,
            },
            "response": {"mode": "alertOnly"},
        }
        with pytest.raises(ConfigurationError) as exc_info:
            validateConfiguration(config)
        assert "alertcooldownseconds" in str(exc_info.value).lower()

    def test_invalid_interval_bounds_rejected(self):
        """Interval seconds outside bounds raises ConfigurationError."""
        config = {
            "monitoring": {
                "paths": ["testFiles"],
                "sensitivity": "balanced",
                "alertCooldownSeconds": 60,
                "intervalSeconds": 120,  # > 60s
            },
            "response": {"mode": "alertOnly"},
        }
        with pytest.raises(ConfigurationError) as exc_info:
            validateConfiguration(config)
        assert "intervalseconds" in str(exc_info.value).lower()

    def test_unsupported_response_mode_rejected(self):
        """Non-alertOnly response modes raise ConfigurationError."""
        config = {
            "monitoring": {
                "paths": ["testFiles"],
                "sensitivity": "balanced",
                "alertCooldownSeconds": 60,
                "intervalSeconds": 2,
            },
            "response": {"mode": "autoKillProcess"},  # Unsupported
        }
        with pytest.raises(ConfigurationError) as exc_info:
            validateConfiguration(config)
        assert "alertonly" in str(exc_info.value).lower()


# ============================================================================
# Section 2: Security Penetration Testing (Path Traversal & Evasion Vectors)
# ============================================================================

class TestSecurityPenetrationAndEvasion:
    """Test PathValidator against diverse adversarial evasion and traversal techniques."""

    def test_null_byte_injection_blocked(self):
        """Null byte injections (\\x00 and %00) are detected and blocked."""
        validator = PathValidator()

        with pytest.raises(PathValidationError) as exc_info:
            validator.validate("testFiles\x00C:\\Windows")
        assert "null byte" in str(exc_info.value).lower()

        with pytest.raises(PathValidationError) as exc_info:
            validator.validate("testFiles%00C:\\Windows")
        assert "null byte" in str(exc_info.value).lower()

    def test_url_encoded_path_traversal_blocked(self):
        """URL percent-encoded traversal attempts (%2e%2e%2f) are decoded and blocked."""
        validator = PathValidator()

        # Decodes to C:\Windows\System32
        with pytest.raises(PathValidationError) as exc_info:
            validator.validate("C:%5cWindows%5cSystem32")
        assert "system directory" in str(exc_info.value).lower()

    def test_dos_device_namespaces_blocked(self):
        """DOS device namespace prefixes (\\\\.\\ and \\\\?\\) are blocked."""
        validator = PathValidator()

        with pytest.raises(PathValidationError) as exc_info:
            validator.validate(r"\\.\C:\Windows")
        assert "device namespace" in str(exc_info.value).lower()

        with pytest.raises(PathValidationError) as exc_info:
            validator.validate(r"\\?\C:\Windows")
        assert "device namespace" in str(exc_info.value).lower()

    def test_dos_reserved_device_names_blocked(self):
        """DOS reserved device names (CON, NUL, AUX, COM1) are blocked."""
        validator = PathValidator()

        for dev_name in ("CON", "NUL", "AUX", "COM1", "PRN"):
            with pytest.raises(PathValidationError) as exc_info:
                validator.validate(f"testFiles/{dev_name}.txt")
            assert "dos reserved" in str(exc_info.value).lower()

    def test_alternate_data_streams_blocked(self):
        """NTFS Alternate Data Stream (ADS) paths (file.txt:stream) are blocked."""
        validator = PathValidator()

        with pytest.raises(PathValidationError) as exc_info:
            validator.validate("testFiles/normal.txt:hidden_payload.exe")
        assert "alternate data stream" in str(exc_info.value).lower()

    def test_8dot3_short_names_system_paths_blocked(self):
        """8.3 short name system directory references (PROGRA~1, WINDOW~1) are blocked."""
        validator = PathValidator()

        with pytest.raises(PathValidationError) as exc_info:
            validator.validate(r"C:\PROGRA~1")
        assert "system directory" in str(exc_info.value).lower()

        with pytest.raises(PathValidationError) as exc_info:
            validator.validate(r"C:\WINDOW~1")
        assert "system directory" in str(exc_info.value).lower()


# ============================================================================
# Section 3: Privacy Preservation & Audit Trail Verification
# ============================================================================

class TestPrivacyPreservationAndAuditTrail:
    """Test path privacy HMAC hashing and log data sanitization."""

    def test_path_identifier_is_deterministic_and_pseudonymous(self):
        """getPathIdentifier generates consistent HMAC hash without exposing cleartext."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "privacy.key"
            sample_path = "C:\\Users\\ConfidentialUser\\SecretDocuments\\file.docx"

            id1 = getPathIdentifier(sample_path, key_path)
            id2 = getPathIdentifier(sample_path, key_path)

            assert id1 == id2
            assert len(id1) == 64  # SHA-256 hex string
            assert "ConfidentialUser" not in id1
            assert "SecretDocuments" not in id1

    def test_different_paths_yield_different_identifiers(self):
        """Different input paths yield distinct cryptographic hashes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "privacy.key"
            id1 = getPathIdentifier("path/one.txt", key_path)
            id2 = getPathIdentifier("path/two.txt", key_path)

            assert id1 != id2


# ============================================================================
# Section 4: Resource Stability & Stress Verification
# ============================================================================

class TestResourceStabilityAndStress:
    """Test connection pool and resources under rapid repeated operations."""

    def test_rapid_connection_pool_acquisition_and_release(self):
        """Connection pool safely handles 200 consecutive rapid acquisitions without leaking."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "stress.sqlite3"
            pool = ConnectionPool(db_path, poolSize=3, timeout=5.0)

            for i in range(200):
                with pool.getConnection() as conn:
                    conn.execute("CREATE TABLE IF NOT EXISTS stress_test (id INT)")
                    conn.execute("INSERT INTO stress_test VALUES (?)", (i,))
                    conn.commit()

            pool.close()

            # Verify all rows written successfully
            with ConnectionPool(db_path, poolSize=1) as check_pool:
                with check_pool.getConnection() as conn:
                    count = conn.execute("SELECT COUNT(*) FROM stress_test").fetchone()[0]
                    assert count == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
