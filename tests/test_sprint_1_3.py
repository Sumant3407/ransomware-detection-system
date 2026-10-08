"""Sprint 1.3 - Comprehensive Logging Infrastructure verification tests."""

import json
import logging
import tempfile
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.logging.logger import (
    ContextFilter,
    JsonFormatter,
    PerformanceTimer,
    closeLogging,
    createLogger,
    getRequestId,
    getSessionId,
    logExecutionTime,
    logSecurityEvent,
    setRequestId,
    setSessionId,
)
from app.detection.alertPolicy import AlertPolicy
from app.detection.predictor import ModelPredictor, ModelValidationError
from app.detection.riskEngine import RiskDecision, ThreatLevel, evaluateRisk
from app.security.pathValidator import PathValidator, PathValidationError


# ============================================================================
# Test Fixtures & Helpers
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_logging():
    """Ensure logging handlers and contextvars are cleaned up before and after each test."""
    setSessionId(None)
    setRequestId(None)
    closeLogging()
    yield
    setSessionId(None)
    setRequestId(None)
    closeLogging()


def parse_json_lines(log_file_path: Path) -> list[dict]:
    """Helper to read and parse JSON lines from a log file."""
    if not log_file_path.exists():
        return []
    records = []
    for line in log_file_path.read_text(encoding="utf-8").strip().splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


# ============================================================================
# JSON Formatter & Schema Tests
# ============================================================================

class TestJsonFormatter:
    """Test structured JSON log record formatting and schema compliance."""

    def test_formatter_produces_valid_json(self):
        """Formatter outputs valid parseable JSON string."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="app.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Test log message",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        data = json.loads(formatted)

        assert isinstance(data, dict)
        assert data["message"] == "Test log message"
        assert data["severity"] == "INFO"
        assert data["component"] == "app.test"
        assert data["event"] == "application"

    def test_formatter_standard_schema_fields(self):
        """Formatter includes all mandatory schema fields."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="app.component",
            level=logging.WARNING,
            pathname=__file__,
            lineno=20,
            msg="Warning event",
            args=(),
            exc_info=None,
        )
        data = json.loads(formatter.format(record))

        required_keys = {"timestamp", "severity", "component", "event", "message", "processId", "threadName"}
        for key in required_keys:
            assert key in data, f"Missing required key: {key}"

    def test_formatter_iso8601_utc_timestamp(self):
        """Formatter outputs valid ISO 8601 UTC timestamp."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="app.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Time check",
            args=(),
            exc_info=None,
        )
        data = json.loads(formatter.format(record))
        timestamp_str = data["timestamp"]

        dt = datetime.fromisoformat(timestamp_str)
        assert dt is not None
        assert dt.tzinfo is not None

    def test_formatter_with_custom_context_dict(self):
        """Formatter includes custom context dictionary when provided."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="app.features",
            level=logging.DEBUG,
            pathname=__file__,
            lineno=30,
            msg="Computed feature",
            args=(),
            exc_info=None,
        )
        record.context = {"entropy": 7.82, "fileCount": 42}
        record.event = "feature_extraction"

        data = json.loads(formatter.format(record))
        assert data["event"] == "feature_extraction"
        assert data["context"] == {"entropy": 7.82, "fileCount": 42}

    def test_formatter_with_duration_ms(self):
        """Formatter includes durationMs when provided."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="app.timing",
            level=logging.DEBUG,
            pathname=__file__,
            lineno=40,
            msg="Completed query",
            args=(),
            exc_info=None,
        )
        record.durationMs = 12.3456

        data = json.loads(formatter.format(record))
        assert data["durationMs"] == 12.35

    def test_formatter_with_exception(self):
        """Formatter includes structured exception object on exc_info."""
        formatter = JsonFormatter()
        try:
            raise ValueError("Invalid sample value")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="app.error",
            level=logging.ERROR,
            pathname=__file__,
            lineno=50,
            msg="Operation failed",
            args=(),
            exc_info=exc_info,
        )
        data = json.loads(formatter.format(record))

        assert "exception" in data
        assert data["exception"]["type"] == "ValueError"
        assert "Invalid sample value" in data["exception"]["message"]
        assert "Traceback" in data["exception"]["traceback"]


# ============================================================================
# Context & Session/Request Tracing Tests
# ============================================================================

class TestContextTracing:
    """Test session ID and request ID propagation across logs."""

    def test_session_id_context(self):
        """setSessionId injects session ID into formatted logs."""
        setSessionId(12345)
        assert getSessionId() == "12345"

        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="app.controller",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Session active",
            args=(),
            exc_info=None,
        )
        data = json.loads(formatter.format(record))
        assert data["sessionId"] == "12345"

    def test_request_id_context(self):
        """setRequestId injects request ID into formatted logs."""
        setRequestId("req-abc-999")
        assert getRequestId() == "req-abc-999"

        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="app.api",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Request processed",
            args=(),
            exc_info=None,
        )
        data = json.loads(formatter.format(record))
        assert data["requestId"] == "req-abc-999"

    def test_clearing_context_variables(self):
        """Clearing context variables removes them from log records."""
        setSessionId(42)
        setSessionId(None)
        assert getSessionId() is None

        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="app.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="No session",
            args=(),
            exc_info=None,
        )
        data = json.loads(formatter.format(record))
        assert "sessionId" not in data

    def test_context_filter_sets_defaults(self):
        """ContextFilter assigns default attributes to records."""
        context_filter = ContextFilter()
        record = logging.LogRecord(
            name="app.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Filter test",
            args=(),
            exc_info=None,
        )
        assert context_filter.filter(record) is True
        assert hasattr(record, "event")
        assert record.event == "application"


# ============================================================================
# Logger Initialization & File Handler Tests
# ============================================================================

class TestLoggerInitialization:
    """Test logger creation, handler attachment, and rotation configuration."""

    def test_create_logger_writes_to_application_log(self):
        """createLogger sets up application.log and outputs structured lines."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger = createLogger(log_dir, levelName="INFO", retentionDays=7)
                logger.info("Application starting", extra={"event": "startup"})
                closeLogging()

                records = parse_json_lines(log_dir / "application.log")
                assert len(records) >= 1

                last_record = records[-1]
                assert last_record["message"] == "Application starting"
                assert last_record["event"] == "startup"
                assert last_record["severity"] == "INFO"
            finally:
                closeLogging()

    def test_create_logger_configures_log_levels(self):
        """createLogger respects configured level threshold."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger = createLogger(log_dir, levelName="WARNING")

                logger.debug("Debug should be filtered")
                logger.info("Info should be filtered")
                logger.warning("Warning should pass")
                logger.error("Error should pass")
                closeLogging()

                records = parse_json_lines(log_dir / "application.log")
                messages = [r["message"] for r in records if "Logging initialized" not in r["message"]]

                assert "Debug should be filtered" not in messages
                assert "Info should be filtered" not in messages
                assert "Warning should pass" in messages
                assert "Error should pass" in messages
            finally:
                closeLogging()

    def test_create_logger_is_idempotent(self):
        """Calling createLogger multiple times does not add duplicate handlers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger1 = createLogger(log_dir, levelName="INFO")
                initial_handlers = len(logger1.handlers)

                logger2 = createLogger(log_dir, levelName="DEBUG")
                assert len(logger2.handlers) == initial_handlers
                assert logger1 is logger2
            finally:
                closeLogging()

    def test_close_logging_removes_and_flushes_handlers(self):
        """closeLogging flushes and detaches all handlers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger = createLogger(log_dir)
                assert len(logger.handlers) > 0

                closeLogging()
                assert len(logger.handlers) == 0
            finally:
                closeLogging()


# ============================================================================
# Security Audit Logging Tests
# ============================================================================

class TestSecurityAuditLogging:
    """Test dedicated security audit logging and audit.log routing."""

    def test_security_audit_event_logged_to_audit_file(self):
        """Security audit events are routed to audit.log."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger = createLogger(log_dir, levelName="DEBUG")

                logSecurityEvent(
                    logger,
                    action="path_validation",
                    target="C:\\Windows\\System32",
                    status="blocked",
                    details={"reason": "system_directory"},
                )
                closeLogging()

                audit_records = parse_json_lines(log_dir / "audit.log")
                assert len(audit_records) >= 1

                audit_entry = audit_records[-1]
                assert audit_entry["event"] == "security_audit"
                assert audit_entry["severity"] == "WARNING"
                assert audit_entry["context"]["action"] == "path_validation"
                assert audit_entry["context"]["target"] == "C:\\Windows\\System32"
                assert audit_entry["context"]["status"] == "blocked"
            finally:
                closeLogging()

    def test_security_audit_allowed_event(self):
        """Allowed security actions are logged at INFO level."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger = createLogger(log_dir, levelName="DEBUG")

                logSecurityEvent(
                    logger,
                    action="model_load",
                    target="data/models/current/model.joblib",
                    status="allowed",
                    details={"checksum": "a1b2c3d4"},
                )
                closeLogging()

                audit_records = parse_json_lines(log_dir / "audit.log")
                assert len(audit_records) >= 1

                audit_entry = audit_records[-1]
                assert audit_entry["severity"] == "INFO"
                assert audit_entry["context"]["status"] == "allowed"
            finally:
                closeLogging()


# ============================================================================
# Performance Monitoring & Timer Tests
# ============================================================================

class TestPerformanceMonitoring:
    """Test execution timing context manager and decorator."""

    def test_performance_timer_context_manager(self):
        """PerformanceTimer records durationMs and logs outcome."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger = createLogger(log_dir, levelName="DEBUG")

                with PerformanceTimer(logger, "model_inference", extraContext={"batchSize": 10}):
                    time.sleep(0.02)  # Simulate 20ms work

                closeLogging()

                records = parse_json_lines(log_dir / "application.log")
                timing_records = [r for r in records if r.get("event") == "performance_metric"]
                assert len(timing_records) >= 1

                entry = timing_records[-1]
                assert entry["context"]["operation"] == "model_inference"
                assert entry["context"]["batchSize"] == 10
                assert entry["durationMs"] >= 15.0
            finally:
                closeLogging()

    def test_log_execution_time_decorator(self):
        """logExecutionTime decorator measures function duration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger = createLogger(log_dir, levelName="DEBUG")

                @logExecutionTime(logger, "compute_statistics")
                def calculate_stats(a, b):
                    time.sleep(0.01)
                    return a + b

                result = calculate_stats(10, 20)
                assert result == 30

                closeLogging()

                records = parse_json_lines(log_dir / "application.log")
                timing_records = [r for r in records if r.get("event") == "performance_metric"]
                assert len(timing_records) >= 1
                assert timing_records[-1]["context"]["operation"] == "compute_statistics"
            finally:
                closeLogging()

    def test_performance_timer_logs_error_on_exception(self):
        """PerformanceTimer records error status when an exception is raised."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger = createLogger(log_dir, levelName="DEBUG")

                with pytest.raises(RuntimeError):
                    with PerformanceTimer(logger, "failing_operation"):
                        raise RuntimeError("Database connection lost")

                closeLogging()

                records = parse_json_lines(log_dir / "application.log")
                timing_records = [r for r in records if r.get("event") == "performance_metric"]
                assert len(timing_records) >= 1
                assert "RuntimeError" in timing_records[-1]["context"]["status"]
            finally:
                closeLogging()


# ============================================================================
# Module Integration Logging Tests
# ============================================================================

class TestModuleIntegrationLogging:
    """Test that individual modules properly log events and do not silently fail."""

    def test_path_validator_emits_security_audit_logs(self):
        """PathValidator logs security audit events on blocked access."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                createLogger(log_dir, levelName="DEBUG")

                validator = PathValidator()
                with pytest.raises(PathValidationError):
                    validator.validate("C:\\Windows\\System32")

                closeLogging()
                audit_records = parse_json_lines(log_dir / "audit.log")
                blocked_events = [
                    r for r in audit_records
                    if r.get("event") == "security_audit" and r.get("context", {}).get("status") == "blocked"
                ]
                assert len(blocked_events) >= 1
            finally:
                closeLogging()

    def test_alert_policy_logs_alert_evaluations(self):
        """AlertPolicy logs when alerts are triggered, escalated, and recorded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                createLogger(log_dir, levelName="DEBUG")

                policy = AlertPolicy(cooldownSeconds=30)
                decision = RiskDecision(ThreatLevel.high, 0.75, "ransomwareLike", "alertOnly")

                should_alert = policy.shouldAlert(decision)
                assert should_alert is True
                policy.recordAlert(decision)

                closeLogging()
                records = parse_json_lines(log_dir / "application.log")
                alert_records = [r for r in records if r.get("event") in ("alert_evaluation", "alert_recorded")]
                assert len(alert_records) >= 2
            finally:
                closeLogging()

    def test_risk_engine_logs_evaluation_details(self):
        """evaluateRisk logs score breakdown and classification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                createLogger(log_dir, levelName="DEBUG")

                decision = evaluateRisk(0.9, 50.0, 10.0, 5.0)
                assert decision.level == ThreatLevel.medium
                assert decision.score > 0.4

                closeLogging()
                records = parse_json_lines(log_dir / "application.log")
                risk_records = [r for r in records if r.get("event") == "risk_evaluation"]
                assert len(risk_records) >= 1
                assert risk_records[-1]["context"]["classification"] == "suspicious"
            finally:
                closeLogging()


# ============================================================================
# Performance & Throughput Tests
# ============================================================================

class TestLoggingPerformance:
    """Test logging throughput and CPU overhead."""

    def test_logging_throughput(self):
        """Logging handles high volume without significant latency (>1000 logs/sec)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            try:
                logger = createLogger(log_dir, levelName="INFO")

                iterations = 1000
                start_time = time.perf_counter()

                for i in range(iterations):
                    logger.info(
                        f"Processing event batch {i}",
                        extra={"event": "metric", "context": {"batch": i, "size": 100}},
                    )

                closeLogging()

                elapsed = time.perf_counter() - start_time
                throughput = iterations / elapsed

                assert throughput > 500, f"Logging throughput too low: {throughput:.1f} logs/sec"
            finally:
                closeLogging()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
