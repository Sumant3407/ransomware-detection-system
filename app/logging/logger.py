"""Structured JSON logging infrastructure for the application."""

import json
import logging
import logging.handlers
import os
import sys
import time
import traceback
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Generator, Optional

# Context variables for request and session tracing across async/sync tasks
_currentSessionId: ContextVar[Optional[str]] = ContextVar("sessionId", default=None)
_currentRequestId: ContextVar[Optional[str]] = ContextVar("requestId", default=None)


def setSessionId(sessionId: Optional[Any]) -> None:
    """Set the active session ID for log context."""
    _currentSessionId.set(str(sessionId) if sessionId is not None else None)


def getSessionId() -> Optional[str]:
    """Get the active session ID from log context."""
    return _currentSessionId.get()


def setRequestId(requestId: Optional[str]) -> None:
    """Set the active request/trace ID for log context."""
    _currentRequestId.set(requestId)


def getRequestId() -> Optional[str]:
    """Get the active request/trace ID from log context."""
    return _currentRequestId.get()


class ContextFilter(logging.Filter):
    """Logging filter that injects contextual metadata into log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Contextual tracing
        if not hasattr(record, "sessionId") or record.sessionId is None:
            record.sessionId = getSessionId()
        if not hasattr(record, "requestId") or record.requestId is None:
            record.requestId = getRequestId()
        if not hasattr(record, "event"):
            record.event = "application"
        if not hasattr(record, "context"):
            record.context = None
        if not hasattr(record, "durationMs"):
            record.durationMs = None
        return True


class JsonFormatter(logging.Formatter):
    """
    Formatter that outputs structured JSON log lines.

    Standard schema:
    - timestamp: ISO 8601 UTC with timezone
    - severity: Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - component: Logger name / module
    - event: Event category slug
    - message: Log message
    - sessionId: Active session ID (if available)
    - requestId: Active request ID (if available)
    - durationMs: Operation duration in milliseconds (if available)
    - context: Arbitrary structured metadata dictionary
    - exception: Formatted traceback (if exception present)
    - processId: OS process ID
    - threadName: Thread name
    """

    def format(self, record: logging.LogRecord) -> str:
        # Timestamp in ISO 8601 UTC
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()

        logData: dict[str, Any] = {
            "timestamp": timestamp,
            "severity": record.levelname,
            "component": record.name,
            "event": getattr(record, "event", "application"),
            "message": record.getMessage(),
        }

        # Contextual tracing identifiers
        sessionId = getattr(record, "sessionId", None) or getSessionId()
        if sessionId is not None:
            logData["sessionId"] = sessionId

        requestId = getattr(record, "requestId", None) or getRequestId()
        if requestId is not None:
            logData["requestId"] = requestId

        # Operation timing
        durationMs = getattr(record, "durationMs", None)
        if durationMs is not None:
            logData["durationMs"] = round(float(durationMs), 2)

        # Structured context dictionary
        context = getattr(record, "context", None)
        if context is not None:
            if isinstance(context, dict):
                logData["context"] = context
            else:
                logData["context"] = str(context)

        # Exception information
        if record.exc_info:
            logData["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else "UnknownException",
                "message": str(record.exc_info[1]) if record.exc_info[1] else "",
                "traceback": self.formatException(record.exc_info),
            }
        elif record.exc_text:
            logData["exception"] = {
                "type": "Exception",
                "message": record.exc_text.splitlines()[-1] if record.exc_text else "",
                "traceback": record.exc_text,
            }

        # Process and thread metadata
        logData["processId"] = record.process
        logData["threadName"] = record.threadName

        return json.dumps(logData, default=str)


def logSecurityEvent(
    logger: logging.Logger,
    action: str,
    target: str,
    status: str,
    details: Optional[dict[str, Any]] = None,
    level: int = logging.INFO,
) -> None:
    """
    Emit a structured security audit log entry.

    Args:
        logger: Logger instance to emit through
        action: Security action (e.g. 'path_validation', 'model_load', 'quarantine')
        target: Target resource or path
        status: Outcome ('allowed', 'blocked', 'success', 'failed')
        details: Optional additional metadata dictionary
        level: Log level (defaults to INFO, or WARNING for blocked/failed)
    """
    if status in ("blocked", "failed", "denied") and level == logging.INFO:
        level = logging.WARNING

    context = {
        "action": action,
        "target": target,
        "status": status,
    }
    if details:
        context.update(details)

    logger.log(
        level,
        f"Security audit: {action} on '{target}' -> {status}",
        extra={"event": "security_audit", "context": context},
    )


@contextmanager
def PerformanceTimer(
    logger: logging.Logger,
    operationName: str,
    event: str = "performance_metric",
    level: int = logging.DEBUG,
    extraContext: Optional[dict[str, Any]] = None,
) -> Generator[dict[str, Any], None, None]:
    """
    Context manager to measure and log operation duration.

    Usage:
        with PerformanceTimer(logger, "model_prediction", extraContext={"model": "v1"}):
            predict()
    """
    startTime = time.perf_counter()
    metrics: dict[str, Any] = {}
    try:
        yield metrics
        status = "success"
    except Exception as error:
        status = f"error: {type(error).__name__}"
        raise
    finally:
        elapsedMs = (time.perf_counter() - startTime) * 1000.0
        context: dict[str, Any] = {
            "operation": operationName,
            "durationMs": round(elapsedMs, 2),
            "status": status,
        }
        if extraContext:
            context.update(extraContext)
        if metrics:
            context.update(metrics)

        logger.log(
            level,
            f"Operation '{operationName}' completed in {elapsedMs:.2f}ms [{status}]",
            extra={"event": event, "durationMs": elapsedMs, "context": context},
        )


def logExecutionTime(
    logger: logging.Logger,
    operationName: Optional[str] = None,
    event: str = "performance_metric",
    level: int = logging.DEBUG,
) -> Callable:
    """
    Decorator to measure and log function execution time.

    Usage:
        @logExecutionTime(logger, "database_query")
        def query(): ...
    """
    def decorator(func: Callable) -> Callable:
        opName = operationName or func.__name__

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with PerformanceTimer(logger, opName, event=event, level=level):
                return func(*args, **kwargs)

        return wrapper

    return decorator


def createLogger(
    logDirectory: Path,
    levelName: str = "INFO",
    retentionDays: int = 30,
    enableConsole: bool = False,
) -> logging.Logger:
    """
    Initialize comprehensive structured logging for the application.

    Configures:
    - Root / app logging hierarchy with structured JSON formatter
    - Timed rotating file handler (daily rotation with configurable retention)
    - Dedicated audit log file for security events
    - Context filter for request/session tracing
    - Optional console logging for CLI/development

    Args:
        logDirectory: Path to directory for log files
        levelName: Minimum log level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        retentionDays: Number of days to retain rotated log files
        enableConsole: Whether to attach a console stream handler

    Returns:
        The configured 'ransomwareDetector' logger instance
    """
    logDirectory = Path(logDirectory).resolve()
    logDirectory.mkdir(parents=True, exist_ok=True)

    numericLevel = getattr(logging, levelName.upper(), logging.INFO)

    # Base application logger & root logger
    appLogger = logging.getLogger("ransomwareDetector")
    rootLogger = logging.getLogger("app")

    appLogPath = (logDirectory / "application.log").resolve()

    # If handlers already configured for this exact log file, update level and return
    existingFileHandlers = [
        h for h in appLogger.handlers
        if isinstance(h, logging.FileHandler) and Path(getattr(h, "baseFilename", "")).resolve() == appLogPath
    ]
    if existingFileHandlers:
        appLogger.setLevel(numericLevel)
        rootLogger.setLevel(numericLevel)
        for h in appLogger.handlers:
            h.setLevel(numericLevel)
        return appLogger

    # Otherwise clean up existing handlers before configuring new target
    closeLogging()

    appLogger.setLevel(numericLevel)
    rootLogger.setLevel(numericLevel)

    formatter = JsonFormatter()
    contextFilter = ContextFilter()

    # 1. Main Application Log (Daily Rotating File Handler)
    appLogPath = logDirectory / "application.log"
    fileHandler = logging.handlers.TimedRotatingFileHandler(
        filename=str(appLogPath),
        when="midnight",
        interval=1,
        backupCount=max(1, retentionDays),
        encoding="utf-8",
        delay=False,
    )
    fileHandler.setFormatter(formatter)
    fileHandler.addFilter(contextFilter)
    fileHandler.setLevel(numericLevel)

    appLogger.addHandler(fileHandler)
    rootLogger.addHandler(fileHandler)

    # 2. Dedicated Security Audit Log Handler
    auditLogPath = logDirectory / "audit.log"
    auditHandler = logging.handlers.TimedRotatingFileHandler(
        filename=str(auditLogPath),
        when="midnight",
        interval=1,
        backupCount=max(1, retentionDays),
        encoding="utf-8",
        delay=False,
    )
    auditHandler.setFormatter(formatter)
    auditHandler.addFilter(contextFilter)

    # Filter to only capture security audit events in audit.log
    class SecurityAuditFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return getattr(record, "event", "") == "security_audit"

    auditHandler.addFilter(SecurityAuditFilter())
    auditHandler.setLevel(logging.INFO)

    appLogger.addHandler(auditHandler)
    rootLogger.addHandler(auditHandler)

    # 3. Optional Console Handler
    if enableConsole:
        consoleHandler = logging.StreamHandler(sys.stdout)
        consoleHandler.setFormatter(formatter)
        consoleHandler.addFilter(contextFilter)
        consoleHandler.setLevel(numericLevel)
        appLogger.addHandler(consoleHandler)
        rootLogger.addHandler(consoleHandler)

    # Don't propagate to python default root to avoid duplicate stdout printing
    appLogger.propagate = False
    rootLogger.propagate = False

    appLogger.info(
        f"Logging initialized: level={levelName}, retention={retentionDays}d, dir={logDirectory}",
        extra={"event": "lifecycle", "context": {"logDirectory": str(logDirectory), "level": levelName}},
    )

    return appLogger


def closeLogging() -> None:
    """
    Flush and close all handlers attached to the application loggers.

    Idempotent and safe to call on shutdown.
    """
    for loggerName in ("ransomwareDetector", "app", ""):
        logger = logging.getLogger(loggerName)
        handlers = list(logger.handlers)
        for handler in handlers:
            try:
                handler.flush()
                handler.close()
                logger.removeHandler(handler)
            except Exception:
                pass
    logging.shutdown()
