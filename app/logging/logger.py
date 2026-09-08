"""Structured local logging for the application."""

import logging
import json
from pathlib import Path


def createLogger(logDirectory: Path, levelName: str = "INFO") -> logging.Logger:
    logDirectory.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("ransomwareDetector")
    if logger.handlers:
        return logger
    logger.setLevel(getattr(logging, levelName.upper(), logging.INFO))
    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            return json.dumps(
                {
                    "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
                    "severity": record.levelname,
                    "component": record.name,
                    "event": getattr(record, "event", "application"),
                    "message": record.getMessage(),
                }
            )

    formatter = JsonFormatter()
    fileHandler = logging.FileHandler(logDirectory / "application.log", encoding="utf-8")
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)
    return logger
