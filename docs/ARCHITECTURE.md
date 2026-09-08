# Architecture

Ransomware Detection System is an offline-first Windows application for detecting ransomware-like behavior. It never executes ransomware and does not delete files, kill processes, isolate networks, or alter system settings.

## Runtime

- `app/config`: validated external configuration and safe path handling.
- `app/domain`: versioned file-event and feature contracts.
- `app/monitoring`: deterministic polling source, with a native Windows watcher planned behind the same interface.
- `app/features`: bounded rolling feature aggregation.
- `app/detection`: validated model prediction and conservative risk decisions.
- `app/runtime`: headless controller connecting monitoring, features, prediction, risk, and SQLite.
- `app/storage`: SQLite persistence using WAL mode and parameterized statements.
- `app/ui`: PySide6 dashboard shell.
- `app/models`: model integrity validation, registry, and activation.

## Training

Training code lives under `trainingModel`. It shares `app.domain.schemas.featureColumns` with runtime inference. `ransomwareLearner.py` remains a compatibility launcher for the validated trainer.

## Safety boundary

Responses are alert-only or log-only. File contents are never stored by the runtime database. Paths are stored as SHA-256 hashes in file-event records.
