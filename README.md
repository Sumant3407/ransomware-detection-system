# Ransomware Detection System

An offline-first Windows desktop application for detecting ransomware-like file behavior with machine learning. The application uses safe, non-destructive simulation for development and testing.

## 1. Requirements

- Windows 10 or Windows 11 for the installer and desktop application
- Python 3.11 or newer
- PowerShell
- A disposable directory for test activity

The headless monitoring and test suite can also run on Linux and macOS. Normal detection does not require an internet connection after the dependencies are installed.

## 2. Open the Project

Open PowerShell and change to the project directory:

```powershell
Set-Location "C:\path\to\Ransomware-detection-system-using-machine-learning"
```

Replace the path with the location where this project is stored.

## 3. Install the Project

Run the installer from PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

The installer checks Windows and Python, creates `.venv`, installs the pinned dependencies from `projectConfig\requirements.txt`, creates the application data directories, and validates the installation.

The installer is safe to run more than once.

## 4. Activate the Virtual Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

Confirm that the application is available:

```powershell
python -m app.main --version
python -m app.main --status
```

Expected status output includes:

```text
Protected
Response policy: alertOnly
```

## 5. Launch the Desktop Application

Start the PySide6 dashboard:

```powershell
python -m app.main --gui
```

The current dashboard displays the protection state and threat level. Monitoring can also be run without the graphical interface.

## 6. Generate Safe Test Files

Generate non-sensitive files in the disposable test directory:

```powershell
python scripts\generateTestData.py --outputDirectory testFiles --files 100
```

The generator creates harmless TXT, CSV, JSON, document-like, image-like, and PDF-like files. It never executes programs and never modifies files outside the selected output directory.

## 7. Run the Safe Behavior Simulator

The simulator requires a marker file and operates only in the marked directory:

```powershell
python scripts\legacy\labActivitySimulator.py testFiles --init --count 10
```

The simulator creates, modifies, and renames generated files. It does not encrypt, delete, or access files outside `testFiles`.

## 8. Collect Behavior Data

Start the collector:

```powershell
python -m scripts.legacy.dataCollector
```

Perform benign activity or run the safe simulator in another PowerShell window. Press `Ctrl+C` to stop collection.

The collector writes samples to:

```text
data\ransomwareBehaviorDataset.csv
```

The default collector label is `Benign`. Use only controlled, safe workloads when developing additional labeled data. Do not run real ransomware.

The existing dataset fixture is located at `data\datasets\ransomwareBehaviorDataset.csv`.

## 9. Run Headless Monitoring

Run a bounded monitoring session:

```powershell
python -m app.main --monitor --samples 10 --interval 1
```

The command monitors the configured directory, aggregates file activity, evaluates risk, and stores detection records in:

```text
data\database\detector.sqlite3
```

Runtime responses are log-only or alert-only. The application does not delete files, kill processes, or change network settings.

## 10. Run the Test Suite

Compile the project:

```powershell
python -m compileall app trainingModel scripts tests
```

Run all tests:

```powershell
python -m unittest discover -s tests -p "test*.py"
```

The tests cover configuration safety, SQLite initialization, file events, feature aggregation, risk scoring, model training, model validation, unlearning, controller persistence, and safe test-data generation.

## 11. Train a Model

The training dataset must contain the shared feature columns and at least two labels. The current legacy dataset may contain only benign samples, so inspect it before training:

```powershell
python -c "import pandas as pd; data = pd.read_csv('data/ransomwareBehaviorDataset.csv'); print(data.shape); print(data['label'].value_counts(dropna=False))"
```

Train a model after sufficient labeled data has been collected:

```powershell
python -m trainingModel.training.ransomwareLearner --datasetPath data/ransomwareBehaviorDataset.csv --modelPath data/models/candidate.joblib
```

The trainer produces a model artifact and `metadata.json`. Metrics are calculated from held-out data and are never fabricated.

## 12. Use the Training GUI

Launch the training workspace:

```powershell
python -m trainingModel.training.trainingGui
```

The training GUI uses the same visual style as the protection GUI and provides:

- Dataset inspection with row, column, and label counts
- Dataset and model path selection
- Safe bounded data collection
- `Benign` and `RANSOMWARE_LIKE` labels
- Background model training
- Training status and measured metadata output

Use `Inspect dataset` to verify the selected CSV before training. Use `Run data collection` only with a disposable directory. The collection action starts the existing collector program and does not execute real ransomware.

## 13. Validate and Activate a Model

Model activation requires a valid artifact and matching metadata checksum. Use the model registry from Python code after training:

```powershell
python -c "from pathlib import Path; from app.config.configuration import getDataDirectory; from app.models.modelRegistry import ModelRegistry; registry = ModelRegistry(getDataDirectory() / 'models', getDataDirectory() / 'database' / 'detector.sqlite3'); print(registry.activateModel(Path('data/models/candidate.joblib')))"
```

The active model is stored under:

```text
data\models\current\
```

Tampered, incompatible, or incomplete model artifacts are rejected.

## 14. Run Exact-Retraining Unlearning

The baseline unlearning workflow removes a selected label and retrains from the remaining approved data:

```powershell
python -m trainingModel.unlearning.unlearn --datasetPath data/ransomwareBehaviorDataset.csv --forget Ransomware --modelPath data/models/unlearned.joblib
```

The dataset must contain the label supplied to `--forget` and enough remaining data for training. This is a measurable retraining baseline; it does not claim mathematically perfect forgetting.

## 15. Stop and Uninstall

Stop a running collector or monitor with `Ctrl+C`.

To remove application files while preserving the `data` directory:

```powershell
.\deployment\uninstall.ps1
```

Review the retained data before removing it manually.

## 16. Project Folders

```text
app/             Runtime configuration, monitoring, detection, storage, and UI
trainingModel/   Model training and exact-retraining unlearning
scripts/         Safe dataset-generation and compatibility utilities
projectConfig/   Pinned dependencies and packaging metadata
deployment/      Installer compatibility utilities
tests/            Unit and integration tests
data/             Datasets, database, logs, and model artifacts
docs/             Architecture, installation, dataset, and security documentation
testFiles/        Disposable local simulation directory
```

## 17. Safety Limitations

This project does not execute real ransomware. It does not implement encryption, deletion, process termination, network isolation, credential collection, persistence, evasion, or destructive quarantine. Exact process attribution and native Windows event monitoring are separate future hardening tasks.

More detail is available in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DATASET.md](docs/DATASET.md), [docs/SECURITY.md](docs/SECURITY.md), and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).



## Production UI and resource budget

The desktop dashboard uses a minimal black interface and keeps the main screen focused on
protection state, threat level, recent file activity, detections, and the active model.
Settings expose the model, monitoring interval, sensitivity, protected folder, Windows
startup, notifications, and trusted emergency-USB behavior.

Runtime memory is treated as a constrained resource: rolling file-event state is bounded,
entropy sampling is capped, the dashboard no longer walks the entire protected tree just
to refresh counters, and training/unlearning dependencies are loaded only by their
dedicated workflows. The 50 MB target is an engineering target for the background
monitoring process; an exact hard ceiling cannot be guaranteed because Python, Qt, the
OS, and a loaded ML model have unavoidable baseline memory usage.


### Real-time Files Changed
The main dashboard refreshes the Files Changed metric every 250 ms and displays events from the most recent 1 second, so the counter updates while the demo is modifying files rather than waiting for a decision cycle.

### Real-time Files Changed counter
The dashboard refreshes every 200 ms and displays the cumulative number of file events
in the active/latest monitoring session. The monitoring controller commits event batches
immediately, so new modifications become visible without waiting for a ten-cycle commit.
