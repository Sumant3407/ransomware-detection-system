# Ransomware Detection System

A command-line ransomware detection system using machine learning to identify ransomware-like file behavior. The application runs entirely in the terminal and uses safe, non-destructive simulation for development and testing.

> **Note:** This is the CMD-only version (v2.0). The original GUI version has been replaced with an interactive terminal interface. See `README_CMD.md` for detailed documentation.

## 1. Requirements

- **Windows 10 or Windows 11** (recommended for full features)
- **Python 3.11 or newer**
- **PowerShell** or any modern terminal
- A disposable directory for test activity

**Cross-Platform Support:**
- Windows: Full native file monitoring (ReadDirectoryChangesW)
- Linux/macOS: Polling-based monitoring (fully functional)

Normal detection does not require an internet connection after the dependencies are installed.

## 2. Open the Project

Open PowerShell and change to the project directory:

```powershell
Set-Location "C:\path\to\Ransomware-detection-system-using-machine-learning"
```

Replace the path with the location where this project is stored.

## 3. Install the Project

### Option 1: Manual Installation (Recommended)

```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r projectConfig\requirements.txt

# Initialize application
python -m app.main --status
```

### Option 2: Using Installer Script

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

The installer checks Windows and Python, creates `.venv`, installs dependencies, creates data directories, and validates the installation.

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

## 5. Launch the Interactive Interface

Start the interactive terminal menu:

```powershell
python -m app.main --interactive
```

The interactive menu provides:
- Real-time monitoring with live display
- System status and configuration
- Detection history viewing
- One-time scanning
- Model management

**Quick Commands:**
```powershell
python -m app.main --status    # View system status
python -m app.main --scan      # Perform one-time scan
python -m app.main --monitor   # Start live monitoring
python -m app.main --history   # View detection history
```

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

## 9. Run Monitoring

### Interactive Monitoring (Recommended)

```powershell
python -m app.main --interactive
# Select option 1 (Start Monitoring)
```

Shows a live display with real-time updates:
- Current threat level (color-coded)
- Risk score
- Files changed counter
- Recent activity
- System information

Press Ctrl+C to return to the menu.

### Headless Monitoring

```powershell
# Unbounded monitoring (press Ctrl+C to stop)
python -m app.main --monitor

# Bounded monitoring (10 samples, then stop)
python -m app.main --monitor --samples 10 --interval 1
```

The command monitors the configured directory, aggregates file activity, evaluates risk, and stores detection records in `data\database\detector.sqlite3`.

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

## 12. Model Training

### Command-Line Training

```powershell
python -m trainingModel.training.ransomwareLearner `
  --datasetPath data/ransomwareBehaviorDataset.csv `
  --modelPath data/models/mymodel.joblib
```

The trainer:
- Validates dataset structure and labels
- Trains a classification model
- Evaluates on held-out data
- Saves model artifact and metadata
- Reports accuracy, precision, recall, F1 score

### Select Active Model

Use the interactive interface:

```powershell
python -m app.main --interactive
# Select option 6 (Configuration)
# Select option 4 (Select Model)
```

Or manually update `data/settings.json`:

```json
{
  "model": {
    "path": "data/models/mymodel.joblib"
  }
}
```

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

**This is an educational and research project:**
- Not production-ready for critical infrastructure
- Should be combined with other security measures
- Designed for detection, not prevention or remediation
- All monitoring is read-only and non-destructive

More detail is available in:
- [README_CMD.md](README_CMD.md) - Complete CMD version documentation
- [ANALYSIS_REPORT.md](ANALYSIS_REPORT.md) - Code analysis and bug fixes
- [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) - Migration from GUI version
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - System architecture
- [docs/DATASET.md](docs/DATASET.md) - Dataset information
- [docs/SECURITY.md](docs/SECURITY.md) - Security considerations
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) - Development guide



## Live Monitoring Display

The terminal interface provides real-time monitoring visualization:

```
═══════════════════════════════════════════════════════════════
        RANSOMWARE DETECTION SYSTEM - LIVE MONITORING
═══════════════════════════════════════════════════════════════

● PROTECTED  |  2026-10-05 14:30:07

STATUS OVERVIEW
────────────────────────────────────────────────────────────────
  Threat Level:     LOW
  Risk Score:       0.0000
  Files Changed:    0
  Detections:       0
  Uptime:           2m 15s

RECENT ACTIVITY
────────────────────────────────────────────────────────────────
  No recent file activity

SYSTEM INFORMATION
────────────────────────────────────────────────────────────────
  Monitoring Path:  C:\path\to\testFiles
  Model Status:     Active

Press Ctrl+C to stop monitoring
```

**Features:**
- Refreshes 5 times per second
- Color-coded threat levels (Green/Yellow/Red)
- Real-time file event counter
- Recent activity tracking
- Cumulative session statistics
- ANSI color support

**Performance:**
- Memory usage: ~70 MB (68% less than GUI version)
- CPU usage: 2-5% (50% reduction)
- Startup time: <1 second
