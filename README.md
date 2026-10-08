# Ransomware Detection System — Behavioral ML & Forensic Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Hardened](https://img.shields.io/badge/security-AES--256--GCM-brightgreen.svg)](docs/SECURITY.md)

An enterprise-grade, offline behavioral ransomware detection, prevention, and forensic investigation system powered by Machine Learning. The system monitors protected directories in real time, correlates mass file operations with process lineage, calculates threat risk scores via random forest classifiers, and captures immutable forensic evidence snapshots for security operations centers (SOC).

The application features both a **Modern Desktop GUI SOC Dashboard** and an **Interactive Terminal Command Center**, with cross-platform support, zero external telemetry, and offline ML inference.

---

## 🌟 Key Highlights

- **🖥️ Triple Operating Interfaces:**
  - **Modern Desktop GUI SOC Dashboard:** Sleek, dark-themed Tkinter/TTK interface with live streaming activity feeds, forensic ancestry trees, subsystem health gauges, model retraining runners, and folder manager (`python -m app.main --gui`).
  - **Zion CRT Terminal Desktop Station:** High-fidelity raw WebGL + Canvas 2D phosphor green CRT terminal interface with Zion mainframe boot animation, curvature, bloom, scanline shaders, and hardware acceleration (`npm start` / `npm run electron:preview`).
  - **Interactive Terminal Console:** Full-featured ANSI terminal UI with live progress gauges, historical inspection, and fast keyboard workflows (`python -m app.main --interactive`).
  - **Headless Daemon Mode:** Scriptable background daemon with configurable sampling intervals, event limits, and JSON stdout piping.
- **🛡️ Real-Time Native Windows API & Multi-Path Monitoring:**
  - High-frequency asynchronous directory watching via `ReadDirectoryChangesW` with overlapped I/O and graceful polling fallback for network shares or Linux/macOS hosts.
  - Multi-path concurrent watching across arbitrary folders (e.g., Documents, Downloads, Desktop, shared project directories).
- **🔍 Deep Process Attribution & Forensic Snapshots:**
  - Real-time resolution of executing Process IDs (`PID`), Process Names, Parent Process IDs (`PPID`), and full process ancestry trees (`PID -> PPID -> Grandparent`).
  - Automatic immutable forensic snapshot capture on alert triggers (SHA-256 hashes, affected path hashes, user context, and system telemetry).
- **🔒 AES-256-GCM Model Encryption & Integrity Validation:**
  - Machine-bound key derivation (PBKDF2-HMAC-SHA256) for scikit-learn model artifacts at rest.
  - Anti-tampering signature checks, dataset poisoning guards, and preflight inference smoke tests.
- **⚡ Hot-Reloading & Live Model Swapping:**
  - Dynamic zero-downtime configuration hot-reload and atomic model pointer swapping without terminating active monitoring threads.
  - Automatic rollback on schema validation failure.
- **🗄️ Robust SQLite Storage & Maintenance:**
  - Thread-safe RLock connection pooling in WAL mode.
  - Built-in online hot backup manager, SHA-256 integrity verification, automated event pruning, and WAL checkpoints.

---

## 🏗️ System Architecture

```text
┌───────────────────────────────────────────────────────────────────────────────┐
│                           OPERATING INTERFACES                                │
│   ┌───────────────────────────────┐       ┌───────────────────────────────┐   │
│   │   Desktop SOC GUI Dashboard   │       │   Interactive CLI / Daemon    │   │
│   │   (app/ui/mainWindow.py)      │       │   (app/ui/interactive.py)     │   │
│   └──────────────┬────────────────┘       └──────────────┬────────────────┘   │
└──────────────────┼───────────────────────────────────────┼────────────────────┘
                   ▼                                       ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                      RUNTIME DETECTION CONTROLLER                             │
│                  (app/runtime/controller.py & worker.py)                     │
├──────────────────────────────────────┬────────────────────────────────────────┤
│   MultiPathEventCollector            │   Risk & Policy Evaluation Engine      │
│   - Windows ReadDirectoryChangesW    │   - 16-Dimensional Feature Windowing   │
│   - Polling Fallback Watchers        │   - Encrypted Random Forest Predictor  │
│   - Process Attribution (PID/PPID)   │   - Token Bucket Alert Rate Limiter    │
├──────────────────────────────────────┼────────────────────────────────────────┤
│   Forensic Evidence Collector        │   Operations, Health & Hot-Reload      │
│   - Forensic Snapshots & Ancestry    │   - Subsystem Health Engine (JSON)     │
│   - SHA-256 Content & Path Hashing   │   - Zero-Downtime Config/Model Reload  │
│   - WAL Optimization & Pruning       │   - Online Hot Backup & Recovery       │
└──────────────────────────────────────┴────────────────────────────────────────┘
```

---

## 📋 System Requirements

- **Operating System:**
  - **Windows 10 / Windows 11** (Recommended for full `ReadDirectoryChangesW` and native process attribution)
  - **Linux / macOS** (Supported via polling-based fallback engine)
- **Python:** Python 3.11 or newer (Python 3.12 / 3.14 fully tested)
- **Dependencies:** `psutil`, `pandas`, `scikit-learn`, `joblib`, `cryptography`, `pytest`, `pytest-cov`
- **Network:** 100% Offline. Zero internet connection required after dependency installation.

---

## 🚀 Quick Installation

### 1. Clone & Set Up Virtual Environment

```powershell
# Navigate to repository directory
Set-Location "C:\path\to\ransomware-detection-system"

# Create and activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

```powershell
pip install -r projectConfig\requirements.txt
```

### 3. Verify Setup

```powershell
# Run subsystem health diagnostic
python -m app.main --health
```

---

## 🖥️ Launching the Application

### 1. Desktop Graphical SOC Dashboard (Recommended)

Launch the modern dark-themed desktop dashboard:

```powershell
python -m app.main --gui
# or
python -m app.main -g
```

#### Dashboard Features:
1. **Live Activity & Streaming Telemetry:** Real-time event counter, color-coded threat gauge (LOW / ELEVATED / CRITICAL), and rolling file activity log.
2. **Forensic Lineage Browser:** Inspect captured incident snapshots, view full process execution chains (`PID -> PPID -> Grandparent`), and export structured JSON reports.
3. **Diagnostics & Subsystem Health:** Subsystem status matrix (Model, Database, Monitoring Paths, Storage, Logging), host CPU/RAM telemetry, and on-demand self-tests.
4. **ML Model Management & Retraining:** Inspect model encryption status, test and swap candidate models, and launch closed-loop model retraining with 5-fold cross-validation.
5. **Folder & Database Settings:** Manage protected directories (Add/Browse/Remove), configure alert rate-limit cooldowns, create database backups, and run WAL optimization.

---

### 2. Zion CRT Terminal Desktop Station (Integrated ThreeUI WebGL SOC)

Launch the hardware-accelerated CRT defense station desktop application with live Python backend integration:

```powershell
# Launch via Python CLI flag
python -m app.main --ui
# or shorthand
python -m app.main -u

# Or launch directly with npm
npm run electron:preview
# or in development mode
npm start
```

#### Integrated Desktop Features:
- **WebGL Fragment Shader & 2D Canvas:** Authentic retro CRT curvature, bloom, scanline rasterization, phosphor green typography, and customizable shader parameters.
- **Interactive CRT Defense Terminal:** Execute real-time defense commands directly from the CRT shell (`scan`, `status`, `health`, `metrics`, `demo benign`, `demo attack`, `retrain`, `forensics`, `help`).
- **Live SOC Telemetry Stream:** Real-time event log with Windows `ReadDirectoryChangesW` process attribution (`PID`, `PPID`, action, path hash).
- **One-Click Simulation Lab:** Generate benign office files, simulate normal work, and run sandboxed ransomware attack bursts with instant visual telemetry.
- **Forensic Lineage Tree:** Interactive `PID -> PPID -> Grandparent` execution chain visualizer with SHA-256 evidence inspection and JSON exporter.
- **Diagnostics & Observability:** Live health indicators for all 5 subsystems (Model, DB, Paths, Storage, Logging) and host CPU/RAM metrics.
- **ML Retraining Studio & Folder Manager:** Automated 5-fold cross-validation retraining, AES-256-GCM verification, and directory picker dialog.

---

### 3. Interactive Terminal Console

Launch the terminal-based interactive control center:

```powershell
python -m app.main --interactive
# or
python -m app.main -i
```

Provides a live ANSI dashboard with real-time risk gauges, session uptime counters, and quick keyboard navigation.

---

### 3. Headless Background Monitoring

Run the detection engine as a lightweight background daemon:

```powershell
# Continuous monitoring (stop with Ctrl+C)
python -m app.main --monitor

# Bounded monitoring (e.g. 50 samples with 1.0s interval)
python -m app.main --monitor --samples 50 --interval 1.0

# Headless monitoring with dynamic hot-reloading enabled
python -m app.main --monitor --hot-reload
```

---

## 🛠️ Complete CLI Command Reference

| Command Flag | Description |
| :--- | :--- |
| `python -m app.main --ui` / `-u` | Launch the Integrated Electron Desktop CRT Terminal Station |
| `python -m app.main --gui` / `-g` | Launch the Desktop Graphical SOC Dashboard |
| `python -m app.main --interactive` / `-i` | Launch the interactive terminal console |
| `python -m app.main --status` | Display detailed protection status and active paths |
| `python -m app.main --health` | Run comprehensive subsystem health check |
| `python -m app.main --health --json` | Output subsystem health report in structured JSON format |
| `python -m app.main --metrics` | Display real-time process CPU, RAM, and detection counters |
| `python -m app.main --scan` | Perform an immediate one-time threat scan across all paths |
| `python -m app.main --history` | Display tabular history of the 50 most recent detections |
| `python -m app.main --forensics` | List captured forensic evidence snapshots |
| `python -m app.main --snapshot-id <ID>` | Display detailed evidence and process ancestry for a snapshot |
| `python -m app.main --snapshot-id <ID> --json` | Export forensic snapshot report as structured JSON |
| `python -m app.main --validate-config <file>` | Validate a candidate JSON configuration against the schema |
| `python -m app.main --swap-model <path>` | Test and swap the active ML model with zero downtime |
| `python -m app.main --optimize-db` | Run SQLite WAL checkpoint, integrity check, and vacuum |
| `python -m app.main --prune-days <N>` | Delete historical file events and logs older than N days |
| `python -m app.main --demo` | Launch interactive demonstration & lab workload wizard |
| `python -m app.main --demo benign --demo-count 25` | Generate 25 benign office documents (Word, Excel, PDF, CSV, JSON, Python, JPG) |
| `python -m app.main --demo normal --demo-steps 10` | Simulate normal low-velocity user office editing activity |
| `python -m app.main --demo attack --demo-count 20` | Simulate safe sandboxed ransomware mass renames & high-entropy write bursts |
| `python -m app.main --demo clean` | Clean and reset the demo sandbox directory |

---

## 🧪 Safe Testing & Lab Simulation

The repository includes safe, non-destructive tools to simulate benign and ransomware-like behavioral patterns without modifying files outside designated disposable test directories:

### 1. Generate Harmless Test Files

```powershell
python scripts\generateTestData.py --outputDirectory testFiles --files 100
```
Generates 100 non-sensitive dummy documents, text files, and images inside `testFiles/`.

### 2. Run Safe Activity Simulator

```powershell
python scripts\legacy\labActivitySimulator.py testFiles --init --count 25
```
Simulates benign batch edits, modifications, and rapid renames inside `testFiles/` to verify real-time event capture.

---

## 🧠 Machine Learning & Retraining Pipeline

The detection pipeline computes 16 behavioral features across rolling 60-second time windows (velocity, rename ratios, extension entropy, write bursts, directory depth alterations) and feeds them to an encrypted Random Forest classifier.

### Train a Candidate Model
```powershell
python -m trainingModel.training.ransomwareLearner `
  --datasetPath data/ransomwareBehaviorDataset.csv `
  --modelPath data/models/candidate.joblib
```

### Run Retraining with Feedback
```powershell
python -m app.models.retrainingPipeline `
  --evaluate-only
```

---

## 🧪 Running the Test Suite

The system includes a comprehensive test suite of 312+ automated tests covering security boundaries, concurrency, ML pipelines, forensics, and GUI components:

```powershell
# Run full test suite with pytest
pytest -v

# Run test suite with code coverage
pytest --cov=app --cov-report=term-missing
```

---

## 📁 Repository Structure

```text
ransomware-detection-system/
├── app/
│   ├── config/              # Configuration validation, path resolver & hot-reloader
│   ├── detection/           # Predictor, risk engine & token bucket alert policy
│   ├── domain/              # Schemas, feature definitions & data contracts
│   ├── features/            # Rolling window entropy & behavioral feature extraction
│   ├── forensics/           # Forensic evidence snapshots & process tree tracer
│   ├── logging/             # Structured JSON logger & security audit loggers
│   ├── models/              # Model registry, retraining pipeline & validation
│   ├── monitoring/          # Multi-path collector, Windows API & process attributor
│   ├── operations/          # Subsystem health checker & online backup manager
│   ├── runtime/             # Detection controller, monitoring worker & workers
│   ├── security/            # Path validator, privacy hasher & AES-256 model encryption
│   ├── storage/             # SQLite connection pool, schema migrations & WAL optimizer
│   └── ui/                  # Modern Desktop GUI Dashboard (mainWindow.py) & Console UI
├── data/
│   ├── backups/             # Online SQLite snapshots and SHA-256 manifests
│   ├── database/            # detector.sqlite3 (WAL mode)
│   ├── datasets/            # Labeled behavioral datasets
│   ├── logs/                # application.log & audit.log (JSON format)
│   └── models/              # Encrypted .joblib model artifacts & metadata
├── projectConfig/           # requirements.txt & packaging configurations
├── scripts/                 # Safe test data generators & simulation utilities
├── tests/                   # 312+ Unit, integration, security & GUI tests
├── QUICKSTART.md            # Step-by-step walkthrough & quickstart guide
└── README.md                # Main documentation
```

---

## 🛡️ Security Boundaries & Disclaimer

This software is an educational and defensive security tool developed for endpoint defense, threat detection research, and SOC analysis:
- The detection engine operates in **read-only, non-destructive mode** and does not terminate processes or modify user files without explicit manual operator intervention.
- Do not run live malicious payloads. Use the included safe lab simulation scripts (`scripts/generateTestData.py` and `scripts/legacy/labActivitySimulator.py`).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
