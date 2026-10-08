# Quickstart Guide — Ransomware Detection System

Welcome to the **Ransomware Detection System** Quickstart Guide. This walkthrough will take you from zero to running real-time monitoring, launching the modern Desktop SOC Dashboard, testing safe simulation workloads, and analyzing forensic incident reports.

---

## ⏱️ 60-Second Setup

### 1. Prerequisites
- **Windows 10 / 11** (or Linux/macOS)
- **Python 3.11+** installed and added to PATH
- **PowerShell** or Git Bash

### 2. Setup Virtual Environment & Dependencies

Open PowerShell in the project directory:

```powershell
# 1. Create virtual environment
python -m venv .venv

# 2. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install all required dependencies
pip install --upgrade pip
pip install -r projectConfig\requirements.txt

# 4. Verify installation with a health check
python -m app.main --health
```

Expected output:
```text
================================================================================
  SUBSYSTEM HEALTH CHECK & OBSERVABILITY DIAGNOSTIC
================================================================================
  OVERALL STATUS: HEALTHY

  Model Subsystem:       HEALTHY (Model artifact loaded, AES-256 decrypted)
  Database Subsystem:    HEALTHY (WAL mode enabled, integrity passed)
  Monitoring Paths:      HEALTHY (All monitored folders accessible)
  Storage Subsystem:     HEALTHY (Disk space adequate)
  Logging Subsystem:     HEALTHY (Log files writable)
```

---

## 🖥️ Method 1: Launching the Desktop GUI SOC Dashboard (Recommended)

The modern Desktop GUI provides an intuitive dark-themed security operations dashboard.

```powershell
python -m app.main --gui
# or shorthand
python -m app.main -g
```

```text
┌───────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ Ransomware Behavior Defense Station — Desktop SOC             [—][口][X]   │
├───────────────────────────────────────────────────────────────────────────────┤
│ [ PROTECTION: ACTIVE ]  [ THREAT: LOW ]  [ RISK: 0.0000 ]  [ PATHS: 3 ]       │
├───────────────────────────────────────────────────────────────────────────────┤
│  [Live Activity] [Forensic Lineage] [Diagnostics] [ML Model] [Settings/Paths] │
├───────────────────────────────────────────────────────────────────────────────┤
│  Timestamp         Action       Process          PID    Path Hash   Path ID   │
│  ───────────────────────────────────────────────────────────────────────────  │
│  14:20:11.102      MODIFIED     explorer.exe     4812   e3b0c442    1         │
│  14:20:12.441      CREATED      notepad.exe      9024   f1d2d2f9    1         │
│  14:20:14.882      RENAMED      cmd.exe          3120   8c2a9e10    2         │
├───────────────────────────────────────────────────────────────────────────────┤
│ [▶ Start Live Protection]  [⚡ Quick Scan]  [🔍 Inspect Forensics]  [⚙ Config]│
└───────────────────────────────────────────────────────────────────────────────┘
```

### Dashboard Tabs Overview:
1. **Live Activity & Feed:** Real-time event log with process name attribution, action types (`CREATED`, `MODIFIED`, `DELETED`, `RENAMED`), and path hashes. Click **"Start Live Protection"** to begin continuous monitoring.
2. **Forensic Lineage:** Browse captured incident snapshots and examine full parent-child execution chains (`PID -> PPID -> Grandparent Process`).
3. **Diagnostics & Observability:** Live host CPU, memory, thread counts, open handles, and on-demand subsystem diagnostic tests.
4. **ML Model & Retraining:** Inspect active model AES-256 encryption status, test and swap candidate models, and run automated retraining.
5. **Live Lab & Demo:** Interactive demonstration sandbox with one-click buttons to generate benign documents (Word, Excel, PDF, CSV, JSON, Python, Images), simulate normal office work, and run safe sandboxed ransomware attack simulations with live console logs.
6. **Settings & Paths:** Add or remove monitored folders with the native directory picker, adjust alert policy cooldown sliders, and run database backups or WAL optimization.

---

## 📺 Method 2: Launching the Integrated Zion CRT Terminal Desktop Station (ThreeUI WebGL)

Launch the hardware-accelerated desktop application with live Python backend integration:

```powershell
# Launch via Python CLI
python -m app.main --ui
# or shorthand
python -m app.main -u

# Or launch directly with npm
npm run electron:preview

# Or launch development mode with live hot-reload
npm start
```

This launches a hardware-accelerated, isolated Electron desktop window combining the authentic ThreeUI raw WebGL CRT fragment shader with live SOC operations, interactive terminal command shell, real-time file event streaming, one-click simulation laboratory, and forensic incident lineage trees.

---

## 💻 Method 3: Launching the Interactive Terminal Console

If you prefer working entirely in the terminal:

```powershell
python -m app.main --interactive
# or shorthand
python -m app.main -i
```

You will see an interactive menu:
```text
═══════════════════════════════════════════════════════════════
  RANSOMWARE BEHAVIOR DEFENSE STATION — TERMINAL CONSOLE
═══════════════════════════════════════════════════════════════
  [1] Start Live Monitoring
  [2] Stop Monitoring
  [3] View Status
  [4] Scan Now
  [5] View Detection History
  [6] Configuration
  [7] Live Demo & Lab Simulation
  [8] Model Information
  [9] Exit
```

Select `1` to start live monitoring or `7` to access the demonstration lab.

---

## 🧪 Method 4: Safe Demonstration Workflows & Lab Simulation

You can run automated demonstrations via the **Desktop GUI ("Live Lab & Demo" Tab)** or directly from the **CLI**:

### Option A: Interactive CLI Demo Wizard
```powershell
python -m app.main --demo
```

### Option B: One-Liner Demonstration Commands

#### 1. Generate Benign Normal Documents
```powershell
python -m app.main --demo benign --demo-count 25
```
Generates 25 realistic office documents (`.docx`, `.xlsx`, `.pdf`, `.txt`, `.csv`, `.json`, `.py`, `.jpg`) inside `testFiles/`.

#### 2. Simulate Normal Office User Activity
```powershell
python -m app.main --demo normal --demo-steps 10
```
Simulates normal text edits, note appending, and file reading. Threat level remains **LOW (Green)**.

#### 3. Simulate Sandboxed Ransomware Attack
```powershell
python -m app.main --demo attack --demo-count 20
```
Executes rapid mass renames (`.locked`, `.crypto`, `.enc`) and high-entropy write bursts strictly inside the sandboxed `testFiles/` folder.
*Watch the live detection engine immediately trigger a **CRITICAL (Red)** alert and capture an immutable forensic snapshot!*

#### 4. Clean & Reset Demo Sandbox
```powershell
python -m app.main --demo clean
```
Safely removes generated test files while preserving the sandbox directory for future demos.
- Real-time file modification and rename events captured via Windows `ReadDirectoryChangesW`.
- Process attribution mapping operations to `python.exe` with PID and PPID.
- 16-feature rolling window calculations.
- Evaluation of risk scores and automatic rate-limited alert triggering.

---

## 🔍 Inspecting Forensic Evidence & Process Lineage

When a threat threshold is crossed, an immutable forensic snapshot is recorded.

### List All Forensic Snapshots
```powershell
python -m app.main --forensics
```

### Inspect a Specific Snapshot
```powershell
python -m app.main --snapshot-id 1
```

Example Output:
```text
================================================================================
  FORENSIC EVIDENCE REPORT — SNAPSHOT #1
================================================================================
  Captured At:      2026-10-08 14:22:15 UTC
  Threat Score:     0.9450 (CRITICAL)
  Classification:   Ransomware-like Behavioral Pattern
  Triggering Event: Rapid mass rename across 28 files in 3.2s

  PROCESS LINEAGE:
  └─ [PID: 1044] explorer.exe
     └─ [PID: 4812] cmd.exe
        └─ [PID: 9140] python.exe (EXECUTING WORKLOAD)

  SYSTEM TELEMETRY AT TIME OF EVENT:
  - CPU Utilization: 8.4%
  - Memory Usage:    94.2 MB
  - Active Threads:  6
```

### Export Snapshot to JSON
```powershell
python -m app.main --snapshot-id 1 --json > evidence_snapshot_1.json
```

---

## ⚙️ Configuration & Monitored Directories

Settings are managed via `data/settings.json`. You can edit this file directly or through the Desktop GUI **Settings** tab.

```json
{
  "monitoring": {
    "paths": [
      "testFiles",
      "C:\\Users\\sumant\\Documents"
    ],
    "interval": 1.0
  },
  "detection": {
    "riskThreshold": 0.65,
    "alertCooldown": 45
  },
  "model": {
    "path": "data/models/ransomwareModel.joblib",
    "encrypted": true
  },
  "logging": {
    "level": "INFO",
    "retentionDays": 7
  }
}
```

### Validate Configuration File
```powershell
python -m app.main --validate-config data/settings.json
```

---

## 🔄 Live Model Swapping & Hot-Reloading

Swap active models in production with zero downtime:

```powershell
python -m app.main --swap-model data/models/candidate.joblib
```

The system conducts preflight schema checks and an inference smoke test before atomically updating the memory pointer.

---

## 🗄️ Database Maintenance & Backups

### Run Online Database Optimization
```powershell
python -m app.main --optimize-db
```
Performs a WAL checkpoint, vacuum, and index defragmentation.

### Prune Historical Events
```powershell
python -m app.main --prune-days 30
```
Safely deletes event records older than 30 days while preserving threat detections and forensic snapshots.

---

## 🧪 Running the Verification Test Suite

Verify all 312+ unit, integration, and security tests:

```powershell
pytest -v
```

---

## ❓ Frequently Asked Questions (FAQ)

**Q: Does this software delete files or block applications automatically?**  
**A:** No. By default, the system operates in a safe, non-destructive **alert-only** mode for SOC observation and manual intervention.

**Q: Can I monitor multiple drives or network folders?**  
**A:** Yes. Simply add the folder paths in `data/settings.json` or through the Desktop GUI. Each path runs on an isolated watcher thread.

**Q: Where are logs stored?**  
**A:** Structured JSON logs are stored in `data/logs/application.log` and security audit events in `data/logs/audit.log`.
