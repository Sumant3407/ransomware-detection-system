# Ransomware Detection System - CMD-Only Version

## Overview

This is the command-line only version of the Ransomware Detection System. All GUI components have been removed, and the system now operates entirely through terminal commands and an interactive menu interface.

---

## What Changed

### Removed Components
- ✗ PySide6 GUI (app/ui/mainWindow.py)
- ✗ Qt-dependent worker (app/runtime/worker.py)
- ✗ PySide6 dependency from requirements.txt
- ✗ --gui command-line flag

### New Components
- ✓ Interactive menu system (app/ui/interactive.py)
- ✓ Live terminal display (app/ui/console.py)
- ✓ Generic worker without Qt dependencies (app/runtime/genericWorker.py)
- ✓ Enhanced CLI with multiple operation modes

### Fixed Bugs
1. **Resource Management**: Added context manager support (`__enter__`/`__exit__`) to DetectionController and WindowsFileEventSource
2. **Entropy Calculation**: Added logging for file read errors, skip large files and special file types
3. **Error Handling**: Improved error messages and graceful degradation
4. **Memory Leaks**: Proper cleanup of file handles and database connections

---

## Installation

### 1. Prerequisites
- Windows 10 or Windows 11 (recommended)
- Python 3.11 or newer
- PowerShell

Linux and macOS are supported for headless monitoring only.

### 2. Install Dependencies

```powershell
# Open PowerShell in the project directory
Set-Location "C:\path\to\ransomware-detection-system"

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r projectConfig\requirements.txt
```

### 3. Initialize the System

```powershell
# Initialize application directories and database
python -m app.main --status
```

---

## Usage

### Interactive Menu Mode (Recommended)

Launch the interactive menu interface:

```powershell
python -m app.main --interactive
```

**Menu Options:**
1. **Start Monitoring** - Begin real-time file monitoring with live display
2. **Stop Monitoring** - Stop active monitoring session
3. **View Status** - Show detailed system status
4. **Scan Now** - Perform one-time scan
5. **View Detection History** - Display recent detections
6. **Configuration** - Modify system settings
7. **Model Information** - View ML model details
8. **Exit** - Quit application

### Command-Line Arguments

```powershell
# Show version
python -m app.main --version

# Show detailed status
python -m app.main --status

# Perform one-time scan
python -m app.main --scan

# View detection history
python -m app.main --history

# Start live monitoring (unlimited, press Ctrl+C to stop)
python -m app.main --monitor

# Run bounded monitoring session (10 samples)
python -m app.main --monitor --samples 10 --interval 1

# Open configuration interface
python -m app.main --config
```

---

## Live Monitoring Display

When you start monitoring, you'll see a real-time updating display:

```
═══════════════════════════════════════════════════════════════
        RANSOMWARE DETECTION SYSTEM - LIVE MONITORING
═══════════════════════════════════════════════════════════════

● PROTECTED  |  2026-10-05 14:25:49

STATUS OVERVIEW
────────────────────────────────────────────────────────────────
  Threat Level:     LOW
  Risk Score:       0.0000
  Files Changed:    0
  Detections:       0
  Uptime:           5m 23s

RECENT ACTIVITY
────────────────────────────────────────────────────────────────
  No recent file activity

SYSTEM INFORMATION
────────────────────────────────────────────────────────────────
  Monitoring Path:  C:\Users\...\testFiles
  Model Status:     Active

Press Ctrl+C to stop monitoring
```

The display refreshes 5 times per second and uses color coding:
- **GREEN**: Low threat, normal operation
- **YELLOW**: Medium threat, suspicious activity
- **RED**: High/Critical threat, ransomware-like behavior

---

## Configuration

### Interactive Configuration

Use the configuration menu:

```powershell
python -m app.main --interactive
# Select option 6 (Configuration)
```

You can modify:
- Monitoring path
- Monitoring interval (1-60 seconds)
- Detection sensitivity (conservative/balanced/aggressive)
- Active ML model

### Manual Configuration

Edit `data/settings.json` or use the default `app/config/defaultConfig.json`:

```json
{
  "monitoring": {
    "enabled": true,
    "paths": ["testFiles"],
    "intervalSeconds": 1,
    "sensitivity": "balanced",
    "alertCooldownSeconds": 60
  },
  "model": {
    "path": "data/trainingRun/ransomwareModel.joblib",
    "version": "ransomwareModel"
  },
  "notifications": {
    "enabled": true
  },
  "response": {
    "mode": "alertOnly"
  }
}
```

---

## Model Training

The system can operate without a trained model (using rule-based detection only), but for best results, train a model:

### 1. Generate Test Data

```powershell
python scripts\generateTestData.py --outputDirectory testFiles --files 100
```

### 2. Collect Behavior Data

```powershell
python -m scripts.legacy.dataCollector
# Perform benign file operations or run simulator
# Press Ctrl+C to stop
```

### 3. Train Model

```powershell
python -m trainingModel.training.ransomwareLearner `
  --datasetPath data/ransomwareBehaviorDataset.csv `
  --modelPath data/models/mymodel.joblib
```

### 4. Activate Model

Use the interactive menu (option 6 → option 4) or update configuration manually.

---

## Detection History

View detections through:

### Interactive Mode
```powershell
python -m app.main --interactive
# Select option 5
```

### Command Line
```powershell
python -m app.main --history
```

### Export to CSV

Detection data is stored in SQLite database at `data/database/detector.sqlite3`. Query directly:

```powershell
sqlite3 data/database/detector.sqlite3 "SELECT * FROM detections"
```

---

## Troubleshooting

### "No valid model found"
- This is normal if you haven't trained a model yet
- The system will use rule-based detection
- To train a model, see "Model Training" section

### "Monitoring path must remain inside an approved directory"
- The system restricts monitoring to safe directories
- Approved: `testFiles/`, `ransomwareDemo/demo_files/`, `data/monitoring/`, or any user directory
- Set an absolute path to your home directory to monitor personal files

### "ReadDirectoryChangesW requires Windows"
- Native Windows file monitoring is only available on Windows
- Linux/macOS automatically fall back to polling-based monitoring
- This is expected and doesn't affect functionality

### Live display not refreshing
- Ensure terminal supports ANSI escape codes
- Use Windows Terminal or PowerShell 7+ for best experience
- Try bounded monitoring instead: `--monitor --samples 10`

### High CPU usage
- Increase monitoring interval: `--interval 2`
- Reduce number of files being monitored
- Check entropy calculation on large files (logged in debug mode)

---

## Performance Tips

1. **Monitoring Interval**: Default is 1 second. Increase to 2-5 seconds for lower CPU usage
2. **File Limits**: The system caps rolling event history at 5000 events to prevent memory issues
3. **Entropy Sampling**: Only last 32 modified files are sampled for entropy
4. **Database**: Uses SQLite with WAL mode for better concurrency

---

## Safety Features

- **No Destructive Actions**: The system only logs and alerts, never modifies or deletes files
- **Path Restrictions**: Monitoring is restricted to approved safe directories
- **Alert-Only Mode**: Only response mode is `alertOnly` (no automatic quarantine or process termination)
- **Safe Testing**: Includes safe file simulator that never encrypts or executes programs

---

## Architecture

```
app/
├── config/          Configuration loading and validation
├── detection/       Risk scoring and ML prediction
├── domain/          Core schemas and data structures
├── features/        Feature extraction and windowing
├── logging/         Logging infrastructure
├── models/          Model registry and validation
├── monitoring/      File event sources (Windows native & polling)
├── runtime/         Controller and worker threads
├── security/        Path privacy and validation
├── storage/         SQLite database management
└── ui/              Console display and interactive menu

trainingModel/
├── collection/      Behavior data collection
├── training/        Model training pipeline
└── unlearning/      Exact retraining unlearning

scripts/             Test data generation and legacy tools
tests/               Unit and integration tests
data/                Database, logs, models, and datasets
```

---

## Key Improvements in CMD Version

1. **Cross-Platform**: Works on Windows, Linux, and macOS (without GUI dependencies)
2. **Lightweight**: Removed ~15MB PySide6 dependency
3. **Scriptable**: All functions accessible via command-line arguments
4. **Live Display**: Real-time terminal updates with color coding
5. **Better Resource Management**: Fixed memory leaks and handle cleanup
6. **Enhanced Error Handling**: More informative error messages
7. **Improved Security**: Added file type filtering and size limits for entropy calculation

---

## Testing

Run the test suite:

```powershell
# Compile project
python -m compileall app trainingModel scripts tests

# Run all tests
python -m unittest discover -s tests -p "test*.py"

# Run specific test
python -m unittest tests.testController
```

---

## Known Limitations

1. **Process Attribution**: Does not track which process modified files
2. **Network Monitoring**: Network metrics are collected but not deeply analyzed
3. **Real Ransomware**: System is not tested against actual ransomware (by design)
4. **fileReadCount**: Feature is defined but always 0 (requires kernel-level monitoring)

---

## Security Considerations

- This is an **educational and research project**
- **Not production-ready** for critical infrastructure protection
- Should be combined with other security measures (antivirus, backups, firewalls)
- Designed for **detection**, not prevention or remediation
- See `ANALYSIS_REPORT.md` for detailed security review

---

## Support & Documentation

- **Full Documentation**: See `docs/` directory
- **Architecture**: `docs/ARCHITECTURE.md`
- **Dataset Info**: `docs/DATASET.md`
- **Security Review**: `docs/SECURITY.md`
- **Code Analysis**: `ANALYSIS_REPORT.md`
- **Original README**: `README.md`

---

## License

See LICENSE file in the project root.

---

## Version History

### v2.0.0 - CMD-Only Release (2026-10-05)
- Removed PySide6 GUI
- Added interactive terminal menu
- Added live monitoring display
- Fixed resource management bugs
- Improved error handling
- Enhanced entropy calculation safety
- Updated documentation

### v1.0.0 - Original GUI Version
- PySide6 desktop application
- Qt-based monitoring
- Training GUI
- Full feature set

---

## Quick Start Example

```powershell
# 1. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 2. Create test files
python scripts\generateTestData.py --outputDirectory testFiles --files 50

# 3. Run a quick scan
python -m app.main --scan

# 4. Start interactive monitoring
python -m app.main --interactive
# Select option 1 (Start Monitoring)
# Watch the live display
# Press Ctrl+C to return to menu
# Select option 8 to exit

# 5. View what was detected
python -m app.main --history
```

---

## Questions?

Review the analysis report for detailed information about the system architecture, identified issues, and implemented fixes: `ANALYSIS_REPORT.md`
