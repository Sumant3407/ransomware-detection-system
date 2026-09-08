# Installation

## Windows 10 and 11

1. Install Python 3.11 or newer from `python.org`.
2. Open PowerShell in the project directory.
3. Run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

The installer is safe to rerun. It creates `.venv`, installs the pinned project dependencies, initializes data directories, and validates the application status command.

Start the application:

```powershell
.\.venv\Scripts\Activate.ps1
python -m app.main --status
python -m app.main --gui
```

The uninstaller removes application files while retaining the `data` directory. Review and remove user data separately when appropriate.

## Development platforms

The headless modules can be tested on Linux and macOS. The installer and native Windows event adapter target Windows. Normal detection does not require internet access after dependencies are installed.
