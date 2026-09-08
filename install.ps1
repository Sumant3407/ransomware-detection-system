param(
    [string]$pythonCommand = "python",
    [string]$venvDirectory = ".venv"
)

$errorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "This installer targets Windows 10 and Windows 11."
}

$python = Get-Command $pythonCommand -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Python 3.11 or newer was not found. Install Python from python.org and retry."
}

$pythonVersion = & $pythonCommand -c "import sys; print('%s.%s' % (sys.version_info.major, sys.version_info.minor))"
if ([version]$pythonVersion -lt [version]"3.11") {
    throw "Python 3.11 or newer is required. Found $pythonVersion."
}

if (-not (Test-Path $venvDirectory)) {
    & $pythonCommand -m venv $venvDirectory
}

$venvPython = Join-Path $venvDirectory "Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    throw "Virtual environment Python was not created at $venvPython"
}

& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r (Join-Path $PSScriptRoot "projectConfig\requirements.txt")
& $venvPython -m app.main --status

Write-Host "Installation complete."
Write-Host "Activate with .\$venvDirectory\Scripts\Activate.ps1"
Write-Host "Start the foundation with python -m app.main"
