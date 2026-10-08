# PowerShell automation script for scheduled/automated Ransomware Detection System backups

param (
    [string]$Description = "Automated scheduled backup",
    [int]$Keep = 10,
    [switch]$NoModels,
    [switch]$Json
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Push-Location $ProjectRoot
try {
    Write-Host "[*] Executing Ransomware Detection System Backup..." -ForegroundColor Cyan

    $argsList = @("-m", "scripts.backupCli", "--create", "--description", $Description, "--keep", $Keep)
    if ($NoModels) {
        $argsList += "--no-models"
    }
    if ($Json) {
        $argsList += "--json"
    }

    $pythonExe = "python"
    & $pythonExe $argsList

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Backup operation completed successfully." -ForegroundColor Green
    } else {
        Write-Error "[-] Backup operation failed with exit code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}
