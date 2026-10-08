# PowerShell automation script for restoring Ransomware Detection System from a backup archive

param (
    [Parameter(Mandatory=$true)]
    [string]$BackupPath,
    [switch]$Force,
    [switch]$Json
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Push-Location $ProjectRoot
try {
    Write-Host "[*] Restoring Ransomware Detection System from $BackupPath..." -ForegroundColor Yellow

    $argsList = @("-m", "scripts.backupCli", "--restore", $BackupPath)
    if ($Force) {
        $argsList += "--force"
    }
    if ($Json) {
        $argsList += "--json"
    }

    $pythonExe = "python"
    & $pythonExe $argsList

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] System restore completed successfully." -ForegroundColor Green
    } else {
        Write-Error "[-] Restore operation failed with exit code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}
