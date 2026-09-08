param(
    [string]$installationDirectory = (Join-Path $HOME "RansomwareDetection")
)

$errorActionPreference = "Stop"

if (Test-Path $installationDirectory) {
    Write-Host "The application directory is: $installationDirectory"
    Write-Host "User data in the data directory will be retained."
    Get-ChildItem -Path $installationDirectory -Force |
        Where-Object { $_.Name -ne "data" } |
        Remove-Item -Recurse -Force
    Write-Host "Application files removed."
}
else {
    Write-Host "Application is not installed at $installationDirectory."
}
