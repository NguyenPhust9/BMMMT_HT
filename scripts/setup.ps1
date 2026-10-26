$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "[setup.ps1] Starting isolated PostgreSQL 17 cluster in private/pgdata..."
& "$ProjectRoot\.venv\Scripts\python.exe" "$ProjectRoot\scripts\postgres_ctl.py" start

Write-Host "[setup.ps1] Applying Django migrations on PostgreSQL..."
& "$ProjectRoot\.venv\Scripts\python.exe" "$ProjectRoot\manage.py" migrate --noinput

Write-Host "[setup.ps1] Running trusted offline bootstrap (bootstrap_lab)..."
& "$ProjectRoot\.venv\Scripts\python.exe" "$ProjectRoot\manage.py" bootstrap_lab --reset

Write-Host "[setup.ps1] Setup completed successfully."

