$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

& "$ProjectRoot\.venv\Scripts\python.exe" "$ProjectRoot\scripts\postgres_ctl.py" status
& "$ProjectRoot\.venv\Scripts\python.exe" "$ProjectRoot\manage.py" check

