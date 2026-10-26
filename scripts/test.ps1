$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

& "$ProjectRoot\.venv\Scripts\python.exe" "$ProjectRoot\scripts\postgres_ctl.py" start
& "$ProjectRoot\.venv\Scripts\python.exe" "$ProjectRoot\scripts\run_all_tests.py"

