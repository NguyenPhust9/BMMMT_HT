#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

python manage.py migrate --noinput
python manage.py bootstrap_lab --reset
echo "[setup.sh] Setup completed successfully."

