#!/usr/bin/env python
"""
Single-command launcher for SecurePay Lab (`python app.py`).
Automatically uses `.venv` if available, starts the isolated PostgreSQL 17 cluster,
applies migrations, bootstraps lab identities/beneficiaries, and starts the web server.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _ensure_venv() -> None:
    """Re-execute with the project's `.venv` Python interpreter if not already running inside it."""
    if os.name == "nt":
        venv_python = BASE_DIR / ".venv" / "Scripts" / "python.exe"
    else:
        venv_python = BASE_DIR / ".venv" / "bin" / "python"

    if not venv_python.exists():
        return

    try:
        current_exe = Path(sys.executable).resolve()
        target_exe = venv_python.resolve()
    except OSError:
        return

    if current_exe != target_exe and Path(sys.prefix).resolve() != (BASE_DIR / ".venv").resolve():
        result = subprocess.run([str(target_exe), str(Path(__file__).resolve()), *sys.argv[1:]])
        raise SystemExit(result.returncode)


def _prepare_environment() -> None:
    """Start PostgreSQL 17, run migrations, and ensure demo data is bootstrapped."""
    from scripts.postgres_ctl import start_cluster

    start_cluster()

    import django
    from django.core.management import call_command

    django.setup()

    print("[app.py] Checking and applying database migrations...")
    call_command("migrate", interactive=False, verbosity=1)

    reset_requested = "--reset" in sys.argv
    from apps.accounts.models import EmployeeIdentity

    if reset_requested or not EmployeeIdentity.objects.exists():
        print("[app.py] Bootstrapping lab identities and beneficiaries...")
        call_command("bootstrap_lab", reset=reset_requested)
    else:
        print("[app.py] Lab identities already present (pass --reset to wipe and re-seed).")

    print("\n" + "=" * 68)
    print("  SecurePay Lab is starting at: http://127.0.0.1:8000")
    print("  Demo accounts (password: 123456):")
    print("    - vanphu             (REQUESTER)")
    print("    - dacqui             (DIRECTOR)")
    print("    - doanphuc           (CONTROLLER)")
    print("    - ngocchau           (SECURITY_ADMIN)")
    print("    - minh               (REQUESTER 2)")
    print("    - dacqui_lookalike   (UNPRIVILEGED)")
    print("=" * 68 + "\n")


def main() -> None:
    _ensure_venv()

    os.chdir(BASE_DIR)
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))

    env_file = BASE_DIR / ".env"
    if env_file.exists():
        from dotenv import load_dotenv

        load_dotenv(env_file)

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

    # Forward custom args to runserver (strip our custom --reset flag)
    extra_args = [arg for arg in sys.argv[1:] if arg != "--reset"]
    has_addrport = any(not arg.startswith("-") for arg in extra_args)
    if not has_addrport:
        extra_args.insert(0, "127.0.0.1:8000")

    # Only run setup once in the main process (skip in Django autoreloader child process)
    if os.environ.get("RUN_MAIN") != "true":
        _prepare_environment()

    from django.core.management import execute_from_command_line

    execute_from_command_line([sys.argv[0], "runserver", *extra_args])


if __name__ == "__main__":
    main()

