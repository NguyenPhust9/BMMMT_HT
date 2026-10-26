"""
Start isolated PostgreSQL 17 cluster, apply Django migrations, run trusted offline bootstrap,
and verify M2 database schema and seed invariants on real PostgreSQL.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from scripts.postgres_ctl import start_cluster


def main() -> None:
    start_cluster()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()
    from django.core.management import call_command
    from django.db import connection
    from apps.accounts.models import EmployeeIdentity
    from apps.beneficiaries.models import Beneficiary, BeneficiaryVersion
    from apps.common.models import SecurityMutex
    from django_otp.plugins.otp_totp.models import TOTPDevice

    call_command("migrate", interactive=False, verbosity=1)
    call_command("bootstrap_lab", reset=True)

    with connection.cursor() as cur:
        cur.execute("SELECT version();")
        pg_ver = cur.fetchone()[0]

    mutex_ok = SecurityMutex.objects.filter(pk=1).exists()
    users_count = EmployeeIdentity.objects.count()
    devices_count = TOTPDevice.objects.filter(confirmed=True).count()
    ben_count = Beneficiary.objects.count()
    ver_count = BeneficiaryVersion.objects.count()

    print(f"[M2_VERIFY] PostgreSQL Version: {pg_ver}")
    print(f"[M2_VERIFY] SecurityMutex(id=1) exists: {mutex_ok}")
    print(f"[M2_VERIFY] Principals seeded: {users_count}, Confirmed TOTP devices: {devices_count}")
    print(f"[M2_VERIFY] Beneficiaries seeded: {ben_count}, BeneficiaryVersions: {ver_count}")

    assert mutex_ok, "SecurityMutex(id=1) missing!"
    assert users_count == 6, f"Expected 6 principals, got {users_count}"
    assert devices_count == 6, f"Expected 6 confirmed TOTP devices, got {devices_count}"
    assert ben_count == 4, f"Expected 4 beneficiaries, got {ben_count}"


if __name__ == "__main__":
    main()

