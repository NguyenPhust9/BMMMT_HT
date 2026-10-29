"""
Shared test helpers for T-01..T-40 on real PostgreSQL.
Provides fresh TOTP generation without exposing any public bypass endpoint,
CSRF-enforced HTTP client helpers, and real-time test evidence recording.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone
import json
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.management import call_command
from django.test import Client
from django.utils import timezone
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice

from apps.accounts.models import EmployeeIdentity
from apps.beneficiaries.models import Beneficiary, BeneficiaryVersion
from apps.common.models import SecurityMutex

EVIDENCE_DIR = Path(settings.BASE_DIR) / "evidence"
EVIDENCE_LOGS_DIR = EVIDENCE_DIR / "logs"

DEMO_USERNAME_ALIASES = {
    "lan": "vanphu",
    "nam": "dacqui",
    "huong": "doanphuc",
    "an": "ngocchau",
}


def seed_standard_lab() -> dict[str, Any]:
    """
    Reset and seed the standard lab dataset via the trusted `bootstrap_lab` command.
    Returns a dictionary of principals and beneficiaries.
    """
    SecurityMutex.objects.get_or_create(pk=1)
    call_command("bootstrap_lab", reset=True, verbosity=0)
    creds_file = Path(settings.BASE_DIR) / "private" / "demo_credentials.json"
    creds = json.loads(creds_file.read_text(encoding="utf-8"))["principals"]

    users = {u.username: u for u in EmployeeIdentity.objects.all()}
    # Preserve the logical keys used by the historical security test suite while
    # the real demo login names remain the new Vietnamese usernames.
    for old_name, new_name in DEMO_USERNAME_ALIASES.items():
        creds[old_name] = creds[new_name]
        users[old_name] = users[new_name]
    bens = {b.code: b for b in Beneficiary.objects.select_related("active_version").all()}
    return {
        "creds": creds,
        "users": users,
        "bens": bens,
        "b1": bens["BEN-001"],
        "b1_ver": bens["BEN-001"].active_version,
        "b2": bens["BEN-002"],
        "b2_ver": bens["BEN-002"].active_version,
        "b3_pending": bens["BEN-003"],
        "b3_pending_ver": BeneficiaryVersion.objects.filter(beneficiary=bens["BEN-003"]).first(),
        "b4_revoked": bens["BEN-004"],
        "b4_revoked_ver": BeneficiaryVersion.objects.filter(beneficiary=bens["BEN-004"]).first(),
    }


class StepClock:
    """
    Monotonic test clock advancing in 35-second steps whenever a fresh TOTP timestep is needed,
    preventing false TOTP replay collisions between login and subsequent actions in automated tests.
    """

    def __init__(self, start: datetime | None = None) -> None:
        self.current = start or (timezone.now() + timedelta(seconds=35))

    def advance(self, seconds: int = 35) -> datetime:
        self.current = self.current + timedelta(seconds=seconds)
        return self.current

    def now(self) -> datetime:
        return self.current


def totp_at(user: EmployeeIdentity, when: datetime) -> str:
    """
    Generate the 6-digit TOTP code for `user`'s confirmed TOTPDevice at timestamp `when`.
    Never writes the OTP or seed to any evidence file.
    """
    device = TOTPDevice.objects.filter(user=user, confirmed=True).order_by("id").first()
    assert device is not None, f"No confirmed TOTPDevice for {user.username}"
    totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
    totp.time = int(when.timestamp())
    return str(totp.token()).zfill(device.digits)


def next_fresh_totp(user: EmployeeIdentity) -> str:
    """
    Ensure `device.last_t` is strictly older than current wall-clock timestep so the current
    wall-clock TOTP code can be used in HTTP Client requests without waiting 30 real seconds.
    """
    device = TOTPDevice.objects.filter(user=user, confirmed=True).order_by("id").first()
    assert device is not None
    now_dt = timezone.now()
    totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
    totp.time = int(now_dt.timestamp())
    current_t = totp.t()
    if device.last_t is not None and device.last_t >= current_t:
        device.last_t = current_t - 1
        device.save(update_fields=["last_t"])
    return str(totp.token()).zfill(device.digits)


def login_full_mfa_client(username: str, password: str, enforce_csrf: bool = False) -> Client:
    """
    Perform full 2-step login (Password -> TOTP MFA) using Django test Client.
    """
    username = DEMO_USERNAME_ALIASES.get(username, username)
    client = Client(enforce_csrf_checks=enforce_csrf)
    user = EmployeeIdentity.objects.get(username=username)

    if enforce_csrf:
        client.get("/auth/login")
        csrf_token = client.cookies["csrftoken"].value
        r1 = client.post(
            "/auth/login",
            data={"username": username, "password": password, "csrfmiddlewaretoken": csrf_token},
            HTTP_ACCEPT="application/json",
            HTTP_X_CSRFTOKEN=csrf_token,
        )
    else:
        r1 = client.post(
            "/auth/login",
            data={"username": username, "password": password},
            HTTP_ACCEPT="application/json",
        )
    assert r1.status_code == 200, f"Step 1 login failed for {username}: {r1.status_code} {r1.content}"

    code = next_fresh_totp(user)
    if enforce_csrf:
        csrf_token = client.cookies["csrftoken"].value
        r2 = client.post(
            "/auth/mfa",
            data={"otp_token": code, "csrfmiddlewaretoken": csrf_token},
            HTTP_ACCEPT="application/json",
            HTTP_X_CSRFTOKEN=csrf_token,
        )
    else:
        r2 = client.post(
            "/auth/mfa",
            data={"otp_token": code},
            HTTP_ACCEPT="application/json",
        )
    assert r2.status_code == 200, f"Step 2 MFA failed for {username}: {r2.status_code} {r2.content}"
    return client


def write_test_evidence(
    test_id: str,
    *,
    actual: str,
    status: str = "PASS",
    fixture: str = "default_lab",
    details: dict[str, Any] | None = None,
) -> str:
    """
    Write sanitized JSON evidence for `test_id` to `evidence/logs/{test_id}.json`.
    Returns the relative evidence path.
    """
    EVIDENCE_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = EVIDENCE_LOGS_DIR / f"{test_id}.json"
    payload = {
        "test_id": test_id,
        "status": status,
        "fixture": fixture,
        "recorded_at_utc": datetime.now(dt_timezone.utc).isoformat(),
        "actual": actual,
        "details": details or {},
    }
    out_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return f"evidence/logs/{test_id}.json"

