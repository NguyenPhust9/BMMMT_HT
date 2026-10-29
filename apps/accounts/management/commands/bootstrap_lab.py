"""
Trusted offline bootstrap command `manage.py bootstrap_lab` (DES-01, DES-07, Section 7.1).
- Ensures SecurityMutex(id=1) exists.
- Safely resets ONLY securepay_lab demo tables when `--reset` is passed (checks database name).
- Provisions fixed identities (vanphu, dacqui, doanphuc, ngocchau, minh, dacqui_lookalike) with distinct person_ids,
  non-superuser/non-staff flags, and confirmed TOTPDevices.
- Seeds fictional beneficiaries (2 VERIFIED, 1 PENDING, 1 REVOKED).
- Saves runtime demo credentials strictly to `private/demo_credentials.json` (git-ignored).
"""
from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex

from apps.accounts.models import EmployeeIdentity, Role
from apps.audit.models import AuditEvent, AuditResult
from apps.audit.services import record_audit_event
from apps.beneficiaries.models import Beneficiary, BeneficiaryStatus, BeneficiaryVersion
from apps.common.models import SecurityMutex
from apps.payments.models import (
    ActionChallenge,
    Approval,
    PaymentExecution,
    PaymentRequest,
    PaymentRevision,
)


SEED_PRINCIPALS = [
    {
        "username": "vanphu",
        "person_id": "PER-VANPHU-001",
        "display_name": "Nguyễn Văn Phú (Kế toán)",
        "role": Role.REQUESTER,
    },
    {
        "username": "dacqui",
        "person_id": "PER-DACQUI-002",
        "display_name": "Bùi Đắc Quí (Giám đốc)",
        "role": Role.DIRECTOR,
    },
    {
        "username": "doanphuc",
        "person_id": "PER-DOANPHUC-003",
        "display_name": "Đoàn Phúc (Kiểm soát viên)",
        "role": Role.CONTROLLER,
    },
    {
        "username": "ngocchau",
        "person_id": "PER-NGOCCHAU-004",
        "display_name": "Đặng Ngọc Châu (Quản trị an ninh)",
        "role": Role.SECURITY_ADMIN,
    },
    {
        "username": "minh",
        "person_id": "PER-MINH-005",
        "display_name": "Hoàng Văn Minh (Kế toán 2)",
        "role": Role.REQUESTER,
    },
    {
        "username": "dacqui_lookalike",
        "person_id": "PER-FAKE-006",
        "display_name": "Bùi Đắc Quí (Giám đốc)",
        "role": Role.UNPRIVILEGED,
    },
]

SEED_BENEFICIARIES = [
    {
        "code": "BEN-001",
        "vendor_name": "Công ty Cổ phần Thiết bị mạng Sao Việt",
        "bank_name": "Ngân hàng TMCP Ngoại thương (VCB)",
        "account_number": "0011009988776",
        "verification_reference": "HĐKT-2026/SV-01 & Biên bản đối chiếu độc lập 2 người #BB-101",
        "status": BeneficiaryStatus.VERIFIED,
        "verified_by_summary": "Đối chiếu độc lập bởi Quí (PER-DACQUI-002) & Phúc (PER-DOANPHUC-003)",
    },
    {
        "code": "BEN-002",
        "vendor_name": "Công ty TNHH Giải pháp Điện toán Ánh Dương",
        "bank_name": "Ngân hàng TMCP Kỹ thương (TCB)",
        "account_number": "1903887766554",
        "verification_reference": "HĐKT-2026/AD-02 & Biên bản đối chiếu độc lập 2 người #BB-102",
        "status": BeneficiaryStatus.VERIFIED,
        "verified_by_summary": "Đối chiếu độc lập bởi Quí (PER-DACQUI-002) & Phúc (PER-DOANPHUC-003)",
    },
    {
        "code": "BEN-003",
        "vendor_name": "Công ty TNHH Thương mại Bắc Hà (Chờ xác minh)",
        "bank_name": "Ngân hàng TMCP Quân đội (MB)",
        "account_number": "8899001122334",
        "verification_reference": "Đề nghị thêm nhà cung cấp mới — CHƯA đối chiếu hợp đồng gốc",
        "status": BeneficiaryStatus.PENDING,
        "verified_by_summary": "",
    },
    {
        "code": "BEN-004",
        "vendor_name": "Công ty TNHH Cung ứng Cũ Đông Đô (Đã thu hồi)",
        "bank_name": "Ngân hàng TMCP Công thương (CTG)",
        "account_number": "1020004455667",
        "verification_reference": "HĐKT-2025/DD-09 — Đã chấm dứt hợp đồng và thu hồi hiệu lực",
        "status": BeneficiaryStatus.REVOKED,
        "verified_by_summary": "Đã thu hồi theo biên bản #BB-REV-04",
    },
]


_PASSWORD_HASH_CACHE: dict[str, str] = {}


class Command(BaseCommand):
    help = "Bootstrap trusted offline identities, MFA devices, SecurityMutex(id=1), and fictional beneficiaries."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Safely clear existing demo records in securepay_lab before seeding.",
        )

    def handle(self, *args, **options):
        db_name = connection.settings_dict.get("NAME", "")
        if "securepay_lab" not in str(db_name):
            raise CommandError(
                f"Refusing to run bootstrap_lab on non-project database '{db_name}' (Section 15.3 safety guard)."
            )

        now = timezone.now()
        private_dir = Path(settings.BASE_DIR) / "private"
        private_dir.mkdir(parents=True, exist_ok=True)
        creds_path = private_dir / "demo_credentials.json"

        with transaction.atomic():
            SecurityMutex.objects.get_or_create(pk=1)
            SecurityMutex.objects.select_for_update().get(pk=1)

            if options.get("reset"):
                AuditEvent.objects.all().delete()
                PaymentExecution.objects.all().delete()
                Approval.objects.all().delete()
                ActionChallenge.objects.all().delete()
                PaymentRequest.objects.update(current_revision=None)
                PaymentRevision.objects.all().delete()
                PaymentRequest.objects.all().delete()
                Beneficiary.objects.update(active_version=None)
                BeneficiaryVersion.objects.all().delete()
                Beneficiary.objects.all().delete()
                TOTPDevice.objects.all().delete()
                EmployeeIdentity.objects.all().delete()

            existing_creds = {}
            if creds_path.exists():
                try:
                    existing_creds = json.loads(creds_path.read_text(encoding="utf-8")).get("principals", {})
                except Exception:
                    existing_creds = {}

            out_principals: dict[str, dict] = {}
            for spec in SEED_PRINCIPALS:
                uname = spec["username"]
                prev = existing_creds.get(uname, {})
                # Deliberately simple and shared for the local classroom demo only.
                raw_password = "123456"
                totp_hex_key = prev.get("totp_hex_key") or random_hex(20)

                user, _ = EmployeeIdentity.objects.update_or_create(
                    username=uname,
                    defaults={
                        "person_id": spec["person_id"],
                        "display_name": spec["display_name"],
                        "role": spec["role"],
                        "is_active": True,
                        "is_suspended": False,
                        "suspension_reason": "",
                        "is_staff": False,
                        "is_superuser": False,
                        "identity_verified_at": now,
                        "security_epoch": 1,
                        "failed_password_attempts": 0,
                        "password_throttled_until": None,
                        "failed_otp_attempts": 0,
                        "otp_throttled_until": None,
                    },
                )
                if raw_password not in _PASSWORD_HASH_CACHE:
                    _PASSWORD_HASH_CACHE[raw_password] = make_password(raw_password)
                user.password = _PASSWORD_HASH_CACHE[raw_password]
                user.save()

                TOTPDevice.objects.filter(user=user).delete()
                TOTPDevice.objects.create(
                    user=user,
                    name=f"totp-{uname}",
                    key=totp_hex_key,
                    confirmed=True,
                    step=30,
                    digits=6,
                    drift=0,
                    tolerance=0,
                )

                out_principals[uname] = {
                    "username": uname,
                    "person_id": spec["person_id"],
                    "display_name": spec["display_name"],
                    "role": spec["role"],
                    "password": raw_password,
                    "totp_hex_key": totp_hex_key,
                }

            for bspec in SEED_BENEFICIARIES:
                ben, _ = Beneficiary.objects.update_or_create(
                    code=bspec["code"],
                    defaults={
                        "status": bspec["status"],
                        "registry_epoch": 1,
                    },
                )
                ver, _ = BeneficiaryVersion.objects.update_or_create(
                    beneficiary=ben,
                    version_number=1,
                    defaults={
                        "vendor_name": bspec["vendor_name"],
                        "bank_name": bspec["bank_name"],
                        "account_number": bspec["account_number"],
                        "verification_reference": bspec["verification_reference"],
                        "status": bspec["status"],
                        "verified_by_summary": bspec["verified_by_summary"],
                    },
                )
                if bspec["status"] == BeneficiaryStatus.VERIFIED:
                    ben.active_version = ver
                else:
                    ben.active_version = None
                ben.save()

            record_audit_event(
                action="OFFLINE_BOOTSTRAP_LAB",
                result=AuditResult.SUCCESS,
                reason_code="OK",
                actor_username="offline_bootstrap_cli",
                metadata={
                    "principals_seeded": list(out_principals.keys()),
                    "beneficiaries_seeded": [b["code"] for b in SEED_BENEFICIARIES],
                    "reset": bool(options.get("reset")),
                },
            )

        creds_payload = {
            "notice": "LOCAL DEMO & TEST CREDENTIALS ONLY — DO NOT COMMIT OR PACKAGE",
            "generated_at_utc": now.isoformat(),
            "principals": out_principals,
        }
        creds_path.write_text(json.dumps(creds_payload, indent=2, ensure_ascii=False), encoding="utf-8")
        self.stdout.write(
            self.style.SUCCESS(
                f"Bootstrapped {len(out_principals)} principals and {len(SEED_BENEFICIARIES)} beneficiaries. "
                f"Local credentials written to private/demo_credentials.json (redacted from stdout)."
            )
        )

