"""
Trusted offline beneficiary registry command `manage.py manage_beneficiary` (DES-07, Section 7.1).
"""
from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from apps.beneficiaries.models import BeneficiaryStatus
from apps.beneficiaries.services import (
    offline_create_or_update_beneficiary_version,
    offline_revoke_beneficiary,
)


class Command(BaseCommand):
    help = "Create a new immutable BeneficiaryVersion or revoke a Beneficiary via offline trusted procedure."

    def add_arguments(self, parser):
        parser.add_argument("--action", choices=["new-version", "revoke"], required=True)
        parser.add_argument("--code", required=True, help="Beneficiary code (e.g. BEN-001)")
        parser.add_argument("--vendor-name", default="")
        parser.add_argument("--bank-name", default="")
        parser.add_argument("--account-number", default="")
        parser.add_argument("--reference", default="Offline contract verification")
        parser.add_argument("--status", default=BeneficiaryStatus.VERIFIED)
        parser.add_argument("--reason", default="Offline dual-control update")

    def handle(self, *args, **options):
        act = options["action"]
        if act == "revoke":
            ben, affected = offline_revoke_beneficiary(code=options["code"], reason=options["reason"])
            self.stdout.write(
                self.style.SUCCESS(
                    f"Revoked beneficiary {ben.code} (epoch={ben.registry_epoch}); affected requests={affected}"
                )
            )
        elif act == "new-version":
            if not (options["vendor_name"] and options["bank_name"] and options["account_number"]):
                raise CommandError("--vendor-name, --bank-name, and --account-number are required for new-version")
            ben, ver = offline_create_or_update_beneficiary_version(
                code=options["code"],
                vendor_name=options["vendor_name"],
                bank_name=options["bank_name"],
                account_number=options["account_number"],
                verification_reference=options["reference"],
                status=options["status"],
                verified_by_summary=options["reason"],
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"Created {ben.code} v{ver.version_number} [{ver.status}] (epoch={ben.registry_epoch})"
                )
            )

