"""
Trusted offline principal recovery CLI `manage.py recover_principal` (Section 10.1, DES-09).
"""
from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.accounts.services import offline_recover_principal


class Command(BaseCommand):
    help = "Perform trusted offline recovery / role update / MFA rotation for an EmployeeIdentity."

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True, help="Username of the principal")
        parser.add_argument("--role", default=None, help="Optional new Role")
        parser.add_argument("--rotate-mfa", action="store_true", help="Rotate TOTPDevice secret")
        parser.add_argument("--note", default="Offline dual-control recovery", help="Operator audit note")

    def handle(self, *args, **options):
        user, _new_key = offline_recover_principal(
            username=options["username"],
            new_role=options["role"],
            rotate_mfa=bool(options["rotate_mfa"]),
            unsuspend=True,
            operator_note=options["note"],
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Recovered principal '{user.username}': role={user.role}, "
                f"is_suspended={user.is_suspended}, new security_epoch={user.security_epoch}"
            )
        )

