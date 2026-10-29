"""Print the current TOTP code for one local classroom-demo identity."""
from __future__ import annotations

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice

from apps.accounts.models import EmployeeIdentity


class Command(BaseCommand):
    help = "Show the current TOTP for a local SecurePay demo account. Never use in production."

    def add_arguments(self, parser):
        parser.add_argument("username", help="Demo username, for example: dacqui")

    def handle(self, *args, **options):
        db_name = str(connection.settings_dict.get("NAME", ""))
        if "securepay_lab" not in db_name:
            raise CommandError("Refusing to reveal a TOTP outside the securepay_lab demo database.")
        if not settings.DEBUG:
            raise CommandError("demo_totp is disabled when DEBUG=False.")

        username = options["username"]
        try:
            user = EmployeeIdentity.objects.get(username=username)
        except EmployeeIdentity.DoesNotExist as exc:
            raise CommandError(f"Unknown demo account: {username}") from exc

        device = TOTPDevice.objects.filter(user=user, confirmed=True).order_by("id").first()
        if device is None:
            raise CommandError(f"No confirmed TOTP device for: {username}")

        totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
        code = str(totp.token()).zfill(device.digits)
        self.stdout.write(self.style.WARNING("LOCAL CLASSROOM DEMO CODE — DO NOT SHARE"))
        self.stdout.write(f"{username}: {code}  (changes every {device.step} seconds)")
