"""Show one-time Authenticator enrollment details for a local classroom demo identity."""
from __future__ import annotations

import base64
import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Show the Base32 setup key for a local demo account. Never use in production."

    def add_arguments(self, parser):
        parser.add_argument("username", help="Demo username, for example: dacqui")

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError("demo_totp_setup is disabled when DEBUG=False.")

        username = options["username"]
        try:
            creds_path = Path(settings.BASE_DIR) / "private" / "demo_credentials.json"
            principals = json.loads(creds_path.read_text(encoding="utf-8"))["principals"]
            principal = principals[username]
            secret = base64.b32encode(bytes.fromhex(principal["totp_hex_key"])).decode("ascii").rstrip("=")
        except FileNotFoundError as exc:
            raise CommandError("Run 'python app.py --reset' once to create demo credentials.") from exc
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            raise CommandError(f"Unknown or invalid demo account: {username}") from exc

        self.stdout.write(self.style.WARNING("ONE-TIME LOCAL DEMO SETUP — KEEP THIS KEY PRIVATE"))
        self.stdout.write(f"Account name : SecurePay - {principal['display_name']}")
        self.stdout.write(f"Setup key   : {secret}")
        self.stdout.write("Key type    : Time based")
        self.stdout.write("Period      : 30 seconds")
        self.stdout.write("After enrollment, clear the terminal and use the phone-generated code.")
