"""
Internal command `manage.py expire_requests` to update overdue requests to EXPIRED under SecurityMutex(id=1) (Section 7.3).
"""
from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from apps.common.mutex import acquire_security_mutex
from apps.payments.models import PAYMENT_REQUEST_STATUSES if False else RequestStatus, PaymentRequest
from apps.payments.services import _check_and_expire_request_under_lock


class Command(BaseCommand):
    help = "Mark overdue payment requests as EXPIRED under SecurityMutex(id=1)."

    def handle(self, *args, **options):
        now = timezone.now()
        expired_count = 0
        with transaction.atomic():
            acquire_security_mutex()
            candidates = list(
                PaymentRequest.objects.select_for_update().filter(
                    status__in=[RequestStatus.PENDING_APPROVAL, RequestStatus.APPROVED, RequestStatus.HOLD],
                    expires_at__lte=now,
                )
            )
            for req in candidates:
                _check_and_expire_request_under_lock(req, now)
                expired_count += 1
        self.stdout.write(self.style.SUCCESS(f"Expired {expired_count} overdue payment request(s)."))

