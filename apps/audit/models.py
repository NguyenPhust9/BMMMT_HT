from __future__ import annotations

import uuid
from django.conf import settings
from django.db import models


class AuditResult(models.TextChoices):
    SUCCESS = "SUCCESS", "Thành công"
    DENIED = "DENIED", "Bị từ chối"
    ERROR = "ERROR", "Lỗi hệ thống"


class AuditEvent(models.Model):
    """
    Append-only application audit record (Section 6.2 & 10.2).
    Never stores raw passwords, OTP codes, TOTP seeds, provisioning URIs, raw session IDs, or CSRF tokens.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="audit_events",
    )
    actor_username_snapshot = models.CharField(max_length=150, blank=True)
    actor_person_id = models.CharField(max_length=64, blank=True)
    actor_role = models.CharField(max_length=32, blank=True)
    action = models.CharField(max_length=64, db_index=True)
    payment_request = models.ForeignKey(
        "payments.PaymentRequest",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="audit_events",
    )
    revision_number = models.PositiveIntegerField(null=True, blank=True)
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="targeted_audit_events",
    )
    result = models.CharField(max_length=16, choices=AuditResult.choices)
    reason_code = models.CharField(max_length=64, db_index=True)
    before_state = models.CharField(max_length=64, blank=True)
    after_state = models.CharField(max_length=64, blank=True)
    correlation_id = models.CharField(max_length=64, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "audit_auditevent"
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return f"[{self.created_at}] {self.action} ({self.result} / {self.reason_code})"

