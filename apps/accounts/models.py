from __future__ import annotations

import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models


class Role(models.TextChoices):
    REQUESTER = "REQUESTER", "Người lập yêu cầu (Kế toán)"
    DIRECTOR = "DIRECTOR", "Giám đốc phê duyệt"
    CONTROLLER = "CONTROLLER", "Kiểm soát viên tài chính"
    SECURITY_ADMIN = "SECURITY_ADMIN", "Quản trị an ninh ứng dụng"
    UNPRIVILEGED = "UNPRIVILEGED", "Tài khoản không có quyền nghiệp vụ"


class EmployeeIdentity(AbstractUser):
    """
    Custom User model representing an employee identity provisioned via trusted offline bootstrap (DES-01).
    - `person_id`: Unique real-person identifier verified offline. Two usernames of the same person
      cannot exist in baseline, and all separation-of-duty checks verify both user.id and person_id.
    - `security_epoch`: Monotonically increasing counter incremented on suspend, revoke_all,
      role change, or offline MFA recovery.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    person_id = models.CharField(max_length=64, unique=True)
    display_name = models.CharField(max_length=150)
    role = models.CharField(
        max_length=32,
        choices=Role.choices,
        default=Role.UNPRIVILEGED,
    )
    is_suspended = models.BooleanField(default=False)
    suspension_reason = models.CharField(max_length=500, blank=True)
    identity_verified_at = models.DateTimeField(null=True, blank=True)
    security_epoch = models.PositiveIntegerField(default=1)

    # Persistent throttling counters (Section 3.1, T-13)
    failed_password_attempts = models.PositiveIntegerField(default=0)
    password_throttled_until = models.DateTimeField(null=True, blank=True)
    failed_otp_attempts = models.PositiveIntegerField(default=0)
    otp_throttled_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "accounts_employeeidentity"

    @property
    def is_operational(self) -> bool:
        return bool(self.is_active and not self.is_suspended and self.identity_verified_at is not None)

    def __str__(self) -> str:
        return f"{self.display_name} ({self.username} / {self.role} / {self.person_id})"

