from __future__ import annotations

import uuid
from django.db import models


class BeneficiaryStatus(models.TextChoices):
    PENDING = "PENDING", "Chờ xác minh độc lập"
    VERIFIED = "VERIFIED", "Đã xác minh độc lập"
    REVOKED = "REVOKED", "Đã thu hồi / Ngừng giao dịch"


class Beneficiary(models.Model):
    """
    Beneficiary master record in the trusted registry (DES-07).
    Points to an immutable `active_version` when status == VERIFIED.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=50, unique=True)
    status = models.CharField(
        max_length=32,
        choices=BeneficiaryStatus.choices,
        default=BeneficiaryStatus.PENDING,
    )
    active_version = models.ForeignKey(
        "BeneficiaryVersion",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
    )
    registry_epoch = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "beneficiaries_beneficiary"
        ordering = ["code"]

    def __str__(self) -> str:
        if self.active_version:
            return f"{self.code} — {self.active_version.vendor_name} (v{self.active_version.version_number})"
        return f"{self.code} ({self.status})"


class BeneficiaryVersion(models.Model):
    """
    Immutable version of a beneficiary's bank account details (DES-07).
    Never edited in-place once created; any bank/account change creates a new version_number.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    beneficiary = models.ForeignKey(
        Beneficiary,
        on_delete=models.PROTECT,
        related_name="versions",
    )
    version_number = models.PositiveIntegerField()
    vendor_name = models.CharField(max_length=200)
    bank_name = models.CharField(max_length=150)
    account_number = models.CharField(max_length=64)
    verification_reference = models.CharField(max_length=300)
    status = models.CharField(
        max_length=32,
        choices=BeneficiaryStatus.choices,
        default=BeneficiaryStatus.PENDING,
    )
    verified_by_summary = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "beneficiaries_beneficiaryversion"
        ordering = ["beneficiary__code", "-version_number"]
        constraints = [
            models.UniqueConstraint(
                fields=["beneficiary", "version_number"],
                name="uniq_beneficiary_version_number",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"{self.beneficiary.code} v{self.version_number}: {self.vendor_name} - "
            f"{self.bank_name} ({self.account_number}) [{self.status}]"
        )

