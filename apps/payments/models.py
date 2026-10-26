from __future__ import annotations

import uuid
from django.conf import settings
from django.db import models
from django.db.models import Q


class RequestStatus(models.TextChoices):
    DRAFT = "DRAFT", "Bản nháp (Chưa gửi duyệt)"
    PENDING_APPROVAL = "PENDING_APPROVAL", "Đang chờ duyệt"
    APPROVED = "APPROVED", "Đủ 2 phê duyệt"
    HOLD = "HOLD", "Bị giữ để kiểm tra"
    REJECTED = "REJECTED", "Đã từ chối"
    CANCELLED = "CANCELLED", "Đã hủy"
    EXPIRED = "EXPIRED", "Xác nhận đã hết hạn"
    EXECUTED_SIMULATED = "EXECUTED_SIMULATED", "Đã thực hiện mô phỏng"


TERMINAL_REQUEST_STATUSES = frozenset(
    {
        RequestStatus.REJECTED,
        RequestStatus.CANCELLED,
        RequestStatus.EXPIRED,
        RequestStatus.EXECUTED_SIMULATED,
    }
)


class SourceKind(models.TextChoices):
    CHAT_MESSAGE = "CHAT_MESSAGE", "Tin nhắn chat (Zalo / Telegram / Messenger)"
    EMAIL = "EMAIL", "Thư điện tử (Email)"
    PHONE_CALL = "PHONE_CALL", "Cuộc gọi thoại / Video"
    PAPER_INVOICE = "PAPER_INVOICE", "Đề nghị / Hóa đơn nội bộ"
    OTHER = "OTHER", "Nguồn khác"


class ChallengeAction(models.TextChoices):
    APPROVE_DIRECTOR = "APPROVE_DIRECTOR", "Phê duyệt (Slot Giám đốc)"
    APPROVE_CONTROLLER = "APPROVE_CONTROLLER", "Phê duyệt (Slot Kiểm soát viên)"
    REJECT = "REJECT", "Từ chối yêu cầu thanh toán"
    EXECUTE = "EXECUTE", "Thực hiện thanh toán mô phỏng"
    SUSPEND = "SUSPEND", "Đình chỉ tài khoản"
    REVOKE_ALL = "REVOKE_ALL", "Thu hồi toàn bộ phiên và xác nhận"


class ChallengeTargetType(models.TextChoices):
    PAYMENT_REQUEST = "PAYMENT_REQUEST", "Yêu cầu thanh toán"
    EMPLOYEE_IDENTITY = "EMPLOYEE_IDENTITY", "Tài khoản nhân viên"


class ApprovalSlot(models.TextChoices):
    DIRECTOR = "DIRECTOR", "Slot Giám đốc (DIRECTOR)"
    CONTROLLER = "CONTROLLER", "Slot Kiểm soát viên (CONTROLLER)"


class ApprovalStatus(models.TextChoices):
    ACTIVE = "ACTIVE", "Còn hiệu lực"
    SUPERSEDED_BY_REVISION = "SUPERSEDED_BY_REVISION", "Hết hiệu lực do tạo revision mới"
    INVALIDATED_BY_INCIDENT = "INVALIDATED_BY_INCIDENT", "Vô hiệu hóa do sự cố / thu hồi quyền"
    EXPIRED = "EXPIRED", "Hết hạn theo thời gian"


class PaymentRequest(models.Model):
    """
    Master payment request record (Section 6.2).
    At most one PaymentExecution can ever exist per PaymentRequest across all revisions.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request_code = models.CharField(max_length=32, unique=True)
    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="payment_requests",
    )
    requester_person_id = models.CharField(max_length=64)
    current_revision = models.ForeignKey(
        "PaymentRevision",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
    )
    status = models.CharField(
        max_length=32,
        choices=RequestStatus.choices,
        default=RequestStatus.DRAFT,
        db_index=True,
    )
    hold_reason = models.CharField(max_length=500, blank=True)
    rejection_reason = models.CharField(max_length=500, blank=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "payments_paymentrequest"
        ordering = ["-created_at"]

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_REQUEST_STATUSES

    def __str__(self) -> str:
        return f"{self.request_code} [{self.status}]"


class PaymentRevision(models.Model):
    """
    Versioned snapshot of payment request content (DES-04, Section 6.2).
    Immutable once submitted (`is_frozen=True`). Any meaningful edit after submission creates
    a new revision_number in DRAFT and invalidates prior approvals/challenges.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    payment_request = models.ForeignKey(
        PaymentRequest,
        on_delete=models.PROTECT,
        related_name="revisions",
    )
    revision_number = models.PositiveIntegerField()
    amount_vnd = models.BigIntegerField()
    currency = models.CharField(max_length=8, default="VND")
    beneficiary = models.ForeignKey(
        "beneficiaries.Beneficiary",
        on_delete=models.PROTECT,
        related_name="payment_revisions",
    )
    beneficiary_version = models.ForeignKey(
        "beneficiaries.BeneficiaryVersion",
        on_delete=models.PROTECT,
        related_name="payment_revisions",
    )
    beneficiary_name_snapshot = models.CharField(max_length=200)
    bank_name_snapshot = models.CharField(max_length=150)
    account_number_snapshot = models.CharField(max_length=64)
    purpose = models.CharField(max_length=500)
    source_kind = models.CharField(
        max_length=50,
        choices=SourceKind.choices,
        default=SourceKind.CHAT_MESSAGE,
    )
    source_excerpt = models.CharField(max_length=2000, blank=True)
    content_digest = models.CharField(max_length=64, blank=True)
    is_frozen = models.BooleanField(default=False)
    frozen_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "payments_paymentrevision"
        ordering = ["payment_request", "-revision_number"]
        constraints = [
            models.UniqueConstraint(
                fields=["payment_request", "revision_number"],
                name="uniq_request_revision_number",
            ),
            models.CheckConstraint(
                condition=Q(amount_vnd__gt=0) & Q(amount_vnd__lte=1_000_000_000_000),
                name="chk_amount_vnd_positive_domain",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.payment_request.request_code} Rev#{self.revision_number} ({self.amount_vnd:,} VND)"


class ActionChallenge(models.Model):
    """
    Server-issued action-scoped step-up challenge (DES-05, Section 6.2 & 8).
    Binds actor, person_id, session, TOTP device, security_epoch, action type,
    target object/revision/digest/beneficiary_version, 120s TTL, and one-time consumption.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nonce = models.CharField(max_length=64, unique=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="action_challenges",
    )
    actor_person_id = models.CharField(max_length=64)
    session_key_hash = models.CharField(max_length=64)
    device_id = models.IntegerField()
    actor_epoch = models.PositiveIntegerField()
    action = models.CharField(max_length=32, choices=ChallengeAction.choices)
    target_type = models.CharField(max_length=32, choices=ChallengeTargetType.choices)

    # Fields for payment actions (APPROVE_DIRECTOR, APPROVE_CONTROLLER, REJECT, EXECUTE)
    payment_request = models.ForeignKey(
        PaymentRequest,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="challenges",
    )
    payment_revision = models.ForeignKey(
        PaymentRevision,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="challenges",
    )
    content_digest = models.CharField(max_length=64)
    beneficiary_version = models.ForeignKey(
        "beneficiaries.BeneficiaryVersion",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
    )

    # Fields for security-admin actions (SUSPEND, REVOKE_ALL)
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="targeted_security_challenges",
    )
    target_user_epoch = models.PositiveIntegerField(null=True, blank=True)
    reason_text = models.CharField(max_length=500, blank=True)

    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)
    invalidated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "payments_actionchallenge"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Challenge({self.action} by {self.actor_person_id}, consumed={self.consumed_at is not None})"


class Approval(models.Model):
    """
    Independent approval decision bound to a frozen PaymentRevision (Section 6.2 & 6.3).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    payment_request = models.ForeignKey(
        PaymentRequest,
        on_delete=models.PROTECT,
        related_name="approvals",
    )
    payment_revision = models.ForeignKey(
        PaymentRevision,
        on_delete=models.PROTECT,
        related_name="approvals",
    )
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="given_approvals",
    )
    approver_person_id = models.CharField(max_length=64)
    slot = models.CharField(max_length=32, choices=ApprovalSlot.choices)
    content_digest = models.CharField(max_length=64)
    beneficiary_version = models.ForeignKey(
        "beneficiaries.BeneficiaryVersion",
        on_delete=models.PROTECT,
        related_name="+",
    )
    approver_epoch_at_signing = models.PositiveIntegerField()
    requester_epoch_at_signing = models.PositiveIntegerField()
    challenge = models.OneToOneField(
        ActionChallenge,
        on_delete=models.PROTECT,
        related_name="approval_record",
    )
    status = models.CharField(
        max_length=32,
        choices=ApprovalStatus.choices,
        default=ApprovalStatus.ACTIVE,
    )
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()

    class Meta:
        db_table = "payments_approval"
        ordering = ["created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["payment_revision", "slot"],
                name="uniq_revision_approval_slot",
            ),
            models.UniqueConstraint(
                fields=["payment_revision", "approver_person_id"],
                name="uniq_revision_approver_person",
            ),
            models.UniqueConstraint(
                fields=["payment_revision", "approver"],
                name="uniq_revision_approver_user",
            ),
        ]

    def __str__(self) -> str:
        return f"Approval({self.payment_revision} / {self.slot} by {self.approver_person_id} [{self.status}])"


class PaymentExecution(models.Model):
    """
    Immutable simulated execution receipt (DES-03, DES-08, Section 6.2).
    OneToOne with PaymentRequest ensures a request can never be executed more than once.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    payment_request = models.OneToOneField(
        PaymentRequest,
        on_delete=models.PROTECT,
        related_name="execution",
    )
    payment_revision = models.ForeignKey(
        PaymentRevision,
        on_delete=models.PROTECT,
        related_name="executions",
    )
    content_digest = models.CharField(max_length=64)
    amount_vnd = models.BigIntegerField()
    currency = models.CharField(max_length=8, default="VND")
    beneficiary_name_snapshot = models.CharField(max_length=200)
    bank_name_snapshot = models.CharField(max_length=150)
    account_number_snapshot = models.CharField(max_length=64)
    executor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="executed_payments",
    )
    executor_person_id = models.CharField(max_length=64)
    challenge = models.OneToOneField(
        ActionChallenge,
        on_delete=models.PROTECT,
        related_name="execution_record",
    )
    idempotency_key = models.CharField(max_length=128)
    payload_fingerprint = models.CharField(max_length=64)
    receipt_id = models.CharField(max_length=64, unique=True)
    execution_label = models.CharField(max_length=64, default="SIMULATED")
    executed_at = models.DateTimeField()

    class Meta:
        db_table = "payments_paymentexecution"
        ordering = ["-executed_at"]

    def __str__(self) -> str:
        return f"{self.receipt_id} ({self.payment_request.request_code} - {self.execution_label})"

