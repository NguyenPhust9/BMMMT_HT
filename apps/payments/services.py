"""
Core payment request lifecycle, immutable revision freezing, action challenge binding,
independent dual approval enforcement, and atomic simulated execution (Sections 6, 7, 8).
"""
from __future__ import annotations

from datetime import timedelta
import secrets
from typing import Any, Callable
import uuid

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.accounts.models import EmployeeIdentity, Role
from apps.accounts.services import get_confirmed_totp_device, verify_totp_token_under_lock
from apps.audit.models import AuditResult
from apps.audit.services import record_audit_event
from apps.beneficiaries.models import Beneficiary, BeneficiaryStatus, BeneficiaryVersion
from apps.common.crypto import canonical_json_sha256, sha256_hex
from apps.common.exceptions import ReasonCode, SecurityDomainError
from apps.common.mutex import acquire_security_mutex, security_atomic
from apps.payments.models import (
    TERMINAL_REQUEST_STATUSES,
    ActionChallenge,
    Approval,
    ApprovalSlot,
    ApprovalStatus,
    ChallengeAction,
    ChallengeTargetType,
    PaymentExecution,
    PaymentRequest,
    PaymentRevision,
    RequestStatus,
    SourceKind,
)

FORBIDDEN_CLIENT_AUTHORITY_FIELDS = frozenset(
    {
        "role",
        "is_verified",
        "verified",
        "mfa_verified",
        "auth_mfa_verified",
        "status",
        "state",
        "requester",
        "requester_id",
        "requester_person_id",
        "approver",
        "approver_id",
        "approver_person_id",
        "approval_ids",
        "security_epoch",
        "content_digest",
        "is_frozen",
        "account_number_override",
        "bank_name_override",
    }
)


def assert_no_authority_fields(
    payload: dict[str, Any] | None,
    *,
    actor: EmployeeIdentity | None = None,
    action: str = "CLIENT_INPUT_VALIDATION",
    payment_request: PaymentRequest | None = None,
) -> None:
    """
    Reject client payloads attempting to supply authority/state/role/verified/account override fields (T-06, T-18, T-24).
    """
    if not payload:
        return
    present = [k for k in payload.keys() if str(k).lower() in FORBIDDEN_CLIENT_AUTHORITY_FIELDS]
    if present:
        record_audit_event(
            action=action,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.FORBIDDEN,
            actor=actor,
            payment_request=payment_request,
            metadata={"rejected_authority_fields": sorted(present)},
        )
        raise SecurityDomainError(
            ReasonCode.FORBIDDEN,
            f"Máy chủ từ chối các trường tự khai trái thẩm quyền từ client: {', '.join(sorted(present))}.",
            status_code=400,
        )


def compute_revision_digest(rev: PaymentRevision) -> str:
    """
    Deterministic SHA-256 digest over canonical JSON of all decision-relevant revision fields (DES-04, TECH-01).
    """
    return canonical_json_sha256(
        {
            "request_id": str(rev.payment_request_id),
            "revision_number": int(rev.revision_number),
            "amount_vnd": int(rev.amount_vnd),
            "currency": str(rev.currency),
            "beneficiary_id": str(rev.beneficiary_id),
            "beneficiary_version_id": str(rev.beneficiary_version_id),
            "beneficiary_name_snapshot": str(rev.beneficiary_name_snapshot),
            "bank_name_snapshot": str(rev.bank_name_snapshot),
            "account_number_snapshot": str(rev.account_number_snapshot),
            "purpose": str(rev.purpose),
            "source_kind": str(rev.source_kind),
            "source_excerpt": str(rev.source_excerpt),
        }
    )


def compute_execution_payload_fingerprint(
    *,
    request_id: Any,
    revision_id: Any,
    content_digest: str,
) -> str:
    return canonical_json_sha256(
        {
            "request_id": str(request_id),
            "revision_id": str(revision_id),
            "content_digest": str(content_digest),
        }
    )


def validate_and_parse_amount_vnd(raw_amount: Any) -> int:
    """
    Strictly validate integer VND in [1, 1_000_000_000_000].
    Rejects floats, decimals, negative/zero, booleans, or non-numeric strings without silent rounding (DES-04, T-37).
    """
    if isinstance(raw_amount, bool) or raw_amount is None:
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            "Số tiền VND không hợp lệ.",
            status_code=400,
        )
    if isinstance(raw_amount, float):
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            "Số tiền VND phải là số nguyên, không chấp nhận số thập phân.",
            status_code=400,
        )
    raw_str = str(raw_amount).strip()
    if not raw_str or "." in raw_str or "," in raw_str:
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            "Số tiền VND phải là số nguyên dương (không chứa dấu thập phân).",
            status_code=400,
        )
    if raw_str.startswith("-"):
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            "Số tiền VND phải lớn hơn 0.",
            status_code=400,
        )
    if not raw_str.isdigit():
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            "Số tiền VND chỉ được chứa chữ số nguyên.",
            status_code=400,
        )
    amount = int(raw_str)
    if amount < 1 or amount > settings.MAX_AMOUNT_VND:
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            f"Số tiền VND phải nằm trong khoảng từ 1 đến {settings.MAX_AMOUNT_VND:,} VND.",
            status_code=400,
        )
    return amount


def validate_request_text_fields(
    *,
    purpose: str,
    source_kind: str,
    source_excerpt: str,
) -> tuple[str, str, str]:
    clean_purpose = (purpose or "").strip()
    if not clean_purpose:
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            "Mục đích thanh toán không được để trống.",
            status_code=400,
        )
    if len(clean_purpose) > settings.MAX_PURPOSE_LENGTH:
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            f"Mục đích thanh toán tối đa {settings.MAX_PURPOSE_LENGTH} ký tự.",
            status_code=400,
        )
    clean_kind = (source_kind or SourceKind.CHAT_MESSAGE).strip()
    if clean_kind not in SourceKind.values:
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            "Loại nguồn thông tin không hợp lệ.",
            status_code=400,
        )
    clean_excerpt = (source_excerpt or "").strip()
    if len(clean_excerpt) > settings.MAX_SOURCE_EXCERPT_LENGTH:
        raise SecurityDomainError(
            ReasonCode.VALIDATION_ERROR,
            f"Trích dẫn nguồn ngoài tối đa {settings.MAX_SOURCE_EXCERPT_LENGTH} ký tự.",
            status_code=400,
        )
    return clean_purpose, clean_kind, clean_excerpt


def _resolve_verified_beneficiary_under_lock(
    beneficiary_version_id: Any,
    *,
    actor: EmployeeIdentity,
    action: str,
    payment_request: PaymentRequest | None = None,
) -> tuple[Beneficiary, BeneficiaryVersion]:
    if not beneficiary_version_id:
        record_audit_event(
            action=action,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.BENEFICIARY_INVALID,
            actor=actor,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.BENEFICIARY_INVALID,
            "Phải chọn một phiên bản người thụ hưởng đã xác minh trong danh mục.",
            status_code=400,
        )
    try:
        ver = (
            BeneficiaryVersion.objects.select_for_update()
            .select_related("beneficiary")
            .filter(pk=beneficiary_version_id)
            .first()
        )
    except Exception:
        ver = None

    if ver is None:
        record_audit_event(
            action=action,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.BENEFICIARY_INVALID,
            actor=actor,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.BENEFICIARY_INVALID,
            "Người thụ hưởng không tồn tại trong danh mục tin cậy.",
            status_code=400,
        )

    ben = Beneficiary.objects.select_for_update().get(pk=ver.beneficiary_id)
    if (
        ben.status != BeneficiaryStatus.VERIFIED
        or ver.status != BeneficiaryStatus.VERIFIED
        or ben.active_version_id != ver.id
    ):
        record_audit_event(
            action=action,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.BENEFICIARY_INVALID,
            actor=actor,
            payment_request=payment_request,
            metadata={"beneficiary_code": ben.code, "version_status": ver.status},
        )
        raise SecurityDomainError(
            ReasonCode.BENEFICIARY_INVALID,
            "Người thụ hưởng chưa được xác minh độc lập, đã bị thu hồi hoặc phiên bản không còn hiệu lực.",
            status_code=400,
        )
    return ben, ver


def _enforce_requester_actor_under_lock(
    actor_id: Any,
    session_epoch: int | None,
    action: str,
    payment_request: PaymentRequest | None = None,
) -> EmployeeIdentity:
    actor = EmployeeIdentity.objects.select_for_update().filter(pk=actor_id).first()
    if actor is None or not actor.is_operational or session_epoch != actor.security_epoch:
        record_audit_event(
            action=action,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.PRINCIPAL_REVOKED,
            actor=actor,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.PRINCIPAL_REVOKED,
            "Phiên hoặc tài khoản đã bị thu hồi / không còn hiệu lực.",
            status_code=403,
        )
    if actor.role != Role.REQUESTER:
        record_audit_event(
            action=action,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.FORBIDDEN,
            actor=actor,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.FORBIDDEN,
            "Chỉ vai trò REQUESTER (Người lập yêu cầu) mới được thực hiện thao tác này.",
            status_code=403,
        )
    if payment_request is not None:
        if payment_request.requester_id != actor.id or payment_request.requester_person_id != actor.person_id:
            record_audit_event(
                action=action,
                result=AuditResult.DENIED,
                reason_code=ReasonCode.FORBIDDEN,
                actor=actor,
                payment_request=payment_request,
            )
            raise SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Bạn không có quyền truy cập hoặc thao tác trên yêu cầu của người khác.",
                status_code=403,
            )
    return actor


def _check_and_expire_request_under_lock(
    req: PaymentRequest,
    now,
    actor: EmployeeIdentity | None = None,
    attempted_action: str = "",
) -> None:
    if req.status not in TERMINAL_REQUEST_STATUSES and req.expires_at is not None and now >= req.expires_at:
        prev_status = req.status
        req.status = RequestStatus.EXPIRED
        req.save(update_fields=["status", "updated_at"])
        if req.current_revision_id:
            Approval.objects.filter(
                payment_revision_id=req.current_revision_id,
                status=ApprovalStatus.ACTIVE,
            ).update(status=ApprovalStatus.EXPIRED)
        ActionChallenge.objects.filter(
            payment_request=req,
            consumed_at__isnull=True,
            invalidated_at__isnull=True,
        ).update(invalidated_at=now)
        record_audit_event(
            action=attempted_action or "REQUEST_AUTO_EXPIRED",
            result=AuditResult.DENIED if attempted_action else AuditResult.SUCCESS,
            reason_code=ReasonCode.REQUEST_EXPIRED,
            actor=actor,
            payment_request=req,
            before_state=prev_status,
            after_state=RequestStatus.EXPIRED,
        )
        if attempted_action:
            raise SecurityDomainError(
                ReasonCode.REQUEST_EXPIRED,
                "Yêu cầu thanh toán đã quá thời hạn 24 giờ theo đồng hồ máy chủ.",
                status_code=409,
            )


def get_RequestForViewer(
    *,
    actor: EmployeeIdentity,
    request_id: Any,
) -> PaymentRequest:
    """
    Object-level read authorization (Section 6.1, T-08):
    - REQUESTER: only own requests.
    - DIRECTOR / CONTROLLER / SECURITY_ADMIN: within company scope (SECURITY_ADMIN gets metadata only in template/API).
    - UNPRIVILEGED: forbidden.
    """
    req = (
        PaymentRequest.objects.select_related(
            "requester",
            "current_revision",
            "current_revision__beneficiary",
            "current_revision__beneficiary_version",
        )
        .filter(pk=request_id)
        .first()
    )
    if req is None:
        raise SecurityDomainError(
            ReasonCode.FORBIDDEN,
            "Yêu cầu không tồn tại hoặc nằm ngoài phạm vi truy cập.",
            status_code=404,
        )
    if actor.role == Role.UNPRIVILEGED:
        record_audit_event(
            action="VIEW_PAYMENT_REQUEST",
            result=AuditResult.DENIED,
            reason_code=ReasonCode.FORBIDDEN,
            actor=actor,
        )
        raise SecurityDomainError(
            ReasonCode.FORBIDDEN,
            "Tài khoản không có quyền xem yêu cầu thanh toán.",
            status_code=403,
        )
    if actor.role == Role.REQUESTER and (req.requester_id != actor.id or req.requester_person_id != actor.person_id):
        record_audit_event(
            action="VIEW_PAYMENT_REQUEST",
            result=AuditResult.DENIED,
            reason_code=ReasonCode.FORBIDDEN,
            actor=actor,
            metadata={"attempted_request_code": req.request_code},
        )
        raise SecurityDomainError(
            ReasonCode.FORBIDDEN,
            "Không được phép xem yêu cầu thanh toán của người lập khác.",
            status_code=403,
        )
    return req


def create_payment_request_draft(
    *,
    actor: EmployeeIdentity,
    session_epoch: int | None,
    beneficiary_version_id: Any,
    amount_vnd: Any,
    purpose: str,
    source_kind: str,
    source_excerpt: str = "",
    raw_payload: dict[str, Any] | None = None,
    submit_immediately: bool = False,
    now=None,
) -> PaymentRequest:
    """
    Create a new PaymentRequest in DRAFT (Revision 1), and optionally submit immediately.
    """
    now = now or timezone.now()
    with security_atomic():
        acquire_security_mutex()
        actor = _enforce_requester_actor_under_lock(actor.pk, session_epoch, "CREATE_PAYMENT_REQUEST")
        assert_no_authority_fields(raw_payload, actor=actor, action="CREATE_PAYMENT_REQUEST")

        parsed_amount = validate_and_parse_amount_vnd(amount_vnd)
        clean_purpose, clean_kind, clean_excerpt = validate_request_text_fields(
            purpose=purpose,
            source_kind=source_kind,
            source_excerpt=source_excerpt,
        )
        ben, ver = _resolve_verified_beneficiary_under_lock(
            beneficiary_version_id,
            actor=actor,
            action="CREATE_PAYMENT_REQUEST",
        )

        seq = PaymentRequest.objects.count() + 1
        req_code = f"REQ-{now.strftime('%Y%m%d')}-{seq:04d}-{secrets.token_hex(2).upper()}"
        req = PaymentRequest.objects.create(
            request_code=req_code,
            requester=actor,
            requester_person_id=actor.person_id,
            status=RequestStatus.DRAFT,
        )
        rev = PaymentRevision.objects.create(
            payment_request=req,
            revision_number=1,
            amount_vnd=parsed_amount,
            currency="VND",
            beneficiary=ben,
            beneficiary_version=ver,
            beneficiary_name_snapshot=ver.vendor_name,
            bank_name_snapshot=ver.bank_name,
            account_number_snapshot=ver.account_number,
            purpose=clean_purpose,
            source_kind=clean_kind,
            source_excerpt=clean_excerpt,
            is_frozen=False,
        )
        rev.content_digest = compute_revision_digest(rev)
        rev.save(update_fields=["content_digest"])

        req.current_revision = rev
        req.save(update_fields=["current_revision", "updated_at"])

        record_audit_event(
            action="CREATE_PAYMENT_REQUEST",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            payment_request=req,
            revision_number=1,
            before_state="NONE",
            after_state=RequestStatus.DRAFT,
            metadata={
                "amount_vnd": parsed_amount,
                "beneficiary_code": ben.code,
                "beneficiary_version": ver.version_number,
            },
        )

    if submit_immediately:
        return submit_payment_request(
            actor=actor,
            session_epoch=session_epoch,
            request_id=req.id,
            now=now,
        )
    return req


def update_draft_in_place(
    *,
    actor: EmployeeIdentity,
    session_epoch: int | None,
    request_id: Any,
    beneficiary_version_id: Any,
    amount_vnd: Any,
    purpose: str,
    source_kind: str,
    source_excerpt: str = "",
    raw_payload: dict[str, Any] | None = None,
    now=None,
) -> PaymentRequest:
    """
    Edit a request ONLY while its current_revision is still an unfrozen DRAFT.
    If the request has already been submitted (`is_frozen=True` or status != DRAFT),
    direct editing is strictly rejected (`409 IMMUTABLE_REVISION`, T-19); the requester must use `revise_payment_request`.
    """
    now = now or timezone.now()
    with security_atomic():
        acquire_security_mutex()
        req = PaymentRequest.objects.select_for_update().filter(pk=request_id).first()
        if req is None:
            raise SecurityDomainError(ReasonCode.FORBIDDEN, "Không tìm thấy yêu cầu.", status_code=404)

        actor = _enforce_requester_actor_under_lock(
            actor.pk, session_epoch, "EDIT_PAYMENT_REQUEST", payment_request=req
        )
        assert_no_authority_fields(raw_payload, actor=actor, action="EDIT_PAYMENT_REQUEST", payment_request=req)

        if req.is_terminal:
            record_audit_event(
                action="EDIT_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.TERMINAL_STATE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.TERMINAL_STATE,
                "Yêu cầu đã ở trạng thái kết thúc, không thể chỉnh sửa.",
                status_code=409,
            )

        rev = PaymentRevision.objects.select_for_update().get(pk=req.current_revision_id)
        if req.status != RequestStatus.DRAFT or rev.is_frozen:
            record_audit_event(
                action="EDIT_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.IMMUTABLE_REVISION,
                actor=actor,
                payment_request=req,
                revision_number=rev.revision_number,
                before_state=req.status,
                after_state=req.status,
            )
            raise SecurityDomainError(
                ReasonCode.IMMUTABLE_REVISION,
                "Phiên bản đã gửi duyệt bị đóng băng bất biến; không thể sửa trực tiếp. Vui lòng tạo Revision mới để duyệt lại.",
                status_code=409,
            )

        parsed_amount = validate_and_parse_amount_vnd(amount_vnd)
        clean_purpose, clean_kind, clean_excerpt = validate_request_text_fields(
            purpose=purpose,
            source_kind=source_kind,
            source_excerpt=source_excerpt,
        )
        ben, ver = _resolve_verified_beneficiary_under_lock(
            beneficiary_version_id,
            actor=actor,
            action="EDIT_PAYMENT_REQUEST",
            payment_request=req,
        )

        rev.amount_vnd = parsed_amount
        rev.beneficiary = ben
        rev.beneficiary_version = ver
        rev.beneficiary_name_snapshot = ver.vendor_name
        rev.bank_name_snapshot = ver.bank_name
        rev.account_number_snapshot = ver.account_number
        rev.purpose = clean_purpose
        rev.source_kind = clean_kind
        rev.source_excerpt = clean_excerpt
        rev.content_digest = compute_revision_digest(rev)
        rev.save()

        record_audit_event(
            action="EDIT_DRAFT_REQUEST",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            payment_request=req,
            revision_number=rev.revision_number,
            before_state=RequestStatus.DRAFT,
            after_state=RequestStatus.DRAFT,
        )
        return req


def submit_payment_request(
    *,
    actor: EmployeeIdentity,
    session_epoch: int | None,
    request_id: Any,
    now=None,
) -> PaymentRequest:
    """
    Freeze the current DRAFT revision, compute its SHA-256 content_digest, set 24h expiry,
    and transition DRAFT -> PENDING_APPROVAL (Section 7.3).
    """
    now = now or timezone.now()
    with security_atomic():
        acquire_security_mutex()
        req = PaymentRequest.objects.select_for_update().filter(pk=request_id).first()
        if req is None:
            raise SecurityDomainError(ReasonCode.FORBIDDEN, "Không tìm thấy yêu cầu.", status_code=404)

        actor = _enforce_requester_actor_under_lock(
            actor.pk, session_epoch, "SUBMIT_PAYMENT_REQUEST", payment_request=req
        )
        if req.is_terminal:
            record_audit_event(
                action="SUBMIT_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.TERMINAL_STATE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.TERMINAL_STATE,
                "Yêu cầu đã ở trạng thái kết thúc.",
                status_code=409,
            )
        if req.status != RequestStatus.DRAFT:
            record_audit_event(
                action="SUBMIT_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.WRONG_SCOPE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.WRONG_SCOPE,
                "Chỉ bản nháp (DRAFT) mới có thể gửi duyệt.",
                status_code=409,
            )

        rev = PaymentRevision.objects.select_for_update().get(pk=req.current_revision_id)
        ben, ver = _resolve_verified_beneficiary_under_lock(
            rev.beneficiary_version_id,
            actor=actor,
            action="SUBMIT_PAYMENT_REQUEST",
            payment_request=req,
        )

        rev.beneficiary_name_snapshot = ver.vendor_name
        rev.bank_name_snapshot = ver.bank_name
        rev.account_number_snapshot = ver.account_number
        rev.content_digest = compute_revision_digest(rev)
        rev.is_frozen = True
        rev.frozen_at = now
        rev.save()

        req.status = RequestStatus.PENDING_APPROVAL
        req.hold_reason = ""
        req.submitted_at = now
        req.expires_at = now + timedelta(hours=settings.REQUEST_TTL_HOURS)
        req.save()

        record_audit_event(
            action="SUBMIT_PAYMENT_REQUEST",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            payment_request=req,
            revision_number=rev.revision_number,
            before_state=RequestStatus.DRAFT,
            after_state=RequestStatus.PENDING_APPROVAL,
            metadata={
                "content_digest": rev.content_digest,
                "expires_at": req.expires_at.isoformat(),
            },
        )
        return req


def revise_payment_request(
    *,
    actor: EmployeeIdentity,
    session_epoch: int | None,
    request_id: Any,
    beneficiary_version_id: Any,
    amount_vnd: Any,
    purpose: str,
    source_kind: str,
    source_excerpt: str = "",
    raw_payload: dict[str, Any] | None = None,
    submit_immediately: bool = False,
    now=None,
) -> PaymentRequest:
    """
    Create a new revision (N+1) in DRAFT, supersede all prior Approvals (`SUPERSEDED_BY_REVISION`),
    and invalidate all prior open ActionChallenges (Section 6.3, 7.3, T-20, T-32).
    """
    now = now or timezone.now()
    with security_atomic():
        acquire_security_mutex()
        req = PaymentRequest.objects.select_for_update().filter(pk=request_id).first()
        if req is None:
            raise SecurityDomainError(ReasonCode.FORBIDDEN, "Không tìm thấy yêu cầu.", status_code=404)

        actor = _enforce_requester_actor_under_lock(
            actor.pk, session_epoch, "REVISE_PAYMENT_REQUEST", payment_request=req
        )
        assert_no_authority_fields(raw_payload, actor=actor, action="REVISE_PAYMENT_REQUEST", payment_request=req)

        _check_and_expire_request_under_lock(req, now, actor=actor, attempted_action="REVISE_PAYMENT_REQUEST")
        if req.is_terminal:
            record_audit_event(
                action="REVISE_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.TERMINAL_STATE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.TERMINAL_STATE,
                "Yêu cầu đã ở trạng thái kết thúc, không thể tạo phiên bản mới.",
                status_code=409,
            )

        parsed_amount = validate_and_parse_amount_vnd(amount_vnd)
        clean_purpose, clean_kind, clean_excerpt = validate_request_text_fields(
            purpose=purpose,
            source_kind=source_kind,
            source_excerpt=source_excerpt,
        )
        ben, ver = _resolve_verified_beneficiary_under_lock(
            beneficiary_version_id,
            actor=actor,
            action="REVISE_PAYMENT_REQUEST",
            payment_request=req,
        )

        old_rev = PaymentRevision.objects.select_for_update().get(pk=req.current_revision_id)
        next_rev_num = old_rev.revision_number + 1
        prev_status = req.status

        # Invalidate all prior ACTIVE approvals and open challenges across the request
        Approval.objects.filter(
            payment_request=req,
            status=ApprovalStatus.ACTIVE,
        ).update(status=ApprovalStatus.SUPERSEDED_BY_REVISION)

        ActionChallenge.objects.filter(
            payment_request=req,
            consumed_at__isnull=True,
            invalidated_at__isnull=True,
        ).update(invalidated_at=now)

        new_rev = PaymentRevision.objects.create(
            payment_request=req,
            revision_number=next_rev_num,
            amount_vnd=parsed_amount,
            currency="VND",
            beneficiary=ben,
            beneficiary_version=ver,
            beneficiary_name_snapshot=ver.vendor_name,
            bank_name_snapshot=ver.bank_name,
            account_number_snapshot=ver.account_number,
            purpose=clean_purpose,
            source_kind=clean_kind,
            source_excerpt=clean_excerpt,
            is_frozen=False,
        )
        new_rev.content_digest = compute_revision_digest(new_rev)
        new_rev.save(update_fields=["content_digest"])

        req.current_revision = new_rev
        req.status = RequestStatus.DRAFT
        req.hold_reason = ""
        req.submitted_at = None
        req.expires_at = None
        req.save()

        record_audit_event(
            action="REVISE_PAYMENT_REQUEST",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            payment_request=req,
            revision_number=next_rev_num,
            before_state=f"{prev_status}:Rev#{old_rev.revision_number}",
            after_state=f"{RequestStatus.DRAFT}:Rev#{next_rev_num}",
            metadata={
                "old_revision": old_rev.revision_number,
                "new_revision": next_rev_num,
                "new_amount_vnd": parsed_amount,
                "beneficiary_code": ben.code,
            },
        )

    if submit_immediately:
        return submit_payment_request(
            actor=actor,
            session_epoch=session_epoch,
            request_id=req.id,
            now=now,
        )
    return req


def cancel_payment_request(
    *,
    actor: EmployeeIdentity,
    session_epoch: int | None,
    request_id: Any,
    now=None,
) -> PaymentRequest:
    """
    Requester cancels their own non-terminal payment request (Section 7.3, T-04).
    """
    now = now or timezone.now()
    with security_atomic():
        acquire_security_mutex()
        req = PaymentRequest.objects.select_for_update().filter(pk=request_id).first()
        if req is None:
            raise SecurityDomainError(ReasonCode.FORBIDDEN, "Không tìm thấy yêu cầu.", status_code=404)

        actor = _enforce_requester_actor_under_lock(
            actor.pk, session_epoch, "CANCEL_PAYMENT_REQUEST", payment_request=req
        )
        _check_and_expire_request_under_lock(req, now, actor=actor, attempted_action="CANCEL_PAYMENT_REQUEST")

        if req.is_terminal:
            record_audit_event(
                action="CANCEL_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.TERMINAL_STATE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.TERMINAL_STATE,
                "Yêu cầu đã ở trạng thái kết thúc, không thể hủy.",
                status_code=409,
            )

        prev_status = req.status
        req.status = RequestStatus.CANCELLED
        req.save(update_fields=["status", "updated_at"])

        Approval.objects.filter(
            payment_request=req,
            status=ApprovalStatus.ACTIVE,
        ).update(status=ApprovalStatus.INVALIDATED_BY_INCIDENT)
        ActionChallenge.objects.filter(
            payment_request=req,
            consumed_at__isnull=True,
            invalidated_at__isnull=True,
        ).update(invalidated_at=now)

        record_audit_event(
            action="CANCEL_PAYMENT_REQUEST",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            payment_request=req,
            before_state=prev_status,
            after_state=RequestStatus.CANCELLED,
        )
        return req


def issue_payment_challenge(
    *,
    actor: EmployeeIdentity,
    session_key: str,
    session_epoch: int | None,
    request_id: Any,
    action: str,
    reason: str = "",
    now=None,
) -> ActionChallenge:
    """
    Server issues an ActionChallenge (TTL 120s) bound to actor, person_id, session, TOTP device,
    security_epoch, action, request, revision, content_digest, and beneficiary_version (DES-05, Section 7.4).
    """
    now = now or timezone.now()
    with security_atomic():
        acquire_security_mutex()
        actor = EmployeeIdentity.objects.select_for_update().filter(pk=actor.pk).first()
        req = PaymentRequest.objects.select_for_update().filter(pk=request_id).first()
        if req is None:
            raise SecurityDomainError(ReasonCode.FORBIDDEN, "Không tìm thấy yêu cầu.", status_code=404)

        if actor is None or not actor.is_operational or session_epoch != actor.security_epoch:
            record_audit_event(
                action="ISSUE_PAYMENT_CHALLENGE",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Tài khoản hoặc phiên đã bị thu hồi.",
                status_code=403,
            )

        _check_and_expire_request_under_lock(req, now, actor=actor, attempted_action="ISSUE_PAYMENT_CHALLENGE")

        if req.is_terminal:
            record_audit_event(
                action="ISSUE_PAYMENT_CHALLENGE",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.TERMINAL_STATE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.TERMINAL_STATE,
                "Yêu cầu đã ở trạng thái kết thúc.",
                status_code=409,
            )

        rev = PaymentRevision.objects.select_for_update().get(pk=req.current_revision_id)
        if not rev.is_frozen or rev.content_digest != compute_revision_digest(rev):
            record_audit_event(
                action="ISSUE_PAYMENT_CHALLENGE",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.SNAPSHOT_MISMATCH,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.SNAPSHOT_MISMATCH,
                "Phiên bản yêu cầu chưa được đóng băng hoặc nội dung không khớp.",
                status_code=409,
            )

        # Role & separation-of-duty checks before issuing a challenge
        if action in (ChallengeAction.APPROVE_DIRECTOR, ChallengeAction.APPROVE_CONTROLLER, ChallengeAction.REJECT):
            if actor.role not in (Role.DIRECTOR, Role.CONTROLLER):
                record_audit_event(
                    action="ISSUE_PAYMENT_CHALLENGE",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.FORBIDDEN,
                    actor=actor,
                    payment_request=req,
                )
                raise SecurityDomainError(
                    ReasonCode.FORBIDDEN,
                    "Tài khoản không có vai trò phê duyệt (DIRECTOR / CONTROLLER).",
                    status_code=403,
                )
            if actor.id == req.requester_id or actor.person_id == req.requester_person_id:
                record_audit_event(
                    action="ISSUE_PAYMENT_CHALLENGE",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.SELF_APPROVAL,
                    actor=actor,
                    payment_request=req,
                )
                raise SecurityDomainError(
                    ReasonCode.SELF_APPROVAL,
                    "Người lập yêu cầu không được tự phê duyệt yêu cầu của chính mình.",
                    status_code=403,
                )
            if action == ChallengeAction.APPROVE_DIRECTOR and actor.role != Role.DIRECTOR:
                record_audit_event(
                    action="ISSUE_PAYMENT_CHALLENGE",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.FORBIDDEN,
                    actor=actor,
                    payment_request=req,
                )
                raise SecurityDomainError(
                    ReasonCode.FORBIDDEN,
                    "Chỉ vai trò DIRECTOR mới được cấp challenge cho slot DIRECTOR.",
                    status_code=403,
                )
            if action == ChallengeAction.APPROVE_CONTROLLER and actor.role != Role.CONTROLLER:
                record_audit_event(
                    action="ISSUE_PAYMENT_CHALLENGE",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.FORBIDDEN,
                    actor=actor,
                    payment_request=req,
                )
                raise SecurityDomainError(
                    ReasonCode.FORBIDDEN,
                    "Chỉ vai trò CONTROLLER mới được cấp challenge cho slot CONTROLLER.",
                    status_code=403,
                )
            if action in (ChallengeAction.APPROVE_DIRECTOR, ChallengeAction.APPROVE_CONTROLLER):
                if req.status != RequestStatus.PENDING_APPROVAL:
                    raise SecurityDomainError(
                        ReasonCode.WRONG_SCOPE,
                        "Yêu cầu không ở trạng thái đang chờ phê duyệt.",
                        status_code=409,
                    )
            if action == ChallengeAction.REJECT:
                if req.status not in (RequestStatus.PENDING_APPROVAL, RequestStatus.APPROVED):
                    raise SecurityDomainError(
                        ReasonCode.WRONG_SCOPE,
                        "Yêu cầu không ở trạng thái có thể từ chối.",
                        status_code=409,
                    )
        elif action == ChallengeAction.EXECUTE:
            if actor.role != Role.REQUESTER or req.requester_id != actor.id or req.requester_person_id != actor.person_id:
                record_audit_event(
                    action="ISSUE_PAYMENT_CHALLENGE",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.FORBIDDEN,
                    actor=actor,
                    payment_request=req,
                )
                raise SecurityDomainError(
                    ReasonCode.FORBIDDEN,
                    "Chỉ chính REQUESTER đã lập yêu cầu mới được cấp challenge thực thi mô phỏng.",
                    status_code=403,
                )
            if req.status != RequestStatus.APPROVED:
                record_audit_event(
                    action="ISSUE_PAYMENT_CHALLENGE",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.MISSING_APPROVAL,
                    actor=actor,
                    payment_request=req,
                )
                raise SecurityDomainError(
                    ReasonCode.MISSING_APPROVAL,
                    "Yêu cầu chưa có đủ 2 phê duyệt độc lập còn hiệu lực.",
                    status_code=409,
                )
        else:
            raise SecurityDomainError(
                ReasonCode.WRONG_SCOPE,
                "Loại challenge không hợp lệ cho yêu cầu thanh toán.",
                status_code=400,
            )

        device = get_confirmed_totp_device(actor, for_update=True)
        challenge = ActionChallenge.objects.create(
            nonce=secrets.token_urlsafe(32),
            actor=actor,
            actor_person_id=actor.person_id,
            session_key_hash=sha256_hex(session_key),
            device_id=device.id,
            actor_epoch=actor.security_epoch,
            action=action,
            target_type=ChallengeTargetType.PAYMENT_REQUEST,
            payment_request=req,
            payment_revision=rev,
            content_digest=rev.content_digest,
            beneficiary_version_id=rev.beneficiary_version_id,
            reason_text=(reason or "").strip()[:500],
            created_at=now,
            expires_at=now + timedelta(seconds=settings.CHALLENGE_TTL_SECONDS),
        )

        record_audit_event(
            action="ISSUE_PAYMENT_CHALLENGE",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            payment_request=req,
            revision_number=rev.revision_number,
            metadata={"challenge_id": str(challenge.id), "challenge_action": action},
        )
        return challenge


def _validate_and_consume_payment_challenge_under_lock(
    *,
    challenge_id: Any,
    nonce: str,
    actor: EmployeeIdentity,
    session_key: str,
    expected_actions: tuple[str, ...],
    payment_request: PaymentRequest,
    payment_revision: PaymentRevision,
    otp_token: str,
    now,
    audit_action_label: str,
) -> ActionChallenge:
    challenge = ActionChallenge.objects.select_for_update().filter(pk=challenge_id).first()
    if challenge is None or challenge.nonce != (nonce or "").strip():
        record_audit_event(
            action=audit_action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.WRONG_SCOPE,
            actor=actor,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.WRONG_SCOPE,
            "Challenge không tồn tại hoặc mã nonce không khớp.",
            status_code=400,
        )

    # Check actor / person / session binding first (T-16)
    if (
        challenge.actor_id != actor.id
        or challenge.actor_person_id != actor.person_id
        or challenge.session_key_hash != sha256_hex(session_key)
    ):
        record_audit_event(
            action=audit_action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.WRONG_SCOPE,
            actor=actor,
            payment_request=payment_request,
            metadata={"challenge_owner_person_id": challenge.actor_person_id},
        )
        raise SecurityDomainError(
            ReasonCode.WRONG_SCOPE,
            "Challenge thuộc về người dùng hoặc phiên làm việc khác, không được phép sử dụng chéo.",
            status_code=403,
        )

    if challenge.actor_epoch != actor.security_epoch:
        record_audit_event(
            action=audit_action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.PRINCIPAL_REVOKED,
            actor=actor,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.PRINCIPAL_REVOKED,
            "Trạng thái bảo mật (security_epoch) của người thực hiện đã thay đổi sau khi cấp challenge.",
            status_code=409,
        )

    # Check target / request / revision / action / digest / beneficiary_version scope (T-17, T-20)
    if (
        challenge.target_type != ChallengeTargetType.PAYMENT_REQUEST
        or challenge.action not in expected_actions
        or challenge.payment_request_id != payment_request.id
        or challenge.payment_revision_id != payment_revision.id
        or challenge.content_digest != payment_revision.content_digest
        or challenge.beneficiary_version_id != payment_revision.beneficiary_version_id
    ):
        record_audit_event(
            action=audit_action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.WRONG_SCOPE,
            actor=actor,
            payment_request=payment_request,
            metadata={
                "challenge_action": challenge.action,
                "expected_actions": list(expected_actions),
                "challenge_request_id": str(challenge.payment_request_id),
                "challenge_revision_id": str(challenge.payment_revision_id),
            },
        )
        raise SecurityDomainError(
            ReasonCode.WRONG_SCOPE,
            "Challenge không khớp yêu cầu, phiên bản (revision), nội dung đóng băng hoặc loại hành động.",
            status_code=409,
        )

    # Check one-time consumption / invalidation (T-22, T-20)
    if challenge.consumed_at is not None or challenge.invalidated_at is not None:
        record_audit_event(
            action=audit_action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.CHALLENGE_USED,
            actor=actor,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.CHALLENGE_USED,
            "Challenge đã được sử dụng hoặc đã mất hiệu lực.",
            status_code=409,
        )

    # Check server UTC expiry boundary `now >= expires_at` (Section 3.1, T-21)
    if now >= challenge.expires_at:
        record_audit_event(
            action=audit_action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.CHALLENGE_EXPIRED,
            actor=actor,
            payment_request=payment_request,
            metadata={
                "server_now": now.isoformat(),
                "expires_at": challenge.expires_at.isoformat(),
            },
        )
        raise SecurityDomainError(
            ReasonCode.CHALLENGE_EXPIRED,
            "Challenge xác nhận đã hết hạn 120 giây theo giờ máy chủ.",
            status_code=409,
        )

    # Verify fresh TOTP token on confirmed device (with anti-replay last_t)
    device = verify_totp_token_under_lock(
        user=actor,
        raw_token=otp_token,
        now=now,
        action_label=audit_action_label,
        payment_request=payment_request,
    )
    if device.id != challenge.device_id:
        record_audit_event(
            action=audit_action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.PRINCIPAL_REVOKED,
            actor=actor,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.PRINCIPAL_REVOKED,
            "Thiết bị MFA đã thay đổi so với thời điểm cấp challenge.",
            status_code=409,
        )

    challenge.consumed_at = now
    challenge.save(update_fields=["consumed_at"])
    return challenge


def approve_payment_request(
    *,
    actor: EmployeeIdentity,
    session_key: str,
    session_epoch: int | None,
    request_id: Any,
    challenge_id: Any,
    nonce: str,
    otp_token: str,
    raw_payload: dict[str, Any] | None = None,
    now=None,
) -> Approval:
    """
    Record an independent approval for DIRECTOR or CONTROLLER slot (Section 7.4).
    """
    now = now or timezone.now()
    with security_atomic():
        acquire_security_mutex()
        actor = EmployeeIdentity.objects.select_for_update().filter(pk=actor.pk).first()
        req = (
            PaymentRequest.objects.select_for_update()
            .filter(pk=request_id)
            .first()
        )
        if req is None:
            raise SecurityDomainError(ReasonCode.FORBIDDEN, "Không tìm thấy yêu cầu.", status_code=404)

        assert_no_authority_fields(raw_payload, actor=actor, action="APPROVE_PAYMENT_REQUEST", payment_request=req)

        if actor is None or not actor.is_operational or session_epoch != actor.security_epoch:
            record_audit_event(
                action="APPROVE_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Tài khoản hoặc phiên của người duyệt đã bị thu hồi.",
                status_code=403,
            )

        if actor.role not in (Role.DIRECTOR, Role.CONTROLLER):
            record_audit_event(
                action="APPROVE_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.FORBIDDEN,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Tài khoản không có quyền phê duyệt yêu cầu thanh toán.",
                status_code=403,
            )

        if actor.id == req.requester_id or actor.person_id == req.requester_person_id:
            record_audit_event(
                action="APPROVE_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.SELF_APPROVAL,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.SELF_APPROVAL,
                "Không được phép tự phê duyệt yêu cầu do chính mình lập.",
                status_code=403,
            )

        _check_and_expire_request_under_lock(req, now, actor=actor, attempted_action="APPROVE_PAYMENT_REQUEST")

        if req.is_terminal:
            record_audit_event(
                action="APPROVE_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.TERMINAL_STATE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.TERMINAL_STATE,
                "Yêu cầu đã ở trạng thái kết thúc, không thể phê duyệt.",
                status_code=409,
            )

        if req.status != RequestStatus.PENDING_APPROVAL:
            record_audit_event(
                action="APPROVE_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.WRONG_SCOPE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.WRONG_SCOPE,
                "Yêu cầu không ở trạng thái đang chờ phê duyệt.",
                status_code=409,
            )

        requester = EmployeeIdentity.objects.select_for_update().get(pk=req.requester_id)
        if not requester.is_operational:
            req.status = RequestStatus.HOLD
            req.hold_reason = "Người lập yêu cầu đang bị đình chỉ."
            req.save(update_fields=["status", "hold_reason", "updated_at"])
            record_audit_event(
                action="APPROVE_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Người lập yêu cầu đã bị đình chỉ, yêu cầu chuyển sang trạng thái HOLD.",
                status_code=409,
            )

        rev = PaymentRevision.objects.select_for_update().get(pk=req.current_revision_id)
        if not rev.is_frozen or rev.content_digest != compute_revision_digest(rev):
            record_audit_event(
                action="APPROVE_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.SNAPSHOT_MISMATCH,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.SNAPSHOT_MISMATCH,
                "Bản chụp nội dung không hợp lệ hoặc chưa đóng băng.",
                status_code=409,
            )

        _resolve_verified_beneficiary_under_lock(
            rev.beneficiary_version_id,
            actor=actor,
            action="APPROVE_PAYMENT_REQUEST",
            payment_request=req,
        )

        slot = ApprovalSlot.DIRECTOR if actor.role == Role.DIRECTOR else ApprovalSlot.CONTROLLER
        expected_action = (
            ChallengeAction.APPROVE_DIRECTOR
            if slot == ApprovalSlot.DIRECTOR
            else ChallengeAction.APPROVE_CONTROLLER
        )

        # Check existing approvals on this revision for duplicate slot or duplicate person_id (T-07, T-12)
        existing_approvals = list(Approval.objects.select_for_update().filter(payment_revision=rev))
        for existing in existing_approvals:
            if existing.approver_id == actor.id or existing.approver_person_id == actor.person_id:
                record_audit_event(
                    action="APPROVE_PAYMENT_REQUEST",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.DUPLICATE_APPROVER,
                    actor=actor,
                    payment_request=req,
                )
                raise SecurityDomainError(
                    ReasonCode.DUPLICATE_APPROVER,
                    "Một cá nhân (person_id) không được phép phê duyệt hai lần hoặc chiếm cả hai vị trí duyệt.",
                    status_code=409,
                )
            if existing.slot == slot:
                record_audit_event(
                    action="APPROVE_PAYMENT_REQUEST",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.DUPLICATE_APPROVER,
                    actor=actor,
                    payment_request=req,
                )
                raise SecurityDomainError(
                    ReasonCode.DUPLICATE_APPROVER,
                    f"Vị trí duyệt {slot} đã được phê duyệt trên phiên bản này.",
                    status_code=409,
                )

        challenge = _validate_and_consume_payment_challenge_under_lock(
            challenge_id=challenge_id,
            nonce=nonce,
            actor=actor,
            session_key=session_key,
            expected_actions=(expected_action,),
            payment_request=req,
            payment_revision=rev,
            otp_token=otp_token,
            now=now,
            audit_action_label="APPROVE_PAYMENT_REQUEST",
        )

        approval = Approval.objects.create(
            payment_request=req,
            payment_revision=rev,
            approver=actor,
            approver_person_id=actor.person_id,
            slot=slot,
            content_digest=rev.content_digest,
            beneficiary_version_id=rev.beneficiary_version_id,
            approver_epoch_at_signing=actor.security_epoch,
            requester_epoch_at_signing=requester.security_epoch,
            challenge=challenge,
            status=ApprovalStatus.ACTIVE,
            created_at=now,
            expires_at=req.expires_at or (now + timedelta(hours=settings.REQUEST_TTL_HOURS)),
        )

        # Check if both slots (DIRECTOR & CONTROLLER) are now validly filled by distinct operational people
        active_approvals = list(
            Approval.objects.select_related("approver").filter(
                payment_revision=rev,
                status=ApprovalStatus.ACTIVE,
            )
        )
        slots_map = {a.slot: a for a in active_approvals}
        before_state = req.status
        if ApprovalSlot.DIRECTOR in slots_map and ApprovalSlot.CONTROLLER in slots_map:
            a_dir = slots_map[ApprovalSlot.DIRECTOR]
            a_ctl = slots_map[ApprovalSlot.CONTROLLER]
            if (
                a_dir.approver_person_id != a_ctl.approver_person_id
                and a_dir.approver_person_id != req.requester_person_id
                and a_ctl.approver_person_id != req.requester_person_id
                and a_dir.approver.is_operational
                and a_ctl.approver.is_operational
                and a_dir.approver.security_epoch == a_dir.approver_epoch_at_signing
                and a_ctl.approver.security_epoch == a_ctl.approver_epoch_at_signing
            ):
                req.status = RequestStatus.APPROVED
                req.save(update_fields=["status", "updated_at"])

        record_audit_event(
            action="APPROVE_PAYMENT_REQUEST",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            payment_request=req,
            revision_number=rev.revision_number,
            before_state=before_state,
            after_state=req.status,
            metadata={
                "slot": slot,
                "approval_id": str(approval.id),
                "content_digest": rev.content_digest,
            },
        )
        return approval


def reject_payment_request(
    *,
    actor: EmployeeIdentity,
    session_key: str,
    session_epoch: int | None,
    request_id: Any,
    challenge_id: Any,
    nonce: str,
    otp_token: str,
    reason: str,
    now=None,
) -> PaymentRequest:
    """
    Approver (DIRECTOR or CONTROLLER) rejects a request before execution (Section 7.3, T-03, T-33).
    REJECTED is a terminal state.
    """
    now = now or timezone.now()
    clean_reason = (reason or "").strip()

    with security_atomic():
        acquire_security_mutex()
        actor = EmployeeIdentity.objects.select_for_update().filter(pk=actor.pk).first()
        req = PaymentRequest.objects.select_for_update().filter(pk=request_id).first()
        if req is None:
            raise SecurityDomainError(ReasonCode.FORBIDDEN, "Không tìm thấy yêu cầu.", status_code=404)

        if actor is None or not actor.is_operational or session_epoch != actor.security_epoch:
            record_audit_event(
                action="REJECT_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Tài khoản hoặc phiên của người duyệt đã bị thu hồi.",
                status_code=403,
            )

        if actor.role not in (Role.DIRECTOR, Role.CONTROLLER):
            record_audit_event(
                action="REJECT_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.FORBIDDEN,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Chỉ DIRECTOR hoặc CONTROLLER mới có quyền từ chối yêu cầu.",
                status_code=403,
            )

        if actor.id == req.requester_id or actor.person_id == req.requester_person_id:
            raise SecurityDomainError(
                ReasonCode.SELF_APPROVAL,
                "Người lập không thể đóng vai người duyệt trên yêu cầu của mình.",
                status_code=403,
            )

        if not clean_reason:
            raise SecurityDomainError(
                ReasonCode.VALIDATION_ERROR,
                "Bắt buộc nhập lý do từ chối yêu cầu thanh toán.",
                status_code=400,
            )

        _check_and_expire_request_under_lock(req, now, actor=actor, attempted_action="REJECT_PAYMENT_REQUEST")

        if req.is_terminal:
            record_audit_event(
                action="REJECT_PAYMENT_REQUEST",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.TERMINAL_STATE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.TERMINAL_STATE,
                "Yêu cầu đã ở trạng thái kết thúc.",
                status_code=409,
            )

        if req.status not in (RequestStatus.PENDING_APPROVAL, RequestStatus.APPROVED):
            raise SecurityDomainError(
                ReasonCode.WRONG_SCOPE,
                "Yêu cầu không ở trạng thái có thể từ chối.",
                status_code=409,
            )

        rev = PaymentRevision.objects.select_for_update().get(pk=req.current_revision_id)
        _validate_and_consume_payment_challenge_under_lock(
            challenge_id=challenge_id,
            nonce=nonce,
            actor=actor,
            session_key=session_key,
            expected_actions=(ChallengeAction.REJECT,),
            payment_request=req,
            payment_revision=rev,
            otp_token=otp_token,
            now=now,
            audit_action_label="REJECT_PAYMENT_REQUEST",
        )

        prev_status = req.status
        req.status = RequestStatus.REJECTED
        req.rejection_reason = clean_reason[:500]
        req.save(update_fields=["status", "rejection_reason", "updated_at"])

        # Invalidate open challenges and mark any prior approvals as no longer active
        Approval.objects.filter(
            payment_request=req,
            status=ApprovalStatus.ACTIVE,
        ).update(status=ApprovalStatus.INVALIDATED_BY_INCIDENT)
        ActionChallenge.objects.filter(
            payment_request=req,
            consumed_at__isnull=True,
            invalidated_at__isnull=True,
        ).update(invalidated_at=now)

        record_audit_event(
            action="REJECT_PAYMENT_REQUEST",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            payment_request=req,
            revision_number=rev.revision_number,
            before_state=prev_status,
            after_state=RequestStatus.REJECTED,
            metadata={"rejection_reason": clean_reason[:500]},
        )
        return req


def execute_payment_request_simulated(
    *,
    actor: EmployeeIdentity,
    session_key: str,
    session_epoch: int | None,
    request_id: Any,
    challenge_id: Any | None = None,
    nonce: str = "",
    otp_token: str = "",
    idempotency_key: str = "",
    raw_payload: dict[str, Any] | None = None,
    fault_injector: Callable[[], None] | None = None,
    now=None,
) -> tuple[PaymentExecution, bool]:
    """
    Final Gate and Atomic Simulated Execution (DES-03, DES-08, Section 7.5).
    Returns `(PaymentExecution, is_idempotent_replay)`.
    - Acquires `SecurityMutex(id=1)` inside `transaction.atomic()`.
    - If `PaymentExecution` already exists for this request:
      - If same authorized requester, same `idempotency_key`, and same `payload_fingerprint`:
        records `IDEMPOTENT_REPLAY` audit and returns existing receipt without requiring new execution effect.
      - Otherwise denies with `409 IDEMPOTENCY_CONFLICT` / `TERMINAL_STATE`.
    - Validates requester ownership, active status, epoch, request expiry, frozen revision digest,
      active verified beneficiary version, both independent approvals (DIRECTOR & CONTROLLER),
      approvers' current active status/role/epoch, and fresh EXECUTE challenge + TOTP.
    - Commits `PaymentExecution`, `EXECUTED_SIMULATED`, and `AuditEvent` in the same transaction.
    """
    now = now or timezone.now()
    clean_idem_key = (idempotency_key or "").strip()

    with security_atomic():
        acquire_security_mutex()
        actor = EmployeeIdentity.objects.select_for_update().filter(pk=actor.pk).first()
        req = (
            PaymentRequest.objects.select_for_update()
            .filter(pk=request_id)
            .first()
        )
        if req is None:
            raise SecurityDomainError(ReasonCode.FORBIDDEN, "Không tìm thấy yêu cầu.", status_code=404)

        assert_no_authority_fields(raw_payload, actor=actor, action="EXECUTE_PAYMENT_SIMULATED", payment_request=req)

        if actor is None or not actor.is_operational or session_epoch != actor.security_epoch:
            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Phiên hoặc tài khoản của người thực hiện đã bị thu hồi.",
                status_code=403,
            )

        if actor.role != Role.REQUESTER or req.requester_id != actor.id or req.requester_person_id != actor.person_id:
            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.FORBIDDEN,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Chỉ chính REQUESTER đã lập yêu cầu mới có quyền thực thi mô phỏng yêu cầu của mình.",
                status_code=403,
            )

        if not clean_idem_key or len(clean_idem_key) > 128:
            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.VALIDATION_ERROR,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.VALIDATION_ERROR,
                "Bắt buộc cung cấp Idempotency-Key hợp lệ khi thực thi mô phỏng.",
                status_code=400,
            )

        rev = PaymentRevision.objects.select_for_update().get(pk=req.current_revision_id)
        fingerprint = compute_execution_payload_fingerprint(
            request_id=req.id,
            revision_id=rev.id,
            content_digest=rev.content_digest,
        )

        # Check if PaymentExecution already exists for this request (Section 7.5, T-29, T-30, T-31)
        existing_exec = PaymentExecution.objects.select_for_update().filter(payment_request=req).first()
        if existing_exec is not None:
            if (
                existing_exec.executor_id == actor.id
                and existing_exec.idempotency_key == clean_idem_key
                and existing_exec.payload_fingerprint == fingerprint
            ):
                record_audit_event(
                    action="EXECUTE_PAYMENT_SIMULATED",
                    result=AuditResult.SUCCESS,
                    reason_code=ReasonCode.IDEMPOTENT_REPLAY,
                    actor=actor,
                    payment_request=req,
                    revision_number=rev.revision_number,
                    before_state=req.status,
                    after_state=req.status,
                    metadata={
                        "receipt_id": existing_exec.receipt_id,
                        "idempotency_key": clean_idem_key,
                    },
                )
                return existing_exec, True

            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.IDEMPOTENCY_CONFLICT,
                actor=actor,
                payment_request=req,
                revision_number=rev.revision_number,
                metadata={"attempted_idempotency_key": clean_idem_key},
            )
            raise SecurityDomainError(
                ReasonCode.IDEMPOTENCY_CONFLICT,
                "Yêu cầu thanh toán này đã được thực thi mô phỏng trước đó; không thể thực thi lần thứ hai.",
                status_code=409,
            )

        # Check terminal states / HOLD / expiry
        _check_and_expire_request_under_lock(req, now, actor=actor, attempted_action="EXECUTE_PAYMENT_SIMULATED")

        if req.status == RequestStatus.HOLD:
            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=actor,
                payment_request=req,
                metadata={"hold_reason": req.hold_reason},
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                f"Yêu cầu đang bị tạm giữ (HOLD) để kiểm tra an ninh: {req.hold_reason}",
                status_code=409,
            )

        if req.is_terminal:
            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.TERMINAL_STATE,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.TERMINAL_STATE,
                "Yêu cầu đã ở trạng thái kết thúc, không thể thực thi.",
                status_code=409,
            )

        # Verify immutable snapshot & digest
        expected_digest = compute_revision_digest(rev)
        if not rev.is_frozen or rev.content_digest != expected_digest:
            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.SNAPSHOT_MISMATCH,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.SNAPSHOT_MISMATCH,
                "Phát hiện sai lệch mã băm nội dung đóng băng (SNAPSHOT_MISMATCH).",
                status_code=409,
            )

        # Verify beneficiary is still VERIFIED and at the exact same active_version (T-28)
        ben, ver = _resolve_verified_beneficiary_under_lock(
            rev.beneficiary_version_id,
            actor=actor,
            action="EXECUTE_PAYMENT_SIMULATED",
            payment_request=req,
        )

        # Final Gate: Re-validate both independent approvals (DIRECTOR & CONTROLLER) from DB (T-02, T-12, T-24, T-25, T-26, T-27)
        active_approvals = list(
            Approval.objects.select_for_update()
            .select_related("approver")
            .filter(payment_revision=rev, status=ApprovalStatus.ACTIVE)
        )
        slots_map = {a.slot: a for a in active_approvals}
        if ApprovalSlot.DIRECTOR not in slots_map or ApprovalSlot.CONTROLLER not in slots_map:
            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.MISSING_APPROVAL,
                actor=actor,
                payment_request=req,
                metadata={"active_slots": list(slots_map.keys())},
            )
            raise SecurityDomainError(
                ReasonCode.MISSING_APPROVAL,
                "Chưa đủ 2 phê duyệt độc lập (DIRECTOR và CONTROLLER) còn hiệu lực cho phiên bản hiện hành.",
                status_code=409,
            )

        a_dir = slots_map[ApprovalSlot.DIRECTOR]
        a_ctl = slots_map[ApprovalSlot.CONTROLLER]
        u_dir = EmployeeIdentity.objects.select_for_update().get(pk=a_dir.approver_id)
        u_ctl = EmployeeIdentity.objects.select_for_update().get(pk=a_ctl.approver_id)

        # Check distinct people
        if (
            u_dir.id == u_ctl.id
            or u_dir.person_id == u_ctl.person_id
            or u_dir.person_id == actor.person_id
            or u_ctl.person_id == actor.person_id
        ):
            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.SELF_APPROVAL,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.SELF_APPROVAL,
                "Vi phạm nguyên tắc tách nhiệm vụ: người lập và hai người duyệt phải là 3 cá nhân độc lập.",
                status_code=403,
            )

        # Check approvers are still operational, still hold the required roles, and epochs still match
        if (
            not u_dir.is_operational
            or not u_ctl.is_operational
            or u_dir.role != Role.DIRECTOR
            or u_ctl.role != Role.CONTROLLER
            or u_dir.security_epoch != a_dir.approver_epoch_at_signing
            or u_ctl.security_epoch != a_ctl.approver_epoch_at_signing
            or actor.security_epoch != a_dir.requester_epoch_at_signing
            or actor.security_epoch != a_ctl.requester_epoch_at_signing
        ):
            req.status = RequestStatus.HOLD
            req.hold_reason = "Quyền hoặc trạng thái bảo mật của người duyệt/người lập đã thay đổi trước khi thực thi."
            req.save(update_fields=["status", "hold_reason", "updated_at"])
            record_audit_event(
                action="EXECUTE_PAYMENT_SIMULATED",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=actor,
                payment_request=req,
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Phiếu phê duyệt không còn hiệu lực do tài khoản, vai trò hoặc yếu tố xác thực đã bị thu hồi/thay đổi.",
                status_code=409,
            )

        # Check approval digest, beneficiary version, and expiry
        for app in (a_dir, a_ctl):
            if (
                app.content_digest != rev.content_digest
                or app.beneficiary_version_id != ver.id
                or now >= app.expires_at
            ):
                record_audit_event(
                    action="EXECUTE_PAYMENT_SIMULATED",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.SNAPSHOT_MISMATCH,
                    actor=actor,
                    payment_request=req,
                )
                raise SecurityDomainError(
                    ReasonCode.SNAPSHOT_MISMATCH,
                    "Phiếu duyệt không khớp nội dung phiên bản hiện tại hoặc đã hết hạn.",
                    status_code=409,
                )

        # Validate fresh EXECUTE ActionChallenge + fresh TOTP token
        challenge = _validate_and_consume_payment_challenge_under_lock(
            challenge_id=challenge_id,
            nonce=nonce,
            actor=actor,
            session_key=session_key,
            expected_actions=(ChallengeAction.EXECUTE,),
            payment_request=req,
            payment_revision=rev,
            otp_token=otp_token,
            now=now,
            audit_action_label="EXECUTE_PAYMENT_SIMULATED",
        )

        receipt_id = f"SIM-RCPT-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
        prev_status = req.status

        execution = PaymentExecution.objects.create(
            payment_request=req,
            payment_revision=rev,
            content_digest=rev.content_digest,
            amount_vnd=rev.amount_vnd,
            currency=rev.currency,
            beneficiary_name_snapshot=rev.beneficiary_name_snapshot,
            bank_name_snapshot=rev.bank_name_snapshot,
            account_number_snapshot=rev.account_number_snapshot,
            executor=actor,
            executor_person_id=actor.person_id,
            challenge=challenge,
            idempotency_key=clean_idem_key,
            payload_fingerprint=fingerprint,
            receipt_id=receipt_id,
            execution_label="SIMULATED",
            executed_at=now,
        )

        req.status = RequestStatus.EXECUTED_SIMULATED
        req.save(update_fields=["status", "updated_at"])

        # Test-only fault injection hook for T-40 (never exposed via any public endpoint)
        if fault_injector is not None:
            fault_injector()

        record_audit_event(
            action="EXECUTE_PAYMENT_SIMULATED",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            payment_request=req,
            revision_number=rev.revision_number,
            before_state=prev_status,
            after_state=RequestStatus.EXECUTED_SIMULATED,
            metadata={
                "receipt_id": receipt_id,
                "amount_vnd": rev.amount_vnd,
                "beneficiary_account": rev.account_number_snapshot,
                "execution_label": "SIMULATED",
                "idempotency_key": clean_idem_key,
            },
        )
        return execution, False

