"""
Trusted beneficiary registry services (DES-07, Section 7.1, T-18, T-28).
"""
from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from apps.audit.models import AuditResult
from apps.audit.services import record_audit_event
from apps.beneficiaries.models import Beneficiary, BeneficiaryStatus, BeneficiaryVersion
from apps.common.exceptions import ReasonCode, SecurityDomainError
from apps.common.mutex import acquire_security_mutex
from apps.accounts.models import EmployeeIdentity, Role
from apps.payments.models import (
    ActionChallenge,
    Approval,
    ApprovalStatus,
    PaymentRequest,
    RequestStatus,
)


def _cascade_beneficiary_change_under_lock(
    beneficiary: Beneficiary,
    reason_summary: str,
    now,
) -> list[str]:
    """
    When a Beneficiary is revoked or its active_version changes, any PENDING_APPROVAL or APPROVED
    request (not yet executed) referencing an older or revoked version is moved to HOLD and its
    prior approvals/challenges are invalidated so it cannot inherit old approvals (T-28).
    """
    affected_codes: list[str] = []
    open_reqs = PaymentRequest.objects.select_for_update().filter(
        status__in=[RequestStatus.PENDING_APPROVAL, RequestStatus.APPROVED],
        current_revision__beneficiary=beneficiary,
    )
    for req in open_reqs:
        rev = req.current_revision
        if (
            beneficiary.status != BeneficiaryStatus.VERIFIED
            or beneficiary.active_version_id is None
            or rev.beneficiary_version_id != beneficiary.active_version_id
        ):
            prev_status = req.status
            req.status = RequestStatus.HOLD
            req.hold_reason = f"Người thụ hưởng {beneficiary.code} thay đổi phiên bản hoặc bị thu hồi: {reason_summary}"[:500]
            req.save(update_fields=["status", "hold_reason", "updated_at"])
            Approval.objects.filter(
                payment_revision=rev,
                status=ApprovalStatus.ACTIVE,
            ).update(status=ApprovalStatus.INVALIDATED_BY_INCIDENT)
            ActionChallenge.objects.filter(
                payment_request=req,
                consumed_at__isnull=True,
                invalidated_at__isnull=True,
            ).update(invalidated_at=now)
            affected_codes.append(req.request_code)
            record_audit_event(
                action="BENEFICIARY_CHANGE_HOLD_REQUEST",
                result=AuditResult.SUCCESS,
                reason_code=ReasonCode.BENEFICIARY_INVALID,
                payment_request=req,
                before_state=prev_status,
                after_state=RequestStatus.HOLD,
                metadata={"beneficiary_code": beneficiary.code, "reason": reason_summary},
            )
    return affected_codes


def offline_create_or_update_beneficiary_version(
    *,
    code: str,
    vendor_name: str,
    bank_name: str,
    account_number: str,
    verification_reference: str,
    status: str = BeneficiaryStatus.VERIFIED,
    verified_by_summary: str = "Dual-control offline contract verification",
    now=None,
) -> tuple[Beneficiary, BeneficiaryVersion]:
    """
    Trusted offline operation creating a new immutable BeneficiaryVersion (never modifying an existing version in-place).
    """
    now = now or timezone.now()
    with transaction.atomic():
        acquire_security_mutex()
        ben = Beneficiary.objects.select_for_update().filter(code=code).first()
        if ben is None:
            ben = Beneficiary.objects.create(
                code=code,
                status=status,
                registry_epoch=1,
            )
            next_ver = 1
        else:
            last_ver = ben.versions.order_by("-version_number").first()
            next_ver = (last_ver.version_number + 1) if last_ver else 1
            ben.registry_epoch += 1

        ver = BeneficiaryVersion.objects.create(
            beneficiary=ben,
            version_number=next_ver,
            vendor_name=vendor_name.strip(),
            bank_name=bank_name.strip(),
            account_number=account_number.strip(),
            verification_reference=verification_reference.strip(),
            status=status,
            verified_by_summary=verified_by_summary.strip(),
        )

        if status == BeneficiaryStatus.VERIFIED:
            # Mark older versions as superseded/revoked so only the new version is active
            BeneficiaryVersion.objects.filter(beneficiary=ben).exclude(pk=ver.pk).update(
                status=BeneficiaryStatus.REVOKED
            )
            ben.status = BeneficiaryStatus.VERIFIED
            ben.active_version = ver
            ben.save()
            affected = _cascade_beneficiary_change_under_lock(
                ben, f"Activated new verified version v{next_ver}", now
            )
        elif status == BeneficiaryStatus.REVOKED:
            ben.status = BeneficiaryStatus.REVOKED
            ben.active_version = None
            ben.save()
            affected = _cascade_beneficiary_change_under_lock(ben, "Beneficiary revoked", now)
        else:
            ben.status = BeneficiaryStatus.PENDING
            ben.save()
            affected = []

        record_audit_event(
            action="OFFLINE_BENEFICIARY_VERSION_CREATED",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor_username="offline_trusted_cli",
            metadata={
                "beneficiary_code": ben.code,
                "version_number": ver.version_number,
                "status": ver.status,
                "affected_requests": affected,
            },
        )
        return ben, ver


def offline_revoke_beneficiary(
    *,
    code: str,
    reason: str = "Revoked by offline dual-control verification",
    now=None,
) -> tuple[Beneficiary, list[str]]:
    now = now or timezone.now()
    with transaction.atomic():
        acquire_security_mutex()
        ben = Beneficiary.objects.select_for_update().get(code=code)
        before_state = f"status={ben.status},epoch={ben.registry_epoch}"
        ben.status = BeneficiaryStatus.REVOKED
        ben.active_version = None
        ben.registry_epoch += 1
        ben.save()
        BeneficiaryVersion.objects.filter(beneficiary=ben).update(status=BeneficiaryStatus.REVOKED)
        affected = _cascade_beneficiary_change_under_lock(ben, reason, now)
        after_state = f"status={ben.status},epoch={ben.registry_epoch}"

        record_audit_event(
            action="OFFLINE_BENEFICIARY_REVOKED",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor_username="offline_trusted_cli",
            before_state=before_state,
            after_state=after_state,
            metadata={"beneficiary_code": ben.code, "reason": reason, "affected_requests": affected},
        )
        return ben, affected


def submit_beneficiary_proposal(
    *, actor: EmployeeIdentity, vendor_name: str, bank_name: str,
    account_number: str, verification_reference: str,
) -> Beneficiary:
    """Create a web proposal. It remains unusable until a controller verifies it."""
    if actor.role != Role.REQUESTER:
        raise SecurityDomainError(ReasonCode.FORBIDDEN, "Chỉ người lập yêu cầu được đề nghị người thụ hưởng mới.", 403)
    values = [vendor_name.strip(), bank_name.strip(), account_number.strip(), verification_reference.strip()]
    if not all(values):
        raise SecurityDomainError(ReasonCode.VALIDATION_ERROR, "Vui lòng nhập đầy đủ thông tin người thụ hưởng.", 400)
    if len(values[2]) < 6 or len(values[2]) > 30 or not values[2].isdigit():
        raise SecurityDomainError(ReasonCode.VALIDATION_ERROR, "Số tài khoản phải gồm từ 6 đến 30 chữ số.", 400)

    with transaction.atomic():
        acquire_security_mutex()
        sequence = Beneficiary.objects.count() + 1
        code = f"BEN-NEW-{sequence:04d}"
        while Beneficiary.objects.filter(code=code).exists():
            sequence += 1
            code = f"BEN-NEW-{sequence:04d}"
        ben = Beneficiary.objects.create(code=code, status=BeneficiaryStatus.PENDING)
        BeneficiaryVersion.objects.create(
            beneficiary=ben, version_number=1, vendor_name=values[0], bank_name=values[1],
            account_number=values[2], verification_reference=values[3],
            status=BeneficiaryStatus.PENDING,
            verified_by_summary=f"Đề nghị bởi {actor.display_name} ({actor.person_id})",
        )
        record_audit_event(action="BENEFICIARY_PROPOSED", result=AuditResult.SUCCESS,
                           reason_code=ReasonCode.OK, actor=actor,
                           metadata={"beneficiary_code": code})
        return ben


def review_beneficiary_proposal(
    *, actor: EmployeeIdentity, beneficiary_id, approve: bool, review_note: str,
) -> Beneficiary:
    """Controller decision for a pending beneficiary proposal."""
    if actor.role != Role.CONTROLLER:
        raise SecurityDomainError(ReasonCode.FORBIDDEN, "Chỉ Kiểm soát viên được xác minh người thụ hưởng.", 403)
    if not review_note.strip():
        raise SecurityDomainError(ReasonCode.VALIDATION_ERROR, "Vui lòng nhập căn cứ hoặc lý do xử lý.", 400)
    with transaction.atomic():
        acquire_security_mutex()
        ben = Beneficiary.objects.select_for_update().filter(pk=beneficiary_id).first()
        if ben is None or ben.status != BeneficiaryStatus.PENDING:
            raise SecurityDomainError(ReasonCode.VALIDATION_ERROR, "Đề nghị không còn ở trạng thái chờ xác minh.", 409)
        ver = ben.versions.select_for_update().order_by("-version_number").first()
        if ver is None:
            raise SecurityDomainError(ReasonCode.VALIDATION_ERROR, "Không tìm thấy thông tin người thụ hưởng.", 409)
        target = BeneficiaryStatus.VERIFIED if approve else BeneficiaryStatus.REVOKED
        ver.status = target
        ver.verified_by_summary = f"{actor.display_name}: {review_note.strip()}"[:200]
        ver.save(update_fields=["status", "verified_by_summary"])
        ben.status = target
        ben.active_version = ver if approve else None
        ben.registry_epoch += 1
        ben.save(update_fields=["status", "active_version", "registry_epoch", "updated_at"])
        record_audit_event(action="BENEFICIARY_VERIFIED" if approve else "BENEFICIARY_REJECTED",
                           result=AuditResult.SUCCESS, reason_code=ReasonCode.OK, actor=actor,
                           metadata={"beneficiary_code": ben.code, "review_note": review_note.strip()})
        return ben

