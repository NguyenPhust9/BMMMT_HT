"""
Read-only views for the trusted Beneficiary registry (Section 8).
Strictly rejects any attempt to create or modify beneficiaries via HTTP API/UI (DES-07, T-18).
"""
from __future__ import annotations

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render

from apps.accounts.models import EmployeeIdentity, Role
from apps.audit.models import AuditResult
from apps.audit.services import record_audit_event
from apps.beneficiaries.models import Beneficiary
from apps.beneficiaries.services import submit_beneficiary_proposal, review_beneficiary_proposal
from apps.common.exceptions import ReasonCode, SecurityDomainError
from apps.common.http import domain_error_response, extract_request_data, require_full_mfa, require_post_method, wants_json


@require_full_mfa
def beneficiaries_list_view(request: HttpRequest) -> HttpResponse:
    actor: EmployeeIdentity = request.user  # type: ignore[assignment]
    if actor.role == Role.UNPRIVILEGED:
        record_audit_event(
            action="VIEW_BENEFICIARIES",
            result=AuditResult.DENIED,
            reason_code=ReasonCode.FORBIDDEN,
            actor=actor,
        )
        return domain_error_response(
            request,
            SecurityDomainError(ReasonCode.FORBIDDEN, "Tài khoản không có quyền xem danh mục người nhận.", status_code=403),
        )

    if request.method != "GET":
        record_audit_event(
            action="MODIFY_BENEFICIARY_HTTP_ATTEMPT",
            result=AuditResult.DENIED,
            reason_code=ReasonCode.FORBIDDEN,
            actor=actor,
            metadata={"method": request.method, "path": request.path},
        )
        return domain_error_response(
            request,
            SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Danh mục người thụ hưởng chỉ được cập nhật qua quy trình đối chiếu độc lập ngoại tuyến (DES-07).",
                status_code=403,
            ),
        )

    beneficiaries = list(
        Beneficiary.objects.select_related("active_version").prefetch_related("versions").all()
    )
    if wants_json(request):
        return JsonResponse(
            {
                "ok": True,
                "beneficiaries": [
                    {
                        "id": str(b.id),
                        "code": b.code,
                        "status": b.status,
                        "registry_epoch": b.registry_epoch,
                        "active_version": (
                            {
                                "id": str(b.active_version.id),
                                "version_number": b.active_version.version_number,
                                "vendor_name": b.active_version.vendor_name,
                                "bank_name": b.active_version.bank_name,
                                "account_number": b.active_version.account_number,
                                "status": b.active_version.status,
                                "verification_reference": b.active_version.verification_reference,
                            }
                            if b.active_version
                            else None
                        ),
                    }
                    for b in beneficiaries
                ],
            }
        )
    return render(request, "beneficiaries/list.html", {"beneficiaries": beneficiaries})


@require_post_method("PROPOSE_BENEFICIARY")
@require_full_mfa
def beneficiary_create_view(request: HttpRequest) -> HttpResponse:
    try:
        data = extract_request_data(request)
        reference_type = str(data.get("reference_type", "")).strip()
        reference_code = str(data.get("reference_code", "")).strip()
        reference_note = str(data.get("reference_note", "")).strip()
        if not reference_type or not reference_code:
            raise SecurityDomainError(
                ReasonCode.VALIDATION_ERROR,
                "Vui lòng chọn loại căn cứ và nhập số hoặc mã tham chiếu.",
                400,
            )
        verification_reference = f"{reference_type}: {reference_code}"
        if reference_note:
            verification_reference += f" — {reference_note}"
        ben = submit_beneficiary_proposal(
            actor=request.user,
            vendor_name=str(data.get("vendor_name", "")), bank_name=str(data.get("bank_name", "")),
            account_number=str(data.get("account_number", "")),
            verification_reference=verification_reference,
        )
        return redirect("/beneficiaries")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("REVIEW_BENEFICIARY")
@require_full_mfa
def beneficiary_review_view(request: HttpRequest, beneficiary_id) -> HttpResponse:
    try:
        data = extract_request_data(request)
        decision = str(data.get("decision", ""))
        if decision not in ("approve", "reject"):
            raise SecurityDomainError(ReasonCode.VALIDATION_ERROR, "Quyết định không hợp lệ.", 400)
        review_beneficiary_proposal(actor=request.user, beneficiary_id=beneficiary_id,
                                    approve=decision == "approve", review_note=str(data.get("review_note", "")))
        return redirect("/beneficiaries")
    except SecurityDomainError as err:
        return domain_error_response(request, err)

