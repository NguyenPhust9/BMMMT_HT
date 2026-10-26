"""
Views and endpoints for payment requests, immutable revisions, action challenges,
independent dual approvals, and simulated execution (Sections 8 & 9).
"""
from __future__ import annotations

import uuid
from django.db.models import Q
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render

from apps.accounts.models import EmployeeIdentity, Role
from apps.audit.models import AuditResult
from apps.audit.services import record_audit_event
from apps.beneficiaries.models import BeneficiaryStatus, BeneficiaryVersion
from apps.common.exceptions import ReasonCode, SecurityDomainError
from apps.common.http import (
    domain_error_response,
    extract_request_data,
    require_full_mfa,
    require_post_method,
    wants_json,
)
from apps.payments.models import (
    ActionChallenge,
    Approval,
    ApprovalSlot,
    ApprovalStatus,
    PaymentExecution,
    PaymentRequest,
    SourceKind,
)
from apps.payments.services import (
    approve_payment_request,
    cancel_payment_request,
    create_payment_request_draft,
    execute_payment_request_simulated,
    get_RequestForViewer,
    issue_payment_challenge,
    reject_payment_request,
    revise_payment_request,
    submit_payment_request,
    update_draft_in_place,
)


def home_redirect_view(request: HttpRequest) -> HttpResponse:
    if getattr(request, "user", None) and request.user.is_authenticated and request.session.get("auth_mfa_verified"):
        if request.user.role == Role.SECURITY_ADMIN:
            return redirect("/security/users")
        return redirect("/dashboard")
    return redirect("/auth/login")


def _verified_beneficiary_versions():
    return list(
        BeneficiaryVersion.objects.select_related("beneficiary").filter(
            status=BeneficiaryStatus.VERIFIED,
            beneficiary__status=BeneficiaryStatus.VERIFIED,
        )
    )


@require_full_mfa
def requests_list_or_create_view(request: HttpRequest) -> HttpResponse:
    actor: EmployeeIdentity = request.user  # type: ignore[assignment]
    if request.method == "GET":
        if actor.role == Role.UNPRIVILEGED:
            record_audit_event(
                action="LIST_PAYMENT_REQUESTS",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.FORBIDDEN,
                actor=actor,
            )
            return domain_error_response(
                request,
                SecurityDomainError(
                    ReasonCode.FORBIDDEN,
                    "Tài khoản không có quyền xem danh sách yêu cầu thanh toán.",
                    status_code=403,
                ),
            )

        qs = PaymentRequest.objects.select_related(
            "requester",
            "current_revision",
            "current_revision__beneficiary",
        ).prefetch_related("current_revision__approvals")

        if actor.role == Role.REQUESTER:
            qs = qs.filter(requester=actor)

        q = request.GET.get("q", "").strip()
        status_filter = request.GET.get("status", "").strip()
        sort = request.GET.get("sort", "newest").strip()
        if q:
            qs = qs.filter(
                Q(request_code__icontains=q)
                | Q(requester__display_name__icontains=q)
                | Q(current_revision__beneficiary_name_snapshot__icontains=q)
            )
        if status_filter:
            qs = qs.filter(status=status_filter)
        qs = qs.order_by("created_at" if sort == "oldest" else "-updated_at")

        items = []
        for r in qs:
            active = []
            if r.current_revision:
                active = [a for a in r.current_revision.approvals.all() if a.status == ApprovalStatus.ACTIVE]
            by_slot = {a.slot: a for a in active}
            expected_slot = (
                ApprovalSlot.DIRECTOR if actor.role == Role.DIRECTOR
                else ApprovalSlot.CONTROLLER if actor.role == Role.CONTROLLER
                else None
            )
            items.append({
                "request": r,
                "active_count": len(active),
                "director_approval": by_slot.get(ApprovalSlot.DIRECTOR),
                "controller_approval": by_slot.get(ApprovalSlot.CONTROLLER),
                "needs_my_approval": bool(
                    expected_slot
                    and r.status == "PENDING_APPROVAL"
                    and expected_slot not in by_slot
                    and r.requester_id != actor.id
                ),
            })

        summary = {
            "total": len(items),
            "pending": sum(1 for item in items if item["request"].status == "PENDING_APPROVAL"),
            "approved": sum(1 for item in items if item["request"].status == "APPROVED"),
            "needs_action": sum(1 for item in items if item["needs_my_approval"]),
        }

        if wants_json(request):
            return JsonResponse(
                {
                    "ok": True,
                    "requests": [
                        {
                            "id": str(r.id),
                            "request_code": r.request_code,
                            "requester": r.requester.username,
                            "requester_person_id": r.requester_person_id,
                            "status": r.status,
                            "revision_number": r.current_revision.revision_number if r.current_revision else 1,
                            "amount_vnd": (
                                r.current_revision.amount_vnd
                                if (r.current_revision and actor.role != Role.SECURITY_ADMIN)
                                else None
                            ),
                            "beneficiary_name": (
                                r.current_revision.beneficiary_name_snapshot
                                if (r.current_revision and actor.role != Role.SECURITY_ADMIN)
                                else None
                            ),
                            "active_approvals_count": cnt,
                            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                        }
                        for item in items
                        for r, cnt in [(item["request"], item["active_count"])]
                    ],
                }
            )
        return render(
            request,
            "payments/request_list.html",
            {
                "request_items": items,
                "summary": summary,
                "q": q,
                "status_filter": status_filter,
                "sort": sort,
                "verified_versions": _verified_beneficiary_versions(),
                "source_kinds": SourceKind.choices,
            },
        )

    if request.method == "POST":
        try:
            data = extract_request_data(request)
            submit_now = str(data.get("submit_immediately", "")).lower() in ("1", "true", "yes", "on")
            clean_data = dict(data)
            clean_data.pop("submit_immediately", None)
            req = create_payment_request_draft(
                actor=actor,
                session_epoch=request.session.get("auth_security_epoch"),
                beneficiary_version_id=clean_data.get("beneficiary_version_id"),
                amount_vnd=clean_data.get("amount_vnd"),
                purpose=str(clean_data.get("purpose", "")),
                source_kind=str(clean_data.get("source_kind", SourceKind.CHAT_MESSAGE)),
                source_excerpt=str(clean_data.get("source_excerpt", "")),
                raw_payload=clean_data,
                submit_immediately=submit_now,
            )
            if wants_json(request):
                resp = JsonResponse(
                    {
                        "ok": True,
                        "reason_code": ReasonCode.OK,
                        "request_id": str(req.id),
                        "request_code": req.request_code,
                        "status": req.status,
                        "revision_number": req.current_revision.revision_number,
                        "content_digest": req.current_revision.content_digest,
                    },
                    status=201,
                )
                resp["X-Reason-Code"] = ReasonCode.OK
                return resp
            return redirect(f"/requests/{req.id}")
        except SecurityDomainError as err:
            return domain_error_response(request, err)

    return domain_error_response(
        request,
        SecurityDomainError(ReasonCode.VALIDATION_ERROR, "Method Not Allowed", status_code=405),
    )


@require_full_mfa
def request_create_form_view(request: HttpRequest) -> HttpResponse:
    actor: EmployeeIdentity = request.user  # type: ignore[assignment]
    if actor.role != Role.REQUESTER:
        return domain_error_response(
            request,
            SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Chỉ vai trò REQUESTER mới có quyền lập yêu cầu thanh toán.",
                status_code=403,
            ),
        )
    return render(
        request,
        "payments/request_create.html",
        {
            "verified_versions": _verified_beneficiary_versions(),
            "source_kinds": SourceKind.choices,
        },
    )


@require_full_mfa
def request_detail_view(request: HttpRequest, request_id) -> HttpResponse:
    if request.method != "GET":
        # Direct POST/PUT/PATCH to /requests/{id} is rejected (T-19)
        return edit_draft_view(request, request_id)
    try:
        actor: EmployeeIdentity = request.user  # type: ignore[assignment]
        req = get_RequestForViewer(actor=actor, request_id=request_id)
        rev = req.current_revision
        all_revisions = list(req.revisions.all().order_by("-revision_number"))
        approvals = list(
            Approval.objects.select_related("approver")
            .filter(payment_revision=rev)
            .order_by("created_at")
        )
        active_approvals = [a for a in approvals if a.status == ApprovalStatus.ACTIVE]
        active_by_slot = {a.slot: a for a in active_approvals}
        execution = PaymentExecution.objects.filter(payment_request=req).first()
        open_challenges = list(
            ActionChallenge.objects.filter(
                payment_request=req,
                actor=actor,
                consumed_at__isnull=True,
                invalidated_at__isnull=True,
            ).order_by("-created_at")[:5]
        )

        if wants_json(request):
            payload = {
                "ok": True,
                "id": str(req.id),
                "request_code": req.request_code,
                "requester": req.requester.username,
                "requester_person_id": req.requester_person_id,
                "status": req.status,
                "hold_reason": req.hold_reason,
                "rejection_reason": req.rejection_reason,
                "submitted_at": req.submitted_at.isoformat() if req.submitted_at else None,
                "expires_at": req.expires_at.isoformat() if req.expires_at else None,
                "current_revision": {
                    "id": str(rev.id),
                    "revision_number": rev.revision_number,
                    "is_frozen": rev.is_frozen,
                    "content_digest": rev.content_digest,
                    "amount_vnd": rev.amount_vnd if actor.role != Role.SECURITY_ADMIN else None,
                    "currency": rev.currency,
                    "beneficiary_version_id": str(rev.beneficiary_version_id),
                    "beneficiary_name_snapshot": (
                        rev.beneficiary_name_snapshot if actor.role != Role.SECURITY_ADMIN else "[REDACTED_FOR_SEC_ADMIN]"
                    ),
                    "bank_name_snapshot": (
                        rev.bank_name_snapshot if actor.role != Role.SECURITY_ADMIN else "[REDACTED_FOR_SEC_ADMIN]"
                    ),
                    "account_number_snapshot": (
                        rev.account_number_snapshot if actor.role != Role.SECURITY_ADMIN else "[REDACTED_FOR_SEC_ADMIN]"
                    ),
                    "purpose": rev.purpose if actor.role != Role.SECURITY_ADMIN else "[REDACTED_FOR_SEC_ADMIN]",
                    "source_kind": rev.source_kind,
                    "source_excerpt": (
                        rev.source_excerpt if actor.role != Role.SECURITY_ADMIN else "[REDACTED_FOR_SEC_ADMIN]"
                    ),
                },
                "active_approvals_count": len(active_approvals),
                "director_approval": active_by_slot.get(ApprovalSlot.DIRECTOR),
                "controller_approval": active_by_slot.get(ApprovalSlot.CONTROLLER),
                "approvals": [
                    {
                        "id": str(a.id),
                        "slot": a.slot,
                        "approver": a.approver.username,
                        "approver_person_id": a.approver_person_id,
                        "status": a.status,
                        "content_digest": a.content_digest,
                        "created_at": a.created_at.isoformat(),
                    }
                    for a in approvals
                ],
                "execution": (
                    {
                        "receipt_id": execution.receipt_id,
                        "execution_label": execution.execution_label,
                        "executed_at": execution.executed_at.isoformat(),
                    }
                    if execution
                    else None
                ),
            }
            return JsonResponse(payload)

        return render(
            request,
            "payments/request_detail.html",
            {
                "payment_request": req,
                "current_revision": rev,
                "all_revisions": all_revisions,
                "approvals": approvals,
                "active_approvals": active_approvals,
                "active_approvals_count": len(active_approvals),
                "execution": execution,
                "open_challenges": open_challenges,
                "verified_versions": _verified_beneficiary_versions(),
                "source_kinds": SourceKind.choices,
                "suggested_idempotency_key": f"idem-{req.request_code}-rev{rev.revision_number}",
            },
        )
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("EDIT_PAYMENT_REQUEST")
@require_full_mfa
def edit_draft_view(request: HttpRequest, request_id) -> HttpResponse:
    try:
        data = extract_request_data(request)
        req = update_draft_in_place(
            actor=request.user,  # type: ignore[arg-type]
            session_epoch=request.session.get("auth_security_epoch"),
            request_id=request_id,
            beneficiary_version_id=data.get("beneficiary_version_id"),
            amount_vnd=data.get("amount_vnd"),
            purpose=str(data.get("purpose", "")),
            source_kind=str(data.get("source_kind", SourceKind.CHAT_MESSAGE)),
            source_excerpt=str(data.get("source_excerpt", "")),
            raw_payload=data,
        )
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "request_id": str(req.id),
                    "status": req.status,
                    "revision_number": req.current_revision.revision_number,
                    "content_digest": req.current_revision.content_digest,
                },
                status=200,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        return redirect(f"/requests/{req.id}")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("SUBMIT_PAYMENT_REQUEST")
@require_full_mfa
def submit_request_view(request: HttpRequest, request_id) -> HttpResponse:
    try:
        req = submit_payment_request(
            actor=request.user,  # type: ignore[arg-type]
            session_epoch=request.session.get("auth_security_epoch"),
            request_id=request_id,
        )
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "request_id": str(req.id),
                    "status": req.status,
                    "revision_number": req.current_revision.revision_number,
                    "content_digest": req.current_revision.content_digest,
                    "expires_at": req.expires_at.isoformat() if req.expires_at else None,
                },
                status=200,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        return redirect(f"/requests/{req.id}")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("REVISE_PAYMENT_REQUEST")
@require_full_mfa
def revise_request_view(request: HttpRequest, request_id) -> HttpResponse:
    try:
        data = extract_request_data(request)
        submit_now = str(data.get("submit_immediately", "")).lower() in ("1", "true", "yes", "on")
        clean_data = dict(data)
        clean_data.pop("submit_immediately", None)
        req = revise_payment_request(
            actor=request.user,  # type: ignore[arg-type]
            session_epoch=request.session.get("auth_security_epoch"),
            request_id=request_id,
            beneficiary_version_id=clean_data.get("beneficiary_version_id"),
            amount_vnd=clean_data.get("amount_vnd"),
            purpose=str(clean_data.get("purpose", "")),
            source_kind=str(clean_data.get("source_kind", SourceKind.CHAT_MESSAGE)),
            source_excerpt=str(clean_data.get("source_excerpt", "")),
            raw_payload=clean_data,
            submit_immediately=submit_now,
        )
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "request_id": str(req.id),
                    "status": req.status,
                    "revision_number": req.current_revision.revision_number,
                    "content_digest": req.current_revision.content_digest,
                },
                status=200,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        return redirect(f"/requests/{req.id}")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("CANCEL_PAYMENT_REQUEST")
@require_full_mfa
def cancel_request_view(request: HttpRequest, request_id) -> HttpResponse:
    try:
        req = cancel_payment_request(
            actor=request.user,  # type: ignore[arg-type]
            session_epoch=request.session.get("auth_security_epoch"),
            request_id=request_id,
        )
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "request_id": str(req.id),
                    "status": req.status,
                },
                status=200,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        return redirect(f"/requests/{req.id}")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("ISSUE_PAYMENT_CHALLENGE")
@require_full_mfa
def issue_challenge_view(request: HttpRequest, request_id) -> HttpResponse:
    try:
        data = extract_request_data(request)
        if not request.session.session_key:
            request.session.save()
        challenge = issue_payment_challenge(
            actor=request.user,  # type: ignore[arg-type]
            session_key=request.session.session_key or "",
            session_epoch=request.session.get("auth_security_epoch"),
            request_id=request_id,
            action=str(data.get("action", "")),
            reason=str(data.get("reason", "")),
        )
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "challenge_id": str(challenge.id),
                    "nonce": challenge.nonce,
                    "action": challenge.action,
                    "request_id": str(challenge.payment_request_id),
                    "revision_id": str(challenge.payment_revision_id),
                    "content_digest": challenge.content_digest,
                    "expires_at": challenge.expires_at.isoformat(),
                },
                status=201,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        return redirect(f"/requests/{request_id}")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("APPROVE_PAYMENT_REQUEST")
@require_full_mfa
def approve_request_view(request: HttpRequest, request_id) -> HttpResponse:
    try:
        data = extract_request_data(request)
        approval = approve_payment_request(
            actor=request.user,  # type: ignore[arg-type]
            session_key=request.session.session_key or "",
            session_epoch=request.session.get("auth_security_epoch"),
            request_id=request_id,
            challenge_id=data.get("challenge_id"),
            nonce=str(data.get("nonce", "")),
            otp_token=str(data.get("otp_token", "")),
            raw_payload=data,
        )
        req = PaymentRequest.objects.get(pk=request_id)
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "approval_id": str(approval.id),
                    "slot": approval.slot,
                    "request_status": req.status,
                    "content_digest": approval.content_digest,
                },
                status=200,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        return redirect(f"/requests/{request_id}")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("REJECT_PAYMENT_REQUEST")
@require_full_mfa
def reject_request_view(request: HttpRequest, request_id) -> HttpResponse:
    try:
        data = extract_request_data(request)
        req = reject_payment_request(
            actor=request.user,  # type: ignore[arg-type]
            session_key=request.session.session_key or "",
            session_epoch=request.session.get("auth_security_epoch"),
            request_id=request_id,
            challenge_id=data.get("challenge_id"),
            nonce=str(data.get("nonce", "")),
            otp_token=str(data.get("otp_token", "")),
            reason=str(data.get("reason", "")),
        )
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "request_id": str(req.id),
                    "status": req.status,
                    "rejection_reason": req.rejection_reason,
                },
                status=200,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        return redirect(f"/requests/{request_id}")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("EXECUTE_PAYMENT_SIMULATED")
@require_full_mfa
def execute_simulated_view(request: HttpRequest, request_id) -> HttpResponse:
    try:
        data = extract_request_data(request)
        idem_key = (
            request.headers.get("Idempotency-Key")
            or str(data.get("idempotency_key", ""))
        ).strip()
        clean_data = dict(data)
        clean_data.pop("idempotency_key", None)

        execution, is_replay = execute_payment_request_simulated(
            actor=request.user,  # type: ignore[arg-type]
            session_key=request.session.session_key or "",
            session_epoch=request.session.get("auth_security_epoch"),
            request_id=request_id,
            challenge_id=clean_data.get("challenge_id"),
            nonce=str(clean_data.get("nonce", "")),
            otp_token=str(clean_data.get("otp_token", "")),
            idempotency_key=idem_key,
            raw_payload=clean_data,
        )
        reason = ReasonCode.IDEMPOTENT_REPLAY if is_replay else ReasonCode.OK
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": reason,
                    "idempotent_replay": is_replay,
                    "request_id": str(execution.payment_request_id),
                    "receipt_id": execution.receipt_id,
                    "execution_label": execution.execution_label,
                    "amount_vnd": execution.amount_vnd,
                    "beneficiary_name_snapshot": execution.beneficiary_name_snapshot,
                    "bank_name_snapshot": execution.bank_name_snapshot,
                    "account_number_snapshot": execution.account_number_snapshot,
                    "content_digest": execution.content_digest,
                    "executed_at": execution.executed_at.isoformat(),
                },
                status=200,
            )
            resp["X-Reason-Code"] = reason
            return resp
        return redirect(f"/requests/{request_id}/receipt")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_full_mfa
def receipt_view(request: HttpRequest, request_id) -> HttpResponse:
    """
    Object-scoped receipt view (Section 8, T-08, T-09):
    - REQUESTER: only own request's receipt.
    - DIRECTOR / CONTROLLER: within company scope.
    - SECURITY_ADMIN / UNPRIVILEGED: forbidden from viewing financial receipts.
    """
    if request.method != "GET":
        return domain_error_response(
            request,
            SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Biên nhận mô phỏng là bất biến, không được phép sửa hoặc xóa (T-29).",
                status_code=405,
            ),
        )
    try:
        actor: EmployeeIdentity = request.user  # type: ignore[assignment]
        if actor.role in (Role.SECURITY_ADMIN, Role.UNPRIVILEGED):
            record_audit_event(
                action="VIEW_RECEIPT",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.FORBIDDEN,
                actor=actor,
            )
            raise SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Vai trò của bạn không có quyền xem biên nhận tài chính.",
                status_code=403,
            )

        req = get_RequestForViewer(actor=actor, request_id=request_id)
        execution = PaymentExecution.objects.select_related("payment_revision", "executor").filter(
            payment_request=req
        ).first()
        if execution is None:
            raise SecurityDomainError(
                ReasonCode.VALIDATION_ERROR,
                "Yêu cầu này chưa có biên nhận thực thi mô phỏng.",
                status_code=404,
            )

        if wants_json(request):
            return JsonResponse(
                {
                    "ok": True,
                    "receipt_id": execution.receipt_id,
                    "request_code": req.request_code,
                    "revision_number": execution.payment_revision.revision_number,
                    "amount_vnd": execution.amount_vnd,
                    "currency": execution.currency,
                    "beneficiary_name_snapshot": execution.beneficiary_name_snapshot,
                    "bank_name_snapshot": execution.bank_name_snapshot,
                    "account_number_snapshot": execution.account_number_snapshot,
                    "content_digest": execution.content_digest,
                    "executor": execution.executor.username,
                    "executor_person_id": execution.executor_person_id,
                    "execution_label": execution.execution_label,
                    "executed_at": execution.executed_at.isoformat(),
                }
            )
        return render(
            request,
            "payments/receipt.html",
            {
                "payment_request": req,
                "execution": execution,
            },
        )
    except SecurityDomainError as err:
        return domain_error_response(request, err)

