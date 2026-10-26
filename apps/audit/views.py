"""
Role-scoped read-only views for AuditEvent (Section 8, 10.2, T-38).
Strictly rejects any POST/PUT/PATCH/DELETE attempt to modify or delete audit logs.
"""
from __future__ import annotations

from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render

from apps.accounts.models import EmployeeIdentity, Role
from apps.audit.models import AuditResult
from apps.audit.services import get_scoped_audit_events, record_audit_event
from apps.common.exceptions import ReasonCode, SecurityDomainError
from apps.common.http import domain_error_response, require_full_mfa, wants_json


@require_full_mfa
def audit_list_view(request: HttpRequest) -> HttpResponse:
    actor: EmployeeIdentity = request.user  # type: ignore[assignment]
    if actor.role == Role.UNPRIVILEGED:
        record_audit_event(
            action="VIEW_AUDIT_LOG",
            result=AuditResult.DENIED,
            reason_code=ReasonCode.FORBIDDEN,
            actor=actor,
        )
        return domain_error_response(
            request,
            SecurityDomainError(ReasonCode.FORBIDDEN, "Tài khoản không có quyền xem nhật ký.", status_code=403),
        )

    if request.method != "GET":
        record_audit_event(
            action="MUTATE_AUDIT_LOG_ATTEMPT",
            result=AuditResult.DENIED,
            reason_code=ReasonCode.FORBIDDEN,
            actor=actor,
            metadata={"method": request.method, "path": request.path},
        )
        return domain_error_response(
            request,
            SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Nhật ký kiểm toán là chỉ đọc (append-only); nghiêm cấm sửa hoặc xóa qua ứng dụng.",
                status_code=403,
            ),
        )

    qs = get_scoped_audit_events(actor)
    action_filter = request.GET.get("action", "").strip()
    result_filter = request.GET.get("result", "").strip()
    if action_filter:
        qs = qs.filter(action__icontains=action_filter)
    if result_filter:
        qs = qs.filter(result=result_filter)

    paginator = Paginator(qs, 50)
    page_obj = paginator.get_page(request.GET.get("page", 1))

    if wants_json(request):
        items = []
        for ev in page_obj.object_list:
            meta = dict(ev.metadata or {})
            if actor.role == Role.SECURITY_ADMIN:
                # Redact detailed financial amount/account in security-admin log view (Section 6.1 & 10.2)
                meta.pop("amount_vnd", None)
                meta.pop("beneficiary_account", None)
            items.append(
                {
                    "id": str(ev.id),
                    "actor": ev.actor_username_snapshot,
                    "actor_person_id": ev.actor_person_id,
                    "actor_role": ev.actor_role,
                    "action": ev.action,
                    "request_code": ev.payment_request.request_code if ev.payment_request else None,
                    "revision_number": ev.revision_number,
                    "result": ev.result,
                    "reason_code": ev.reason_code,
                    "before_state": ev.before_state,
                    "after_state": ev.after_state,
                    "metadata": meta,
                    "created_at": ev.created_at.isoformat(),
                }
            )
        return JsonResponse({"ok": True, "events": items, "count": paginator.count})

    return render(
        request,
        "audit/list.html",
        {
            "page_obj": page_obj,
            "action_filter": action_filter,
            "result_filter": result_filter,
        },
    )

