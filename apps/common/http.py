"""
HTTP response helpers and authentication decorators for views/endpoints (Section 8).
Ensures consistent HTTP status codes (400/401/403/404/409/429) and reason_code
across both HTML browser forms and JSON API requests.
"""
from __future__ import annotations

from functools import wraps
import json
from typing import Any, Callable

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render

from apps.audit.models import AuditResult
from apps.audit.services import record_audit_event
from apps.common.exceptions import ReasonCode, SecurityDomainError


def wants_json(request: HttpRequest) -> bool:
    accept = request.headers.get("Accept", "")
    content_type = request.headers.get("Content-Type", "")
    return (
        "application/json" in accept.lower()
        or "application/json" in content_type.lower()
        or request.GET.get("format") == "json"
    )


def extract_request_data(request: HttpRequest) -> dict[str, Any]:
    content_type = request.headers.get("Content-Type", "").lower()
    if "application/json" in content_type and request.body:
        try:
            parsed = json.loads(request.body.decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
        except Exception as exc:
            raise SecurityDomainError(
                ReasonCode.VALIDATION_ERROR,
                "Payload JSON không hợp lệ.",
                status_code=400,
            ) from exc
    data: dict[str, Any] = {}
    for k, v in request.POST.items():
        if k != "csrfmiddlewaretoken":
            data[k] = v
    return data


def domain_error_response(
    request: HttpRequest,
    err: SecurityDomainError,
    *,
    template_name: str = "common/error.html",
    extra_context: dict[str, Any] | None = None,
) -> HttpResponse:
    payload = {
        "ok": False,
        "reason_code": err.reason_code,
        "message": err.message,
        **err.extra,
    }
    if wants_json(request):
        resp: HttpResponse = JsonResponse(payload, status=err.status_code)
    else:
        ctx = {
            "error_reason_code": err.reason_code,
            "error_message": err.message,
            "error_status_code": err.status_code,
            **(extra_context or {}),
        }
        resp = render(request, template_name, ctx, status=err.status_code)
    resp["X-Reason-Code"] = err.reason_code
    return resp


def require_full_mfa(view_func: Callable) -> Callable:
    """
    Require an authenticated user who has completed Step 2 MFA (`auth_mfa_verified=True`)
    with a matching `auth_security_epoch == user.security_epoch` and operational status.
    Pre-auth sessions (Step 1 password only) are rejected with 401 MFA_REQUIRED (T-10).
    """

    @wraps(view_func)
    def _wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        user = getattr(request, "user", None)
        preauth_uid = request.session.get("preauth_user_id")
        if preauth_uid and (not user or not user.is_authenticated or not request.session.get("auth_mfa_verified")):
            record_audit_event(
                action="ACCESS_PROTECTED_ENDPOINT",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.MFA_REQUIRED,
                metadata={"path": request.path, "method": request.method},
            )
            err = SecurityDomainError(
                ReasonCode.MFA_REQUIRED,
                "Bạn mới chỉ qua bước mật khẩu (Pre-Auth); bắt buộc hoàn tất xác thực MFA (TOTP) trước khi thao tác.",
                status_code=401,
            )
            return domain_error_response(request, err)

        if not user or not user.is_authenticated:
            record_audit_event(
                action="ACCESS_PROTECTED_ENDPOINT",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.AUTH_REQUIRED,
                metadata={"path": request.path, "method": request.method},
            )
            err = SecurityDomainError(
                ReasonCode.AUTH_REQUIRED,
                "Yêu cầu đăng nhập và xác thực MFA đầy đủ.",
                status_code=401,
            )
            return domain_error_response(request, err)

        sess_epoch = request.session.get("auth_security_epoch")
        mfa_ok = request.session.get("auth_mfa_verified") is True
        if not mfa_ok or sess_epoch != user.security_epoch or not user.is_operational:
            record_audit_event(
                action="ACCESS_PROTECTED_ENDPOINT",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=user,
                metadata={"path": request.path, "method": request.method},
            )
            err = SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Phiên làm việc hoặc tài khoản đã bị thu hồi / hết hiệu lực.",
                status_code=401,
            )
            return domain_error_response(request, err)

        return view_func(request, *args, **kwargs)

    return _wrapped


def require_post_method(action_name: str) -> Callable:
    """
    Ensure state-changing endpoints strictly reject GET/PUT/DELETE with 405 Method Not Allowed
    without mutating any state (Section 7.3, 8, T-36).
    """

    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def _wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            if request.method != "POST":
                actor = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
                record_audit_event(
                    action=action_name,
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.VALIDATION_ERROR,
                    actor=actor,
                    metadata={"rejected_method": request.method, "path": request.path},
                )
                if wants_json(request):
                    resp: HttpResponse = JsonResponse(
                        {
                            "ok": False,
                            "reason_code": ReasonCode.VALIDATION_ERROR,
                            "message": "Phương thức HTTP không được phép; mọi thao tác thay đổi trạng thái bắt buộc dùng POST.",
                        },
                        status=405,
                    )
                else:
                    resp = render(
                        request,
                        "common/error.html",
                        {
                            "error_reason_code": ReasonCode.VALIDATION_ERROR,
                            "error_message": "Phương thức HTTP không được phép (405). Mọi thao tác thay đổi trạng thái bắt buộc dùng POST.",
                            "error_status_code": 405,
                        },
                        status=405,
                    )
                resp["X-Reason-Code"] = ReasonCode.VALIDATION_ERROR
                resp["Allow"] = "POST"
                return resp
            return view_func(request, *args, **kwargs)

        return _wrapped

    return decorator

