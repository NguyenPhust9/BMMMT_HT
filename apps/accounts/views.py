"""
Views for authentication (Step 1 password -> Step 2 MFA -> Logout),
security-admin panel (`/security/users`, `/suspend`, `/revoke-all`),
and explicit denial of prohibited public self-service/admin routes (DES-01, DES-09).
"""
from __future__ import annotations

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render

from apps.accounts.models import EmployeeIdentity, Role
from apps.accounts.services import (
    complete_password_only_login,
    execute_security_admin_action,
    issue_security_admin_challenge,
    logout_current_session,
    step1_password_login,
    step2_mfa_login,
)
from apps.audit.models import AuditResult
from apps.audit.services import record_audit_event
from apps.common.exceptions import ReasonCode, SecurityDomainError
from apps.common.http import (
    domain_error_response,
    extract_request_data,
    require_full_mfa,
    require_post_method,
    wants_json,
)
from apps.payments.models import ActionChallenge, ChallengeAction
from apps.payments.services import assert_no_authority_fields


def login_view(request: HttpRequest) -> HttpResponse:
    if request.method == "GET":
        return render(request, "accounts/login.html")
    if request.method != "POST":
        return domain_error_response(
            request,
            SecurityDomainError(ReasonCode.VALIDATION_ERROR, "Method Not Allowed", status_code=405),
        )
    try:
        data = extract_request_data(request)
        assert_no_authority_fields(data, action="AUTH_LOGIN_PASSWORD")
        user = step1_password_login(
            request,
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
        )
        user = complete_password_only_login(request, user=user)
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "next": "/security/users" if user.role == Role.SECURITY_ADMIN else "/dashboard",
                    "username": user.username,
                },
                status=200,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        if user.role == Role.SECURITY_ADMIN:
            return redirect("/security/users")
        return redirect("/dashboard")
    except SecurityDomainError as err:
        return domain_error_response(request, err, template_name="accounts/login.html")


def mfa_verify_view(request: HttpRequest) -> HttpResponse:
    if request.method == "GET":
        if not request.session.get("preauth_user_id"):
            return redirect("/auth/login")
        return render(request, "accounts/mfa.html")
    if request.method != "POST":
        return domain_error_response(
            request,
            SecurityDomainError(ReasonCode.VALIDATION_ERROR, "Method Not Allowed", status_code=405),
        )
    try:
        data = extract_request_data(request)
        assert_no_authority_fields(data, action="AUTH_LOGIN_MFA")
        user = step2_mfa_login(
            request,
            otp_token=str(data.get("otp_token", "")),
        )
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "user_id": str(user.id),
                    "username": user.username,
                    "role": user.role,
                    "person_id": user.person_id,
                    "security_epoch": user.security_epoch,
                },
                status=200,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        if user.role == Role.SECURITY_ADMIN:
            return redirect("/security/users")
        return redirect("/requests")
    except SecurityDomainError as err:
        return domain_error_response(request, err, template_name="accounts/mfa.html")


@require_post_method("AUTH_LOGOUT")
def logout_view(request: HttpRequest) -> HttpResponse:
    logout_current_session(request)
    if wants_json(request):
        resp = JsonResponse({"ok": True, "reason_code": ReasonCode.OK}, status=200)
        resp["X-Reason-Code"] = ReasonCode.OK
        return resp
    return redirect("/auth/login")


@require_full_mfa
def security_users_view(request: HttpRequest) -> HttpResponse:
    actor: EmployeeIdentity = request.user  # type: ignore[assignment]
    if actor.role != Role.SECURITY_ADMIN:
        record_audit_event(
            action="VIEW_SECURITY_USERS",
            result=AuditResult.DENIED,
            reason_code=ReasonCode.FORBIDDEN,
            actor=actor,
        )
        return domain_error_response(
            request,
            SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Chỉ SECURITY_ADMIN mới có quyền truy cập trang quản trị an ninh.",
                status_code=403,
            ),
        )

    users = list(EmployeeIdentity.objects.all().order_by("username"))
    open_challenges = list(
        ActionChallenge.objects.filter(
            actor=actor,
            consumed_at__isnull=True,
            invalidated_at__isnull=True,
        ).select_related("target_user")[:10]
    )
    if wants_json(request):
        return JsonResponse(
            {
                "ok": True,
                "users": [
                    {
                        "id": str(u.id),
                        "username": u.username,
                        "display_name": u.display_name,
                        "person_id": u.person_id,
                        "role": u.role,
                        "is_active": u.is_active,
                        "is_suspended": u.is_suspended,
                        "suspension_reason": u.suspension_reason,
                        "security_epoch": u.security_epoch,
                    }
                    for u in users
                ],
            }
        )
    return render(
        request,
        "accounts/security_users.html",
        {
            "users": users,
            "open_challenges": open_challenges,
        },
    )


@require_post_method("ISSUE_SECURITY_CHALLENGE")
@require_full_mfa
def issue_security_challenge_view(request: HttpRequest, user_id) -> HttpResponse:
    try:
        data = extract_request_data(request)
        assert_no_authority_fields(data, actor=request.user, action="ISSUE_SECURITY_CHALLENGE")
        if not request.session.session_key:
            request.session.save()
        challenge = issue_security_admin_challenge(
            actor=request.user,  # type: ignore[arg-type]
            session_key=request.session.session_key or "",
            target_user_id=user_id,
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
                    "target_user_id": str(challenge.target_user_id),
                    "target_user_epoch": challenge.target_user_epoch,
                    "expires_at": challenge.expires_at.isoformat(),
                },
                status=201,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        return redirect("/security/users")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


def _handle_security_action(request: HttpRequest, user_id, action: str) -> HttpResponse:
    try:
        data = extract_request_data(request)
        assert_no_authority_fields(data, actor=request.user, action=f"SECURITY_{action}")
        target_user, affected_codes = execute_security_admin_action(
            actor=request.user,  # type: ignore[arg-type]
            session_key=request.session.session_key or "",
            session_epoch=request.session.get("auth_security_epoch"),
            target_user_id=user_id,
            action=action,
            reason=str(data.get("reason", "")),
            challenge_id=data.get("challenge_id"),
            nonce=str(data.get("nonce", "")),
            otp_token=str(data.get("otp_token", "")),
        )
        if wants_json(request):
            resp = JsonResponse(
                {
                    "ok": True,
                    "reason_code": ReasonCode.OK,
                    "target_user_id": str(target_user.id),
                    "is_suspended": target_user.is_suspended,
                    "security_epoch": target_user.security_epoch,
                    "affected_requests": affected_codes,
                },
                status=200,
            )
            resp["X-Reason-Code"] = ReasonCode.OK
            return resp
        return redirect("/security/users")
    except SecurityDomainError as err:
        return domain_error_response(request, err)


@require_post_method("SECURITY_SUSPEND")
@require_full_mfa
def suspend_user_view(request: HttpRequest, user_id) -> HttpResponse:
    return _handle_security_action(request, user_id, ChallengeAction.SUSPEND)


@require_post_method("SECURITY_REVOKE_ALL")
@require_full_mfa
def revoke_all_user_view(request: HttpRequest, user_id) -> HttpResponse:
    return _handle_security_action(request, user_id, ChallengeAction.REVOKE_ALL)


def prohibited_route_view(request: HttpRequest, *args, **kwargs) -> HttpResponse:
    """
    Explicitly block public signup, MFA reset, role/factor self-service, or /admin/ routes (DES-01, DES-09, T-09, T-14, T-15).
    """
    actor = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
    record_audit_event(
        action="PROHIBITED_ROUTE_ATTEMPT",
        result=AuditResult.DENIED,
        reason_code=ReasonCode.FORBIDDEN,
        actor=actor,
        metadata={"path": request.path, "method": request.method},
    )
    return domain_error_response(
        request,
        SecurityDomainError(
            ReasonCode.FORBIDDEN,
            "Chức năng này bị cấm trên giao diện/API ứng dụng theo chính sách bảo mật baseline (DES-01 / DES-09).",
            status_code=403,
        ),
    )

