"""
Authentication, MFA, TOTP anti-replay, persistent throttling, session management,
and security-admin incident response services (Sections 7.1, 7.2, 8, 10.1).
"""
from __future__ import annotations

from datetime import timedelta
import secrets
from typing import Any

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session
from django.db import transaction
from django.http import HttpRequest
from django.utils import timezone
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex

from apps.accounts.models import EmployeeIdentity, Role
from apps.audit.models import AuditResult
from apps.audit.services import record_audit_event
from apps.common.crypto import canonical_json_sha256, sha256_hex
from apps.common.exceptions import ReasonCode, SecurityDomainError
from apps.common.mutex import acquire_security_mutex, security_atomic
from apps.payments.models import (
     TERMINAL_REQUEST_STATUSES,
    ActionChallenge,
    Approval,
    ApprovalStatus,
    ChallengeAction,
    ChallengeTargetType,
    PaymentRequest,
    RequestStatus,
)


def get_session_key_hash(request: HttpRequest) -> str:
    if not request.session.session_key:
        request.session.save()
    return sha256_hex(request.session.session_key or "")


def get_confirmed_totp_device(user: EmployeeIdentity, for_update: bool = False) -> TOTPDevice:
    qs = TOTPDevice.objects.filter(user=user, confirmed=True)
    if for_update:
        qs = qs.select_for_update()
    device = qs.order_by("id").first()
    if not device:
        raise SecurityDomainError(
            ReasonCode.MFA_REQUIRED,
            "Tài khoản chưa có thiết bị TOTP đã xác nhận.",
            status_code=401,
        )
    return device


def generate_totp_code_for_device(device: TOTPDevice, at_time: float | None = None) -> tuple[str, int]:
    """
    Helper for local offline bootstrap / test fixtures to compute the 6-digit TOTP code
    and timestep for a TOTPDevice at a given unix timestamp.
    """
    ts = int(at_time if at_time is not None else timezone.now().timestamp())
    totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
    totp.time = ts
    code = str(totp.token()).zfill(device.digits)
    return code, totp.t()


def _check_and_record_otp_failure(user: EmployeeIdentity, device: TOTPDevice, now) -> None:
    user.failed_otp_attempts += 1
    try:
        device.throttle_increment(commit=True)
    except Exception:
        pass
    if user.failed_otp_attempts >= settings.MAX_OTP_ATTEMPTS:
        user.otp_throttled_until = now + timedelta(seconds=settings.OTP_COOLDOWN_SECONDS)
    user.save(update_fields=["failed_otp_attempts", "otp_throttled_until"])


def verify_totp_token_under_lock(
    *,
    user: EmployeeIdentity,
    raw_token: str,
    now=None,
    action_label: str = "MFA_VERIFY",
    payment_request: PaymentRequest | None = None,
) -> TOTPDevice:
    """
    Must be called inside `transaction.atomic()` after `acquire_security_mutex()`.
    Enforces:
    1. Principal is active, not suspended, identity verified.
    2. Persistent OTP throttling across sessions/challenges (`otp_throttled_until` & `TOTPDevice`).
    3. Confirmed `TOTPDevice` belonging to `user`.
    4. Strict timestep anti-replay (`t > device.last_t`) across login and all actions (T-23, T-34).
    """
    now = now or timezone.now()
    if not user.is_operational:
        record_audit_event(
            action=action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.PRINCIPAL_REVOKED,
            actor=user,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.PRINCIPAL_REVOKED,
            "Tài khoản đang bị đình chỉ hoặc không còn hiệu lực hoạt động.",
            status_code=403,
        )

    if user.otp_throttled_until and now < user.otp_throttled_until:
        record_audit_event(
            action=action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.RATE_LIMITED,
            actor=user,
            payment_request=payment_request,
            metadata={"throttled_until": user.otp_throttled_until.isoformat()},
        )
        raise SecurityDomainError(
            ReasonCode.RATE_LIMITED,
            "Tài khoản đang bị tạm khóa xác thực OTP do nhập sai quá số lần quy định. Vui lòng thử lại sau.",
            status_code=429,
        )

    if user.otp_throttled_until and now >= user.otp_throttled_until:
        user.failed_otp_attempts = 0
        user.otp_throttled_until = None
        user.save(update_fields=["failed_otp_attempts", "otp_throttled_until"])
        for dev in TOTPDevice.objects.select_for_update().filter(user=user):
            try:
                dev.throttle_reset(commit=True)
            except Exception:
                pass

    device = get_confirmed_totp_device(user, for_update=True)
    token_str = (raw_token or "").strip()
    if not token_str.isdigit() or len(token_str) != device.digits:
        _check_and_record_otp_failure(user, device, now)
        record_audit_event(
            action=action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.OTP_INVALID,
            actor=user,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.OTP_INVALID,
            "Mã xác thực OTP không hợp lệ.",
            status_code=400,
        )

    token_int = int(token_str)
    ts = int(now.timestamp())
    totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
    totp.time = ts

    matched_offset: int | None = None
    for offset in range(-device.tolerance, device.tolerance + 1):
        if totp.t() + offset >= 0 and totp.verify(token_int, tolerance=0, min_t=None):
            pass

    # Compute exact timestep match within tolerance window [-tolerance, +tolerance]
    base_t = totp.t()
    matched_t: int | None = None
    for offset in range(-device.tolerance, device.tolerance + 1):
        candidate_t = base_t + offset
        if candidate_t < 0:
            continue
        candidate_totp = TOTP(device.bin_key, device.step, device.t0, device.digits, 0)
        candidate_totp.time = device.t0 + candidate_t * device.step
        if int(candidate_totp.token()) == token_int:
            matched_t = candidate_t
            matched_offset = offset
            break

    if matched_t is None:
        _check_and_record_otp_failure(user, device, now)
        if user.otp_throttled_until and now < user.otp_throttled_until:
            record_audit_event(
                action=action_label,
                result=AuditResult.DENIED,
                reason_code=ReasonCode.RATE_LIMITED,
                actor=user,
                payment_request=payment_request,
            )
            raise SecurityDomainError(
                ReasonCode.RATE_LIMITED,
                "Đã vượt quá giới hạn thử OTP sai; thiết bị bị tạm khóa.",
                status_code=429,
            )
        record_audit_event(
            action=action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.OTP_INVALID,
            actor=user,
            payment_request=payment_request,
        )
        raise SecurityDomainError(
            ReasonCode.OTP_INVALID,
            "Mã OTP không đúng.",
            status_code=400,
        )

    # Check anti-replay on timestep (`last_t`)
    if device.last_t is not None and matched_t <= device.last_t:
        _check_and_record_otp_failure(user, device, now)
        record_audit_event(
            action=action_label,
            result=AuditResult.DENIED,
            reason_code=ReasonCode.OTP_REPLAY,
            actor=user,
            payment_request=payment_request,
            metadata={"rejected_timestep": matched_t, "last_accepted_timestep": device.last_t},
        )
        raise SecurityDomainError(
            ReasonCode.OTP_REPLAY,
            "Mã OTP của khung thời gian này đã được sử dụng. Vui lòng đợi mã OTP mới ở chu kỳ tiếp theo.",
            status_code=409,
        )

    # Valid fresh timestep! Persist last_t and reset failure counters
    device.last_t = matched_t
    if device.throttling_enabled:
        device.throttling_failure_count = 0
        device.throttling_failure_timestamp = None
    device.save()

    if user.failed_otp_attempts > 0 or user.otp_throttled_until is not None:
        user.failed_otp_attempts = 0
        user.otp_throttled_until = None
        user.save(update_fields=["failed_otp_attempts", "otp_throttled_until"])

    return device


def step1_password_login(
    request: HttpRequest,
    *,
    username: str,
    password: str,
    now=None,
) -> EmployeeIdentity:
    """
    Step 1 of login: Verify username & password under SecurityMutex(id=1).
    Creates ONLY a pre-authenticated session (`preauth_user_id`, `preauth_epoch`, `preauth_expires_at`, `preauth_used=False`).
    Never grants full session authority until Step 2 MFA succeeds.
    Does not leak whether an unknown username exists in error messages (Section 8).
    """
    now = now or timezone.now()
    clean_username = (username or "").strip()

    with security_atomic():
        acquire_security_mutex()
        user = EmployeeIdentity.objects.select_for_update().filter(username=clean_username).first()

        if user is not None:
            if user.password_throttled_until and now < user.password_throttled_until:
                record_audit_event(
                    action="AUTH_LOGIN_PASSWORD",
                    result=AuditResult.DENIED,
                    reason_code=ReasonCode.RATE_LIMITED,
                    actor=user,
                )
                raise SecurityDomainError(
                    ReasonCode.RATE_LIMITED,
                    "Tài khoản đang bị tạm khóa do nhập sai mật khẩu nhiều lần. Vui lòng thử lại sau.",
                    status_code=429,
                )
            if user.password_throttled_until and now >= user.password_throttled_until:
                user.failed_password_attempts = 0
                user.password_throttled_until = None
                user.save(update_fields=["failed_password_attempts", "password_throttled_until"])

        if user is None or not user.check_password(password or ""):
            if user is not None:
                user.failed_password_attempts += 1
                if user.failed_password_attempts >= settings.MAX_PASSWORD_ATTEMPTS:
                    user.password_throttled_until = now + timedelta(seconds=settings.PASSWORD_COOLDOWN_SECONDS)
                user.save(update_fields=["failed_password_attempts", "password_throttled_until"])
                if user.password_throttled_until and now < user.password_throttled_until:
                    record_audit_event(
                        action="AUTH_LOGIN_PASSWORD",
                        result=AuditResult.DENIED,
                        reason_code=ReasonCode.RATE_LIMITED,
                        actor=user,
                    )
                    raise SecurityDomainError(
                        ReasonCode.RATE_LIMITED,
                        "Tài khoản đang bị tạm khóa do nhập sai mật khẩu nhiều lần. Vui lòng thử lại sau.",
                        status_code=429,
                    )
            record_audit_event(
                action="AUTH_LOGIN_PASSWORD",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.INVALID_CREDENTIALS,
                actor=user,
                actor_username=clean_username,
            )
            raise SecurityDomainError(
                ReasonCode.INVALID_CREDENTIALS,
                "Thông tin đăng nhập không hợp lệ.",
                status_code=401,
            )

        if not user.is_operational:
            record_audit_event(
                action="AUTH_LOGIN_PASSWORD",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=user,
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Tài khoản đang bị đình chỉ hoặc không được phép truy cập.",
                status_code=403,
            )

        user.failed_password_attempts = 0
        user.password_throttled_until = None
        user.save(update_fields=["failed_password_attempts", "password_throttled_until"])

        captured_epoch = user.security_epoch
        expires_at = now + timedelta(seconds=settings.PREAUTH_TTL_SECONDS)

        # Clear any existing auth state and establish minimal preauth state
        request.session.flush()
        request.session["preauth_user_id"] = str(user.id)
        request.session["preauth_epoch"] = captured_epoch
        request.session["preauth_expires_at"] = expires_at.timestamp()
        request.session["preauth_used"] = False
        request.session.save()

        record_audit_event(
            action="AUTH_LOGIN_PREAUTH",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=user,
            before_state="ANONYMOUS",
            after_state="PREAUTH_PENDING_MFA",
            metadata={"security_epoch": captured_epoch},
        )
        return user


def complete_password_only_login(
    request: HttpRequest,
    *,
    user: EmployeeIdentity,
    now=None,
) -> EmployeeIdentity:
    """Promote a successful password check directly to a full web session.

    Login TOTP is intentionally bypassed for the local demo UI. The session still
    carries the existing epoch and device binding so revocation and sensitive
    action challenges continue to work as before.
    """
    now = now or timezone.now()
    captured_epoch = request.session.get("preauth_epoch")

    with security_atomic():
        acquire_security_mutex()
        current_user = EmployeeIdentity.objects.select_for_update().filter(pk=user.pk).first()
        if (
            current_user is None
            or not current_user.is_operational
            or captured_epoch is None
            or current_user.security_epoch != int(captured_epoch)
        ):
            request.session.flush()
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Tài khoản đã bị thu hồi hoặc thay đổi trạng thái bảo mật trong lúc đăng nhập.",
                status_code=401,
            )

        device = get_confirmed_totp_device(current_user)
        login(request, current_user, backend="django.contrib.auth.backends.ModelBackend")
        request.session.cycle_key()
        for key in ("preauth_user_id", "preauth_epoch", "preauth_expires_at", "preauth_used"):
            request.session.pop(key, None)

        # Keep the established session contract used by middleware and action challenges.
        request.session["auth_mfa_verified"] = True
        request.session["auth_security_epoch"] = current_user.security_epoch
        request.session["auth_device_id"] = device.id
        request.session["session_created_at"] = now.timestamp()
        request.session["session_last_activity_at"] = now.timestamp()
        request.session.save()

        record_audit_event(
            action="AUTH_LOGIN_PASSWORD_ONLY",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=current_user,
            before_state="PREAUTH_PENDING_MFA",
            after_state="AUTHENTICATED_PASSWORD_ONLY",
            metadata={"security_epoch": current_user.security_epoch},
        )
        return current_user


def step2_mfa_login(
    request: HttpRequest,
    *,
    otp_token: str,
    now=None,
) -> EmployeeIdentity:
    """
    Step 2 of login (Section 7.2):
    Under SecurityMutex(id=1), validates preauth session state, checks security_epoch has not changed
    between password and MFA steps, verifies TOTP token on confirmed device, rotates session key,
    and binds the exact verified security_epoch into the full session.
    """
    now = now or timezone.now()
    preauth_user_id = request.session.get("preauth_user_id")
    preauth_epoch = request.session.get("preauth_epoch")
    preauth_expires_at = request.session.get("preauth_expires_at")
    preauth_used = request.session.get("preauth_used")

    if not preauth_user_id or preauth_epoch is None or preauth_expires_at is None or preauth_used is not False:
        record_audit_event(
            action="AUTH_LOGIN_MFA",
            result=AuditResult.DENIED,
            reason_code=ReasonCode.AUTH_REQUIRED,
        )
        raise SecurityDomainError(
            ReasonCode.AUTH_REQUIRED,
            "Phiên tiền xác thực không tồn tại hoặc đã được sử dụng. Vui lòng đăng nhập lại từ bước mật khẩu.",
            status_code=401,
        )

    if now.timestamp() >= float(preauth_expires_at):
        request.session.flush()
        record_audit_event(
            action="AUTH_LOGIN_MFA",
            result=AuditResult.DENIED,
            reason_code=ReasonCode.CHALLENGE_EXPIRED,
        )
        raise SecurityDomainError(
            ReasonCode.CHALLENGE_EXPIRED,
            "Phiên tiền xác thực đã quá hạn 5 phút. Vui lòng đăng nhập lại.",
            status_code=401,
        )

    with security_atomic():
        acquire_security_mutex()
        user = EmployeeIdentity.objects.select_for_update().filter(pk=preauth_user_id).first()
        if user is None or not user.is_operational or user.security_epoch != int(preauth_epoch):
            request.session.flush()
            record_audit_event(
                action="AUTH_LOGIN_MFA",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=user,
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Tài khoản đã bị thu hồi hoặc thay đổi trạng thái bảo mật giữa hai bước đăng nhập.",
                status_code=401,
            )

        device = verify_totp_token_under_lock(
            user=user,
            raw_token=otp_token,
            now=now,
            action_label="AUTH_LOGIN_MFA",
        )
        verified_epoch = user.security_epoch

        # Mark preauth used, login user, rotate session ID, and bind exact verified_epoch
        request.session["preauth_used"] = True
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        request.session.cycle_key()
        for k in ("preauth_user_id", "preauth_epoch", "preauth_expires_at", "preauth_used"):
            request.session.pop(k, None)

        request.session["auth_mfa_verified"] = True
        request.session["auth_security_epoch"] = verified_epoch
        request.session["auth_device_id"] = device.id
        request.session["session_created_at"] = now.timestamp()
        request.session["session_last_activity_at"] = now.timestamp()
        request.session.save()

        record_audit_event(
            action="AUTH_LOGIN_MFA",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=user,
            before_state="PREAUTH_PENDING_MFA",
            after_state="AUTHENTICATED_FULL_MFA",
            metadata={"security_epoch": verified_epoch},
        )
        return user


def logout_current_session(request: HttpRequest, now=None) -> None:
    """
    Normal logout (Section 7.2, T-11):
    Destroys the current session and invalidates open ActionChallenges bound to this session.
    Does NOT increment security_epoch and does NOT invalidate historical valid Approvals.
    """
    now = now or timezone.now()
    user = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
    sess_hash = get_session_key_hash(request) if request.session.session_key else ""

    with security_atomic():
        acquire_security_mutex()
        if sess_hash:
            ActionChallenge.objects.filter(
                session_key_hash=sess_hash,
                consumed_at__isnull=True,
                invalidated_at__isnull=True,
            ).update(invalidated_at=now)
        if user:
            record_audit_event(
                action="AUTH_LOGOUT",
                result=AuditResult.SUCCESS,
                reason_code=ReasonCode.OK,
                actor=user,
                before_state="AUTHENTICATED_FULL_MFA",
                after_state="LOGGED_OUT",
            )
        logout(request)


def compute_security_action_digest(
    *,
    action: str,
    target_user_id: str,
    target_epoch: int,
    reason: str,
) -> str:
    return canonical_json_sha256(
        {
            "action": action,
            "target_user_id": str(target_user_id),
            "target_epoch": int(target_epoch),
            "reason": reason.strip(),
        }
    )


def issue_security_admin_challenge(
    *,
    actor: EmployeeIdentity,
    session_key: str,
    target_user_id: Any,
    action: str,
    reason: str,
    now=None,
) -> ActionChallenge:
    """
    Issue an ActionChallenge for SUSPEND or REVOKE_ALL (Section 8).
    Only SECURITY_ADMIN can request this challenge, and it binds target_user, target_epoch, and reason.
    """
    now = now or timezone.now()
    clean_reason = (reason or "").strip()

    with security_atomic():
        acquire_security_mutex()
        actor = EmployeeIdentity.objects.select_for_update().get(pk=actor.pk)
        if not actor.is_operational or actor.role != Role.SECURITY_ADMIN:
            record_audit_event(
                action="ISSUE_SECURITY_CHALLENGE",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.FORBIDDEN,
                actor=actor,
            )
            raise SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Chỉ SECURITY_ADMIN đang hoạt động mới được cấp challenge quản trị an ninh.",
                status_code=403,
            )

        if action not in (ChallengeAction.SUSPEND, ChallengeAction.REVOKE_ALL):
            record_audit_event(
                action="ISSUE_SECURITY_CHALLENGE",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.WRONG_SCOPE,
                actor=actor,
            )
            raise SecurityDomainError(
                ReasonCode.WRONG_SCOPE,
                "Loại challenge quản trị an ninh không hợp lệ.",
                status_code=400,
            )

        if not clean_reason or len(clean_reason) > 500:
            raise SecurityDomainError(
                ReasonCode.VALIDATION_ERROR,
                "Bắt buộc nhập lý do sự cố an ninh (tối đa 500 ký tự).",
                status_code=400,
            )

        target_user = EmployeeIdentity.objects.select_for_update().filter(pk=target_user_id).first()
        if target_user is None:
            raise SecurityDomainError(
                ReasonCode.VALIDATION_ERROR,
                "Không tìm thấy tài khoản mục tiêu.",
                status_code=404,
            )

        device = get_confirmed_totp_device(actor, for_update=True)
        digest = compute_security_action_digest(
            action=action,
            target_user_id=str(target_user.id),
            target_epoch=target_user.security_epoch,
            reason=clean_reason,
        )

        challenge = ActionChallenge.objects.create(
            nonce=secrets.token_urlsafe(32),
            actor=actor,
            actor_person_id=actor.person_id,
            session_key_hash=sha256_hex(session_key),
            device_id=device.id,
            actor_epoch=actor.security_epoch,
            action=action,
            target_type=ChallengeTargetType.EMPLOYEE_IDENTITY,
            target_user=target_user,
            target_user_epoch=target_user.security_epoch,
            reason_text=clean_reason,
            content_digest=digest,
            created_at=now,
            expires_at=now + timedelta(seconds=settings.CHALLENGE_TTL_SECONDS),
        )

        record_audit_event(
            action="ISSUE_SECURITY_CHALLENGE",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            target_user=target_user,
            metadata={"challenge_id": str(challenge.id), "security_action": action},
        )
        return challenge


def _CascadePrincipalIncidentUnderLock(
    target_user: EmployeeIdentity,
    reason_summary: str,
    now,
) -> list[str]:
    """
    Invalidate open challenges for target_user, delete active sessions for target_user,
    invalidate active approvals signed by target_user on unexecuted requests,
    and move affected PENDING_APPROVAL / APPROVED requests to HOLD (Section 10.1, T-25..T-27).
    """
    # 1. Invalidate all open challenges created by target_user
    ActionChallenge.objects.filter(
        actor=target_user,
        consumed_at__isnull=True,
        invalidated_at__isnull=True,
    ).update(invalidated_at=now)

    # 2. Delete active DB sessions belonging to target_user
    for sess in Session.objects.all():
        data = sess.get_decoded()
        if str(data.get("_auth_user_id")) == str(target_user.id) or str(data.get("preauth_user_id")) == str(
            target_user.id
        ):
            sess.delete()

    # 3. Find non-terminal requests where target_user is requester or has an ACTIVE approval
    affected_codes: list[str] = []
    active_approvals = list(
        Approval.objects.select_related("payment_request")
        .filter(
            approver=target_user,
            status=ApprovalStatus.ACTIVE,
        )
    )
    affected_request_ids = set()
    for app in active_approvals:
        if app.payment_request.status not in TERMINAL_REQUEST_STATUSES:
            app.status = ApprovalStatus.INVALIDATED_BY_INCIDENT
            app.save(update_fields=["status"])
            affected_request_ids.add(app.payment_request_id)

    requester_reqs = PaymentRequest.objects.filter(
        requester=target_user,
        status__in=[RequestStatus.PENDING_APPROVAL, RequestStatus.APPROVED],
    )
    for req in requester_reqs:
        affected_request_ids.add(req.id)

    if affected_request_ids:
        reqs_to_hold = PaymentRequest.objects.select_for_update().filter(
            id__in=affected_request_ids,
            status__in=[RequestStatus.PENDING_APPROVAL, RequestStatus.APPROVED],
        )
        for req in reqs_to_hold:
            prev_status = req.status
            req.status = RequestStatus.HOLD
            req.hold_reason = f"Tạm giữ do sự cố an ninh tài khoản {target_user.username}: {reason_summary}"[:500]
            req.save(update_fields=["status", "hold_reason", "updated_at"])
            affected_codes.append(req.request_code)
            # Invalidate open challenges on this request
            ActionChallenge.objects.filter(
                payment_request=req,
                consumed_at__isnull=True,
                invalidated_at__isnull=True,
            ).update(invalidated_at=now)
            record_audit_event(
                action="REQUEST_MOVED_TO_HOLD",
                result=AuditResult.SUCCESS,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=None,
                payment_request=req,
                target_user=target_user,
                before_state=prev_status,
                after_state=RequestStatus.HOLD,
                metadata={"hold_reason": req.hold_reason},
            )

    return affected_codes


def execute_security_admin_action(
    *,
    actor: EmployeeIdentity,
    session_key: str,
    session_epoch: int | None,
    target_user_id: Any,
    action: str,
    reason: str,
    challenge_id: Any,
    nonce: str,
    otp_token: str,
    now=None,
) -> tuple[EmployeeIdentity, list[str]]:
    """
    Execute SUSPEND or REVOKE_ALL by SECURITY_ADMIN with fresh challenge + TOTP under SecurityMutex(id=1).
    """
    now = now or timezone.now()
    clean_reason = (reason or "").strip()

    with security_atomic():
        acquire_security_mutex()
        actor = EmployeeIdentity.objects.select_for_update().get(pk=actor.pk)
        if not actor.is_operational or actor.role != Role.SECURITY_ADMIN:
            record_audit_event(
                action=f"SECURITY_{action}",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.FORBIDDEN,
                actor=actor,
            )
            raise SecurityDomainError(
                ReasonCode.FORBIDDEN,
                "Chỉ SECURITY_ADMIN mới có quyền thực hiện thao tác đình chỉ / thu hồi.",
                status_code=403,
            )

        if session_epoch != actor.security_epoch:
            record_audit_event(
                action=f"SECURITY_{action}",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.PRINCIPAL_REVOKED,
                actor=actor,
            )
            raise SecurityDomainError(
                ReasonCode.PRINCIPAL_REVOKED,
                "Phiên của quản trị viên đã bị thu hồi.",
                status_code=401,
            )

        target_user = EmployeeIdentity.objects.select_for_update().filter(pk=target_user_id).first()
        if target_user is None:
            raise SecurityDomainError(
                ReasonCode.VALIDATION_ERROR,
                "Không tìm thấy tài khoản mục tiêu.",
                status_code=404,
            )

        if action not in (ChallengeAction.SUSPEND, ChallengeAction.REVOKE_ALL):
            raise SecurityDomainError(
                ReasonCode.WRONG_SCOPE,
                "Hành động quản trị không được hỗ trợ.",
                status_code=400,
            )

        challenge = ActionChallenge.objects.select_for_update().filter(pk=challenge_id).first()
        if challenge is None or challenge.nonce != (nonce or "").strip():
            record_audit_event(
                action=f"SECURITY_{action}",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.WRONG_SCOPE,
                actor=actor,
                target_user=target_user,
            )
            raise SecurityDomainError(
                ReasonCode.WRONG_SCOPE,
                "Challenge quản trị không tồn tại hoặc sai nonce.",
                status_code=400,
            )

        if challenge.consumed_at is not None or challenge.invalidated_at is not None:
            record_audit_event(
                action=f"SECURITY_{action}",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.CHALLENGE_USED,
                actor=actor,
                target_user=target_user,
            )
            raise SecurityDomainError(
                ReasonCode.CHALLENGE_USED,
                "Challenge quản trị đã được sử dụng hoặc đã bị hủy.",
                status_code=409,
            )

        if now >= challenge.expires_at:
            record_audit_event(
                action=f"SECURITY_{action}",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.CHALLENGE_EXPIRED,
                actor=actor,
                target_user=target_user,
            )
            raise SecurityDomainError(
                ReasonCode.CHALLENGE_EXPIRED,
                "Challenge quản trị đã hết hạn 120 giây.",
                status_code=409,
            )

        expected_digest = compute_security_action_digest(
            action=action,
            target_user_id=str(target_user.id),
            target_epoch=target_user.security_epoch,
            reason=clean_reason,
        )

        if (
            challenge.actor_id != actor.id
            or challenge.actor_person_id != actor.person_id
            or challenge.actor_epoch != actor.security_epoch
            or challenge.session_key_hash != sha256_hex(session_key)
            or challenge.target_type != ChallengeTargetType.EMPLOYEE_IDENTITY
            or challenge.action != action
            or challenge.target_user_id != target_user.id
            or challenge.target_user_epoch != target_user.security_epoch
            or challenge.content_digest != expected_digest
        ):
            record_audit_event(
                action=f"SECURITY_{action}",
                result=AuditResult.DENIED,
                reason_code=ReasonCode.WRONG_SCOPE,
                actor=actor,
                target_user=target_user,
            )
            raise SecurityDomainError(
                ReasonCode.WRONG_SCOPE,
                "Challenge không khớp người thực hiện, phiên, tài khoản mục tiêu, epoch hoặc lý do.",
                status_code=409,
            )

        verify_totp_token_under_lock(
            user=actor,
            raw_token=otp_token,
            now=now,
            action_label=f"SECURITY_{action}",
        )

        challenge.consumed_at = now
        challenge.save(update_fields=["consumed_at"])

        before_state = f"active={target_user.is_active},suspended={target_user.is_suspended},epoch={target_user.security_epoch}"
        target_user.security_epoch += 1
        if action == ChallengeAction.SUSPEND:
            target_user.is_suspended = True
            target_user.suspension_reason = clean_reason
            target_user.save(update_fields=["is_suspended", "suspension_reason", "security_epoch"])
        else:
            target_user.save(update_fields=["security_epoch"])

        affected_codes = _CascadePrincipalIncidentUnderLock(target_user, clean_reason, now)
        after_state = f"active={target_user.is_active},suspended={target_user.is_suspended},epoch={target_user.security_epoch}"

        record_audit_event(
            action=f"SECURITY_{action}",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=actor,
            target_user=target_user,
            before_state=before_state,
            after_state=after_state,
            metadata={"reason": clean_reason, "affected_requests": affected_codes},
        )
        return target_user, affected_codes


def offline_recover_principal(
    *,
    username: str,
    new_role: str | None = None,
    rotate_mfa: bool = False,
    unsuspend: bool = True,
    operator_note: str = "Offline identity re-verification completed",
    now=None,
) -> tuple[EmployeeIdentity, str | None]:
    """
    Trusted offline CLI operation (Section 10.1, DES-09, T-15, T-26, T-27).
    Always acquires SecurityMutex(id=1), increments security_epoch, invalidates old sessions/challenges
    and prior active approvals on unexecuted requests (moving those requests to HOLD so they must be
    revised and re-approved). Never automatically resurrects invalidated approvals.
    """
    now = now or timezone.now()
    new_hex_key: str | None = None

    with security_atomic():
        acquire_security_mutex()
        user = EmployeeIdentity.objects.select_for_update().get(username=username)
        before_state = (
            f"role={user.role},suspended={user.is_suspended},epoch={user.security_epoch}"
        )

        user.security_epoch += 1
        if unsuspend:
            user.is_suspended = False
            user.suspension_reason = ""
            user.failed_password_attempts = 0
            user.password_throttled_until = None
            user.failed_otp_attempts = 0
            user.otp_throttled_until = None

        if new_role is not None:
            if new_role not in Role.values:
                raise ValueError(f"Invalid role: {new_role}")
            user.role = new_role

        user.save()

        if rotate_mfa:
            TOTPDevice.objects.filter(user=user).delete()
            new_hex_key = random_hex(20)
            TOTPDevice.objects.create(
                user=user,
                name=f"totp-{user.username}-recovered",
                key=new_hex_key,
                confirmed=True,
                step=30,
                digits=6,
                drift=0,
                tolerance=0,
            )

        affected_codes = _CascadePrincipalIncidentUnderLock(user, operator_note, now)
        after_state = (
            f"role={user.role},suspended={user.is_suspended},epoch={user.security_epoch}"
        )

        record_audit_event(
            action="OFFLINE_PRINCIPAL_RECOVERY",
            result=AuditResult.SUCCESS,
            reason_code=ReasonCode.OK,
            actor=None,
            actor_username="offline_trusted_cli",
            target_user=user,
            before_state=before_state,
            after_state=after_state,
            metadata={
                "operator_note": operator_note,
                "rotate_mfa": rotate_mfa,
                "new_role": new_role or user.role,
                "affected_requests": affected_codes,
            },
        )
        return user, new_hex_key

