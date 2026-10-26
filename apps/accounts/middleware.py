"""
Session security middleware enforcing:
1. Full MFA completion check (`auth_mfa_verified == True`).
2. `auth_security_epoch == user.security_epoch` (immediate session revocation when epoch increments).
3. Idle timeout (30m) and max lifetime (8h) according to server UTC clock (Section 3.1 & 7.2).
"""
from __future__ import annotations

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest, HttpResponse
from django.utils import timezone


class SecurityEpochSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            now_ts = timezone.now().timestamp()
            mfa_verified = request.session.get("auth_mfa_verified") is True
            sess_epoch = request.session.get("auth_security_epoch")
            created_at = request.session.get("session_created_at")
            last_activity = request.session.get("session_last_activity_at")

            invalid_session = False
            if not mfa_verified or sess_epoch is None:
                invalid_session = True
            elif not getattr(user, "is_operational", False) or int(sess_epoch) != user.security_epoch:
                invalid_session = True
            elif created_at is not None and (now_ts - float(created_at)) >= settings.SESSION_MAX_LIFETIME_SECONDS:
                invalid_session = True
            elif last_activity is not None and (now_ts - float(last_activity)) >= settings.SESSION_IDLE_TIMEOUT_SECONDS:
                invalid_session = True

            if invalid_session:
                logout(request)
                request.user = AnonymousUser()
            else:
                request.session["session_last_activity_at"] = now_ts

        return self.get_response(request)

