from __future__ import annotations

from django.http import HttpRequest


def security_context(request: HttpRequest) -> dict:
    user = getattr(request, "user", None)
    is_full_mfa = bool(
        user
        and getattr(user, "is_authenticated", False)
        and request.session.get("auth_mfa_verified") is True
        and request.session.get("auth_security_epoch") == getattr(user, "security_epoch", None)
    )
    return {
        "is_full_mfa_authenticated": is_full_mfa,
        "current_role": getattr(user, "role", None) if is_full_mfa else None,
        "current_person_id": getattr(user, "person_id", None) if is_full_mfa else None,
    }

