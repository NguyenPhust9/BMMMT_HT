"""
Audit recording and secret sanitization service (Section 10.2, T-38).
"""
from __future__ import annotations

import uuid
from typing import Any
from django.utils import timezone

from apps.accounts.models import EmployeeIdentity, Role
from apps.audit.models import AuditEvent, AuditResult

FORBIDDEN_METADATA_SUBSTRINGS = (
    "password",
    "passwd",
    "pwd",
    "otp",
    "totp",
    "token",
    "secret",
    "seed",
    "bin_key",
    "provisioning",
    "otpauth",
    "cookie",
    "sessionid",
    "session_key",
    "csrf",
    "recovery",
)


def sanitize_metadata(data: dict[str, Any] | None) -> dict[str, Any]:
    """
    Strip any key whose name suggests secret material and scrub otpauth:// URIs from values.
    """
    if not data:
        return {}
    cleaned: dict[str, Any] = {}
    for k, v in data.items():
        key_lower = str(k).lower()
        if any(bad in key_lower for bad in FORBIDDEN_METADATA_SUBSTRINGS):
            continue
        if isinstance(v, dict):
            cleaned[str(k)] = sanitize_metadata(v)
        elif isinstance(v, (list, tuple)):
            cleaned[str(k)] = [
                "[REDACTED]" if isinstance(item, str) and "otpauth://" in item.lower() else item
                for item in v
            ]
        elif isinstance(v, str):
            if "otpauth://" in v.lower():
                cleaned[str(k)] = "[REDACTED]"
            else:
                cleaned[str(k)] = v[:500]
        elif isinstance(v, (int, float, bool)) or v is None:
            cleaned[str(k)] = v
        else:
            cleaned[str(k)] = str(v)[:300]
    return cleaned


def record_audit_event(
    *,
    action: str,
    result: str = AuditResult.SUCCESS,
    reason_code: str = "OK",
    actor: EmployeeIdentity | None = None,
    actor_username: str = "",
    payment_request: Any = None,
    revision_number: int | None = None,
    target_user: EmployeeIdentity | None = None,
    before_state: str = "",
    after_state: str = "",
    correlation_id: str = "",
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    username_snap = actor.username if actor else (actor_username[:150] if actor_username else "anonymous")
    person_snap = actor.person_id if actor else ""
    role_snap = actor.role if actor else ""

    if revision_number is None and payment_request is not None and getattr(payment_request, "current_revision", None):
        revision_number = payment_request.current_revision.revision_number

    return AuditEvent.objects.create(
        actor=actor if (actor and getattr(actor, "pk", None)) else None,
        actor_username_snapshot=username_snap,
        actor_person_id=person_snap,
        actor_role=role_snap,
        action=action,
        payment_request=payment_request,
        revision_number=revision_number,
        target_user=target_user,
        result=result,
        reason_code=reason_code,
        before_state=before_state or "",
        after_state=after_state or "",
        correlation_id=correlation_id or uuid.uuid4().hex[:16],
        metadata=sanitize_metadata(metadata),
        created_at=timezone.now(),
    )


def get_scoped_audit_events(user: EmployeeIdentity):
    """
    Role-scoped query for audit events (Section 6.1, 10.2, T-38):
    - REQUESTER: only events tied to payment_requests created by this requester, or their own auth events.
    - DIRECTOR / CONTROLLER: business payment request timeline events in the company scope.
    - SECURITY_ADMIN: all security/incident/auth/payment metadata events (sensitive business purpose redacted in view).
    - UNPRIVILEGED: none.
    """
    if not user or not user.is_authenticated:
        return AuditEvent.objects.none()
    if user.role == Role.REQUESTER:
        return AuditEvent.objects.select_related("payment_request", "actor", "target_user").filter(
            payment_request__requester=user
        )
    if user.role in (Role.DIRECTOR, Role.CONTROLLER):
        return AuditEvent.objects.select_related("payment_request", "actor", "target_user").exclude(
            payment_request__isnull=True
        )
    if user.role == Role.SECURITY_ADMIN:
        return AuditEvent.objects.select_related("payment_request", "actor", "target_user").all()
    return AuditEvent.objects.none()

