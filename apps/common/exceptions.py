"""
Reason codes and domain exceptions for SecurePay Lab (Section 8).
"""
from __future__ import annotations

from typing import Any


class ReasonCode:
    OK = "OK"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    MFA_REQUIRED = "MFA_REQUIRED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    FORBIDDEN = "FORBIDDEN"
    SELF_APPROVAL = "SELF_APPROVAL"
    DUPLICATE_APPROVER = "DUPLICATE_APPROVER"
    MISSING_APPROVAL = "MISSING_APPROVAL"
    SNAPSHOT_MISMATCH = "SNAPSHOT_MISMATCH"
    IMMUTABLE_REVISION = "IMMUTABLE_REVISION"
    WRONG_SCOPE = "WRONG_SCOPE"
    CHALLENGE_EXPIRED = "CHALLENGE_EXPIRED"
    CHALLENGE_USED = "CHALLENGE_USED"
    OTP_INVALID = "OTP_INVALID"
    OTP_REPLAY = "OTP_REPLAY"
    PRINCIPAL_REVOKED = "PRINCIPAL_REVOKED"
    BENEFICIARY_INVALID = "BENEFICIARY_INVALID"
    TERMINAL_STATE = "TERMINAL_STATE"
    REQUEST_EXPIRED = "REQUEST_EXPIRED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    RATE_LIMITED = "RATE_LIMITED"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    MUTEX_MISSING = "MUTEX_MISSING"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class SecurityDomainError(Exception):
    """
    Structured domain error carrying a server reason_code, HTTP status_code,
    user-safe message, and whether the current DB transaction (e.g. throttle + denied audit)
    should be committed rather than rolled back.
    """

    def __init__(
        self,
        reason_code: str,
        message: str,
        status_code: int = 400,
        commit_denial: bool = True,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.status_code = status_code
        self.commit_denial = commit_denial
        self.extra = extra or {}

