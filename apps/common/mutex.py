"""
SecurityMutex locking primitive for PostgreSQL (DES-08).
"""
from __future__ import annotations

import contextlib
from django.db import transaction

from apps.common.exceptions import ReasonCode, SecurityDomainError
from apps.common.models import SecurityMutex


@contextlib.contextmanager
def security_atomic():
    """
    Wraps `transaction.atomic()` so that if `SecurityDomainError` is raised with
    `commit_denial=True` (the default for controlled security denials, throttle increments,
    HOLD/EXPIRED transitions, and DENIED AuditEvents), the transaction commits cleanly
    before re-raising `SecurityDomainError`. Any other exception (or `commit_denial=False`)
    rolls back the transaction atomically.
    """
    captured_denial: SecurityDomainError | None = None
    with transaction.atomic():
        try:
            yield
        except SecurityDomainError as exc:
            if not exc.commit_denial:
                raise
            captured_denial = exc
    if captured_denial is not None:
        raise captured_denial



def acquire_security_mutex() -> SecurityMutex:
    """
    Acquire row-level exclusive lock on SecurityMutex(id=1) inside an atomic block.
    Fails closed if not in an atomic block or if row id=1 does not exist.
    """
    connection = transaction.get_connection()
    if not connection.in_atomic_block:
        raise SecurityDomainError(
            ReasonCode.INTERNAL_ERROR,
            "Thao tác nhạy cảm bắt buộc chạy trong transaction.atomic().",
            status_code=500,
            commit_denial=False,
        )
    try:
        return SecurityMutex.objects.select_for_update().get(pk=1)
    except SecurityMutex.DoesNotExist as exc:
        raise SecurityDomainError(
            ReasonCode.MUTEX_MISSING,
            "Không tìm thấy hàng khóa an ninh SecurityMutex(id=1); hệ thống từ chối an toàn (Fail-Closed).",
            status_code=503,
            commit_denial=False,
        ) from exc

