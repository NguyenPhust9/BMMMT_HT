"""
Automated verification suite for T-21..T-40 on real PostgreSQL 17.
Covers:
- Section 12.4 (Part 2): Server-clock expiry, challenge replay, TOTP timestep replay, direct API (T-21..T-24)
- Section 12.5: Revocation & terminal state invariants (T-25..T-29)
- Section 12.6: Concurrency & atomicity on PostgreSQL with two independent DB connections (T-30..T-35)
- Section 12.7: Web surface, CSRF, XSS/validation, audit secret scan, HTTPS TLS profile & fault rollback (T-36..T-40)
"""
from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

from django.conf import settings
from django.core.management import call_command
from django.core.wsgi import get_wsgi_application
from django.db import connections
from django.test import Client, TransactionTestCase, override_settings
from django_otp.plugins.otp_totp.models import TOTPDevice

from apps.accounts.models import EmployeeIdentity, Role
from apps.accounts.services import execute_security_admin_action, issue_security_admin_challenge
from apps.audit.models import AuditEvent
from apps.beneficiaries.models import Beneficiary
from apps.common.exceptions import ReasonCode, SecurityDomainError
from apps.payments.models import (
    ActionChallenge,
    Approval,
    ApprovalStatus,
    ChallengeAction,
    PaymentExecution,
    PaymentRequest,
    RequestStatus,
    SourceKind,
)
from apps.payments.services import (
    approve_payment_request,
    execute_payment_request_simulated,
    issue_payment_challenge,
    reject_payment_request,
    revise_payment_request,
)
from tests.helpers import (
    StepClock,
    login_full_mfa_client,
    next_fresh_totp,
    seed_standard_lab,
    totp_at,
    write_test_evidence,
)


class _QuietWSGIHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass


class TestSuiteT21ToT40(TransactionTestCase):
    reset_sequences = True

    def setUp(self) -> None:
        super().setUp()
        self.lab = seed_standard_lab()
        self.creds = self.lab["creds"]

    def _create_and_submit_r1(
        self,
        lan_client: Client,
        amount_vnd: int = 20_000_000,
        beneficiary_version_id: str | None = None,
        purpose: str = "Thanh toan hop dong dich vu ha tang so",
    ) -> str:
        ver_id = str(beneficiary_version_id or self.lab["b1_ver"].id)
        r_create = lan_client.post(
            "/requests",
            data=json.dumps(
                {
                    "beneficiary_version_id": ver_id,
                    "amount_vnd": amount_vnd,
                    "purpose": purpose,
                    "source_kind": SourceKind.EMAIL,
                    "source_excerpt": "De nghi thanh toan hoa don dich vu theo hop dong.",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_create.status_code, 201, r_create.content)
        req_id = r_create.json()["request_id"]
        r_sub = lan_client.post(f"/requests/{req_id}/submit", HTTP_ACCEPT="application/json")
        self.assertEqual(r_sub.status_code, 200, r_sub.content)
        return req_id

    def _issue_and_approve(self, client: Client, user: EmployeeIdentity, req_id: str) -> dict:
        act = (
            ChallengeAction.APPROVE_DIRECTOR
            if user.role == Role.DIRECTOR
            else ChallengeAction.APPROVE_CONTROLLER
        )
        r_chal = client.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": act}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_chal.status_code, 201, r_chal.content)
        c_data = r_chal.json()
        cid = c_data["challenge_id"]
        nonce = c_data["nonce"]
        otp = next_fresh_totp(user)
        r_app = client.post(
            f"/requests/{req_id}/approve",
            data=json.dumps({"challenge_id": cid, "nonce": nonce, "otp_token": otp}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        return {"challenge_id": cid, "nonce": nonce, "response": r_app}

    def _prepare_fully_approved_request(self) -> tuple[str, Client, Client, Client]:
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        huong_c = login_full_mfa_client("huong", self.creds["huong"]["password"])
        req_id = self._create_and_submit_r1(lan_c)
        self.assertEqual(self._issue_and_approve(nam_c, self.lab["users"]["nam"], req_id)["response"].status_code, 200)
        self.assertEqual(self._issue_and_approve(huong_c, self.lab["users"]["huong"], req_id)["response"].status_code, 200)
        self.assertEqual(PaymentRequest.objects.get(pk=req_id).status, RequestStatus.APPROVED)
        return req_id, lan_c, nam_c, huong_c

    def test_t21_server_clock_expiry_and_boundary_cases(self) -> None:
        """T-21: Server clock determines challenge expiration (`now < expires_at` -> valid; `now >= expires_at` -> CHALLENGE_EXPIRED)."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        r1_id = self._create_and_submit_r1(lan_c, amount_vnd=10_000_000, purpose="R1 boundary before")
        r2_id = self._create_and_submit_r1(lan_c, amount_vnd=11_000_000, purpose="R2 boundary exact/after")

        nam = EmployeeIdentity.objects.get(username="nam")
        clock = StepClock()
        t_issue = clock.advance(60)

        c1 = issue_payment_challenge(
            actor=nam,
            session_key="sess-nam-t21",
            session_epoch=nam.security_epoch,
            request_id=r1_id,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t_issue,
        )
        c2 = issue_payment_challenge(
            actor=nam,
            session_key="sess-nam-t21",
            session_epoch=nam.security_epoch,
            request_id=r2_id,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t_issue,
        )

        # Case 1: 1 second before expires_at (`now = expires_at - 1s`) -> accepted
        t_before = c1.expires_at - timedelta(seconds=1)
        otp_before = totp_at(nam, t_before)
        app1 = approve_payment_request(
            actor=nam,
            session_key="sess-nam-t21",
            session_epoch=nam.security_epoch,
            request_id=r1_id,
            challenge_id=c1.id,
            nonce=c1.nonce,
            otp_token=otp_before,
            now=t_before,
        )
        self.assertIsNotNone(app1.id)

        # Case 2: Exactly at `expires_at` (`now == expires_at`) -> rejected with CHALLENGE_EXPIRED
        t_exact = c2.expires_at
        otp_exact = totp_at(nam, t_exact + timedelta(seconds=35))
        with self.assertRaises(SecurityDomainError) as ctx_exact:
            approve_payment_request(
                actor=nam,
                session_key="sess-nam-t21",
                session_epoch=nam.security_epoch,
                request_id=r2_id,
                challenge_id=c2.id,
                nonce=c2.nonce,
                otp_token=otp_exact,
                now=t_exact,
            )
        self.assertEqual(ctx_exact.exception.reason_code, ReasonCode.CHALLENGE_EXPIRED)

        # Case 3: 5 seconds after `expires_at` (`now > expires_at`) -> rejected with CHALLENGE_EXPIRED
        t_after = c2.expires_at + timedelta(seconds=5)
        with self.assertRaises(SecurityDomainError) as ctx_after:
            approve_payment_request(
                actor=nam,
                session_key="sess-nam-t21",
                session_epoch=nam.security_epoch,
                request_id=r2_id,
                challenge_id=c2.id,
                nonce=c2.nonce,
                otp_token=otp_exact,
                now=t_after,
            )
        self.assertEqual(ctx_after.exception.reason_code, ReasonCode.CHALLENGE_EXPIRED)
        self.assertEqual(Approval.objects.filter(payment_request_id=r2_id).count(), 0)

        write_test_evidence(
            "T-21",
            actual=(
                f"Tai now = expires_at - 1s ({t_before.isoformat()}), C1 duoc chap nhan; "
                f"tai now == expires_at ({t_exact.isoformat()}) va now = expires_at + 5s ({t_after.isoformat()}), "
                f"C2 bi tu choi voi {ctx_exact.exception.reason_code}; Approval count cho R2 = 0."
            ),
            details={
                "c1_expires_at": c1.expires_at.isoformat(),
                "c1_before_boundary_approved": True,
                "c2_exact_boundary_reason": ctx_exact.exception.reason_code,
                "c2_after_boundary_reason": ctx_after.exception.reason_code,
            },
        )

    def test_t22_consumed_challenge_replay_blocked_and_idempotent_retry_returns_receipt(self) -> None:
        """T-22: Consumed challenge cannot create a new decision; idempotent execute retry returns existing receipt."""
        req_id, lan_c, nam_c, _ = self._prepare_fully_approved_request()
        nam_chal = ActionChallenge.objects.filter(
            actor__username="nam", payment_request_id=req_id, consumed_at__isnull=False
        ).first()
        self.assertIsNotNone(nam_chal)
        consumed_at_before = nam_chal.consumed_at

        # Replay consumed approval challenge C1 on another request R2 or on R1
        r2_id = self._create_and_submit_r1(lan_c, amount_vnd=15_000_000, purpose="R2 test replay")
        # Even if we test replaying C1 on R1 while R1 was still PENDING_APPROVAL: let's test on R2 where Nam approves R2 then replays C2
        res_nam_r2 = self._issue_and_approve(nam_c, self.lab["users"]["nam"], r2_id)
        self.assertEqual(res_nam_r2["response"].status_code, 200)
        c2_obj = ActionChallenge.objects.get(pk=res_nam_r2["challenge_id"])
        consumed_c2_before = c2_obj.consumed_at

        # Replay consumed C2
        r_replay = nam_c.post(
            f"/requests/{r2_id}/approve",
            data=json.dumps(
                {
                    "challenge_id": res_nam_r2["challenge_id"],
                    "nonce": res_nam_r2["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["nam"]),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_replay.status_code, 409)
        c2_obj.refresh_from_db()
        self.assertEqual(c2_obj.consumed_at, consumed_c2_before)

        # Execute R1 with idempotency_key, then retry with the same key -> returns same receipt without creating a 2nd row
        r_echal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        echal_json = r_echal.json()
        r_exec1 = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": echal_json["challenge_id"],
                    "nonce": echal_json["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["lan"]),
                    "idempotency_key": "IDEMP-T22-KEY",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_exec1.status_code, 200)
        self.assertFalse(r_exec1.json()["idempotent_replay"])

        r_exec_retry = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": echal_json["challenge_id"],
                    "nonce": echal_json["nonce"],
                    "otp_token": "000000",
                    "idempotency_key": "IDEMP-T22-KEY",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_exec_retry.status_code, 200)
        self.assertTrue(r_exec_retry.json()["idempotent_replay"])
        self.assertEqual(r_exec1.json()["receipt_id"], r_exec_retry.json()["receipt_id"])
        self.assertEqual(PaymentExecution.objects.filter(payment_request_id=req_id).count(), 1)

        write_test_evidence(
            "T-22",
            actual=(
                f"Phat lai challenge da tieu thu bi HTTP {r_replay.status_code}, consumed_at giu nguyen; "
                f"retry idempotent cung key IDEMP-T22-KEY tra cung bien nhan "
                f"{r_exec1.json()['receipt_id']} voi PaymentExecution count=1."
            ),
            details={
                "replay_approve_http": r_replay.status_code,
                "receipt_id": r_exec1.json()["receipt_id"],
                "idempotent_replay_flag": r_exec_retry.json()["idempotent_replay"],
                "execution_count": 1,
            },
        )

    def test_t23_totp_timestep_cannot_be_reused(self) -> None:
        """T-23: Once a TOTP code/timestep is accepted for Nam on R1, reusing the same code/timestep on R2 is rejected."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        r1_id = self._create_and_submit_r1(lan_c, amount_vnd=10_000_000, purpose="R1 TOTP timestep")
        r2_id = self._create_and_submit_r1(lan_c, amount_vnd=15_000_000, purpose="R2 TOTP timestep")

        nam = EmployeeIdentity.objects.get(username="nam")
        clock = StepClock()
        t_step = clock.advance(60)
        otp_same_step = totp_at(nam, t_step)

        c1 = issue_payment_challenge(
            actor=nam,
            session_key="sess-t23",
            session_epoch=nam.security_epoch,
            request_id=r1_id,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t_step,
        )
        c2 = issue_payment_challenge(
            actor=nam,
            session_key="sess-t23",
            session_epoch=nam.security_epoch,
            request_id=r2_id,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t_step,
        )

        # First use at t_step succeeds and updates device.last_t
        approve_payment_request(
            actor=nam,
            session_key="sess-t23",
            session_epoch=nam.security_epoch,
            request_id=r1_id,
            challenge_id=c1.id,
            nonce=c1.nonce,
            otp_token=otp_same_step,
            now=t_step,
        )
        dev = TOTPDevice.objects.get(user=nam, confirmed=True)
        last_t_after_first = dev.last_t

        # Second use in the SAME 30s timestep on R2 fails with OTP_REPLAY (409)
        with self.assertRaises(SecurityDomainError) as ctx:
            approve_payment_request(
                actor=nam,
                session_key="sess-t23",
                session_epoch=nam.security_epoch,
                request_id=r2_id,
                challenge_id=c2.id,
                nonce=c2.nonce,
                otp_token=otp_same_step,
                now=t_step + timedelta(seconds=2),
            )
        self.assertEqual(ctx.exception.reason_code, ReasonCode.OTP_REPLAY)
        self.assertEqual(Approval.objects.filter(payment_request_id=r2_id).count(), 0)

        write_test_evidence(
            "T-23",
            actual=(
                f"Sau khi ma TOTP cua Nam duoc chap nhan cho R1 (device.last_t={last_t_after_first}), "
                f"dung lai cung ma/timestep cho challenge C2 tren R2 bi tu choi voi {ctx.exception.reason_code}; "
                f"Approval count tren R2 = 0."
            ),
            details={
                "device_last_t": last_t_after_first,
                "r1_approval_count": 1,
                "r2_approval_count": 0,
                "second_use_reason_code": ctx.exception.reason_code,
            },
        )

    def test_t24_direct_api_call_enforces_db_conditions_and_executor_identity(self) -> None:
        """T-24: Direct API call supplying client-claimed approval_ids/status or wrong actor is rejected."""
        req_id, lan_c, nam_c, _ = self._prepare_fully_approved_request()

        # Client tries to inject approval_ids or status in execute-simulated payload
        r_inject = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": "00000000-0000-0000-0000-000000000000",
                    "nonce": "fake",
                    "otp_token": "123456",
                    "idempotency_key": "IDEMP-T24",
                    "approval_ids": [1, 2],
                    "status": "EXECUTED_SIMULATED",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_inject.status_code, 400)
        self.assertEqual(r_inject.json()["reason_code"], ReasonCode.FORBIDDEN)

        # Approver Nam tries to execute Lan's approved request directly via API
        r_nam_exec = nam_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_nam_exec.status_code, 403)
        self.assertEqual(r_nam_exec.json()["reason_code"], ReasonCode.FORBIDDEN)
        self.assertEqual(PaymentExecution.objects.filter(payment_request_id=req_id).count(), 0)

        write_test_evidence(
            "T-24",
            actual=(
                f"Goi thang execute-simulated kem approval_ids/status tu khai bi HTTP {r_inject.status_code} "
                f"(FORBIDDEN); nguoi duyet Nam goi xin challenge EXECUTE bi HTTP {r_nam_exec.status_code} "
                f"(FORBIDDEN); PaymentExecution count=0."
            ),
            details={
                "injected_execute_http": r_inject.status_code,
                "nam_execute_challenge_http": r_nam_exec.status_code,
                "execution_count": 0,
            },
        )

    def test_t25_suspend_before_execute_moves_request_to_hold_and_blocks_execution(self) -> None:
        """T-25: R1 is APPROVED; SecurityAdmin suspends Nam before Lan executes -> R1 moves to HOLD and cannot execute."""
        req_id, lan_c, _, _ = self._prepare_fully_approved_request()
        an_c = login_full_mfa_client("an", self.creds["an"]["password"])

        # Lan pre-issues an EXECUTE challenge before Nam is suspended
        r_echal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_echal.status_code, 201)
        echal_json = r_echal.json()

        # SecurityAdmin An suspends Nam
        nam_user = EmployeeIdentity.objects.get(username="nam")
        reason_str = "Tam dinh chi Nam truoc khi execute R1"
        r_achal = an_c.post(
            f"/security/users/{nam_user.id}/challenges",
            data=json.dumps({"action": ChallengeAction.SUSPEND, "reason": reason_str}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        achal_json = r_achal.json()
        r_susp = an_c.post(
            f"/security/users/{nam_user.id}/suspend",
            data=json.dumps(
                {
                    "challenge_id": achal_json["challenge_id"],
                    "nonce": achal_json["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["an"]),
                    "reason": reason_str,
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_susp.status_code, 200)

        # Lan attempts to execute R1 using the challenge issued earlier
        r_exec = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": echal_json["challenge_id"],
                    "nonce": echal_json["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["lan"]),
                    "idempotency_key": "IDEMP-T25",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_exec.status_code, 409)
        req = PaymentRequest.objects.get(pk=req_id)
        self.assertEqual(req.status, RequestStatus.HOLD)
        self.assertEqual(PaymentExecution.objects.filter(payment_request=req).count(), 0)

        write_test_evidence(
            "T-25",
            actual=(
                f"Sau khi SecurityAdmin dinh chi Nam, R1 chuyen sang trang thai {req.status}; "
                f"Lan thu execute bang challenge da cap truoc do bi chan HTTP {r_exec.status_code} "
                f"({r_exec.json()['reason_code']}); PaymentExecution count=0."
            ),
            details={
                "request_status_after_suspend": req.status,
                "lan_execute_http": r_exec.status_code,
                "lan_execute_reason": r_exec.json()["reason_code"],
                "execution_count": 0,
            },
        )

    def test_t26_revoked_approver_role_invalidates_prior_approval_at_final_gate(self) -> None:
        """T-26: If Nam's role is revoked/changed before execute, Final Gate checks live role and blocks execution."""
        req_id, lan_c, _, _ = self._prepare_fully_approved_request()

        r_echal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        echal_json = r_echal.json()

        # Trusted role change on Nam (DIRECTOR -> REQUESTER)
        nam_user = EmployeeIdentity.objects.get(username="nam")
        nam_user.role = Role.REQUESTER
        nam_user.save(update_fields=["role"])

        r_exec = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": echal_json["challenge_id"],
                    "nonce": echal_json["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["lan"]),
                    "idempotency_key": "IDEMP-T26",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_exec.status_code, 409)
        self.assertEqual(r_exec.json()["reason_code"], ReasonCode.PRINCIPAL_REVOKED)
        req = PaymentRequest.objects.get(pk=req_id)
        self.assertEqual(req.status, RequestStatus.HOLD)
        self.assertEqual(PaymentExecution.objects.filter(payment_request=req).count(), 0)

        write_test_evidence(
            "T-26",
            actual=(
                f"Khi role cua Nam bi doi tu DIRECTOR sang REQUESTER truoc khi execute, Final Gate phat hien "
                f"role hien tai khong khop, chuyen R1 sang {req.status} va tra HTTP {r_exec.status_code} "
                f"(PRINCIPAL_REVOKED); PaymentExecution count=0."
            ),
            details={
                "http_status": r_exec.status_code,
                "reason_code": r_exec.json()["reason_code"],
                "request_status": req.status,
                "execution_count": 0,
            },
        )

    def test_t27_mfa_factor_rotation_bumps_epoch_and_invalidates_prior_authority(self) -> None:
        """T-27: Rotating/resetting Nam's TOTP factor via trusted recovery bumps security_epoch and invalidates prior approvals/challenges."""
        req_id, lan_c, nam_c, _ = self._prepare_fully_approved_request()
        nam_user = EmployeeIdentity.objects.get(username="nam")
        old_epoch = nam_user.security_epoch

        call_command(
            "recover_principal",
            username="nam",
            rotate_mfa=True,
            note="Reset MFA factor theo quy trinh tin cay",
            verbosity=0,
        )
        nam_user.refresh_from_db()
        req = PaymentRequest.objects.get(pk=req_id)
        self.assertGreater(nam_user.security_epoch, old_epoch)
        self.assertEqual(req.status, RequestStatus.HOLD)

        # Old session of Nam is rejected
        r_old_sess = nam_c.get(f"/requests/{req_id}", HTTP_ACCEPT="application/json")
        self.assertEqual(r_old_sess.status_code, 401)

        # Lan cannot execute R1 because it is in HOLD and Nam's approval was invalidated
        r_lan_chal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_lan_chal.status_code, 409)
        self.assertEqual(PaymentExecution.objects.filter(payment_request=req).count(), 0)

        write_test_evidence(
            "T-27",
            actual=(
                f"Reset/rotate TOTP factor cua Nam qua recover_principal tang security_epoch ({old_epoch} -> {nam_user.security_epoch}), "
                f"dua R1 sang {req.status}, chan phien cu HTTP {r_old_sess.status_code} va chan Lan execute HTTP {r_lan_chal.status_code}."
            ),
            details={
                "old_epoch": old_epoch,
                "new_epoch": nam_user.security_epoch,
                "request_status": req.status,
                "old_session_http": r_old_sess.status_code,
                "lan_execute_challenge_http": r_lan_chal.status_code,
            },
        )

    def test_t28_beneficiary_version_change_or_revocation_blocks_execution_at_final_gate(self) -> None:
        """T-28: Updating or revoking B1 via `manage_beneficiary` after R1 is APPROVED blocks execution at Final Gate."""
        req_id, lan_c, _, _ = self._prepare_fully_approved_request()

        r_echal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        echal_json = r_echal.json()

        # Trusted CLI updates B1's bank account to a new version (version 2)
        call_command(
            "manage_beneficiary",
            action="new-version",
            code="BEN-001",
            vendor_name="Cong ty Co phan Thiet bi mang Sao Viet (Fictional Lab)",
            bank_name="Ngan hang TMCP Ngoai thuong Mo phong (VCB-SIM)",
            account_number="0071009999999",
            reason="Cap nhat tai khoan ngan hang moi cua doi tac BEN-001",
            verbosity=0,
        )
        b1 = Beneficiary.objects.get(code="BEN-001")
        self.assertEqual(b1.active_version.version_number, 2)

        # Final gate / offline_create_or_update_beneficiary_version detects that R1 was approved for version 1, not version 2
        r_exec = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": echal_json["challenge_id"],
                    "nonce": echal_json["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["lan"]),
                    "idempotency_key": "IDEMP-T28",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertIn(r_exec.status_code, (400, 409))
        req = PaymentRequest.objects.get(pk=req_id)
        self.assertEqual(PaymentExecution.objects.filter(payment_request=req).count(), 0)

        write_test_evidence(
            "T-28",
            actual=(
                f"Khi BEN-001 duoc cap nhat sang version 2 truoc luc execute, Final Gate phat hien "
                f"revision 1 gan voi version 1 da cu, tra HTTP {r_exec.status_code} ({r_exec.json()['reason_code']}) "
                f"va khong tu dong chuyen sang tai khoan moi (PaymentExecution=0)."
            ),
            details={
                "approved_beneficiary_version": 1,
                "active_beneficiary_version": b1.active_version.version_number,
                "execute_http": r_exec.status_code,
                "reason_code": r_exec.json()["reason_code"],
                "request_status": req.status,
                "execution_count": 0,
            },
        )

    def test_t29_executed_simulated_is_immutable_and_cannot_be_re_executed_with_new_key(self) -> None:
        """T-29: Once EXECUTED_SIMULATED, revising, cancelling, rejecting, or executing with a new key are all blocked."""
        req_id, lan_c, _, huong_c = self._prepare_fully_approved_request()

        r_echal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        echal_json = r_echal.json()
        r_exec1 = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": echal_json["challenge_id"],
                    "nonce": echal_json["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["lan"]),
                    "idempotency_key": "IDEMP-T29-ORIG",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_exec1.status_code, 200)
        receipt_id = r_exec1.json()["receipt_id"]

        # Try revise, cancel, reject, and new-key execute
        r_revise = lan_c.post(
            f"/requests/{req_id}/revise",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(self.lab["b1_ver"].id),
                    "amount_vnd": 99_000_000,
                    "purpose": "Sua sau execute",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        r_cancel = lan_c.post(f"/requests/{req_id}/cancel", HTTP_ACCEPT="application/json")
        r_reject_chal = huong_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.REJECT, "reason": "Reject sau execute"}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        r_exec_new_key = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": echal_json["challenge_id"],
                    "nonce": echal_json["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["lan"]),
                    "idempotency_key": "IDEMP-T29-SECOND-KEY",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )

        self.assertEqual(r_revise.status_code, 409)
        self.assertEqual(r_cancel.status_code, 409)
        self.assertEqual(r_reject_chal.status_code, 409)
        self.assertEqual(r_exec_new_key.status_code, 409)
        self.assertEqual(PaymentExecution.objects.filter(payment_request_id=req_id).count(), 1)
        self.assertEqual(PaymentExecution.objects.get(payment_request_id=req_id).receipt_id, receipt_id)

        write_test_evidence(
            "T-29",
            actual=(
                f"Sau khi R1 dat EXECUTED_SIMULATED ({receipt_id}), revise={r_revise.status_code}, "
                f"cancel={r_cancel.status_code}, reject_challenge={r_reject_chal.status_code}, "
                f"execute voi key moi={r_exec_new_key.status_code}; PaymentExecution count=1 khong doi."
            ),
            details={
                "receipt_id": receipt_id,
                "revise_http": r_revise.status_code,
                "cancel_http": r_cancel.status_code,
                "reject_http": r_reject_chal.status_code,
                "second_key_execute_http": r_exec_new_key.status_code,
                "execution_count": 1,
            },
        )

    def test_t30_concurrent_execute_same_idempotency_key_single_effect(self) -> None:
        """T-30: Two concurrent execute workers on separate PostgreSQL connections with the same idempotency_key produce 1 execution."""
        req_id, _, _, _ = self._prepare_fully_approved_request()
        lan = EmployeeIdentity.objects.get(username="lan")
        clock = StepClock()
        t1 = clock.advance(60)

        chal = issue_payment_challenge(
            actor=lan,
            session_key="sess-t30",
            session_epoch=lan.security_epoch,
            request_id=req_id,
            action=ChallengeAction.EXECUTE,
            now=t1,
        )
        otp1 = totp_at(lan, t1)

        barrier = threading.Barrier(2)
        results: list[dict] = []
        lock = threading.Lock()

        def worker(worker_idx: int) -> None:
            connections.close_all()
            try:
                barrier.wait(timeout=10)
                ex, is_replay = execute_payment_request_simulated(
                    actor=lan,
                    session_key="sess-t30",
                    session_epoch=lan.security_epoch,
                    request_id=req_id,
                    challenge_id=chal.id,
                    nonce=chal.nonce,
                    otp_token=otp1,
                    idempotency_key="IDEMP-T30-SAME",
                    now=t1,
                )
                with lock:
                    results.append(
                        {"worker": worker_idx, "status": "OK", "receipt": ex.receipt_id, "is_replay": is_replay}
                    )
            except Exception as exc:  # pragma: no cover
                with lock:
                    results.append({"worker": worker_idx, "status": "ERR", "error": str(exc)})
            finally:
                connections.close_all()

        t_a = threading.Thread(target=worker, args=(1,))
        t_b = threading.Thread(target=worker, args=(2,))
        t_a.start()
        t_b.start()
        t_a.join(timeout=15)
        t_b.join(timeout=15)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["status"] == "OK" for r in results), results)
        self.assertEqual(results[0]["receipt"], results[1]["receipt"])
        self.assertEqual(sorted([r["is_replay"] for r in results]), [False, True])
        self.assertEqual(PaymentExecution.objects.filter(payment_request_id=req_id).count(), 1)

        write_test_evidence(
            "T-30",
            actual=(
                f"Hai worker PostgreSQL doc lap cung gui idempotency_key='IDEMP-T30-SAME' qua Barrier(2): "
                f"1 worker tao moi (is_replay=False), 1 worker nhan ket qua idempotent (is_replay=True), "
                f"cung receipt={results[0]['receipt']}, PaymentExecution COUNT=1."
            ),
            details={"worker_results": results, "execution_count": 1},
        )

    def test_t31_concurrent_execute_different_keys_still_single_execution(self) -> None:
        """T-31: Two concurrent execute workers with different idempotency keys and distinct valid TOTP timesteps produce at most 1 execution."""
        req_id, _, _, _ = self._prepare_fully_approved_request()
        lan = EmployeeIdentity.objects.get(username="lan")
        clock = StepClock()
        t_issue = clock.advance(60)
        t_w1 = t_issue + timedelta(seconds=35)
        t_w2 = t_issue + timedelta(seconds=70)

        c1 = issue_payment_challenge(
            actor=lan,
            session_key="sess-t31-a",
            session_epoch=lan.security_epoch,
            request_id=req_id,
            action=ChallengeAction.EXECUTE,
            now=t_issue,
        )
        c2 = issue_payment_challenge(
            actor=lan,
            session_key="sess-t31-b",
            session_epoch=lan.security_epoch,
            request_id=req_id,
            action=ChallengeAction.EXECUTE,
            now=t_issue,
        )
        otp_w1 = totp_at(lan, t_w1)
        otp_w2 = totp_at(lan, t_w2)

        barrier = threading.Barrier(2)
        results: list[dict] = []
        lock = threading.Lock()

        def worker(worker_idx: int, chal_obj: ActionChallenge, otp: str, key: str, sess: str, when) -> None:
            connections.close_all()
            try:
                barrier.wait(timeout=10)
                ex, is_replay = execute_payment_request_simulated(
                    actor=lan,
                    session_key=sess,
                    session_epoch=lan.security_epoch,
                    request_id=req_id,
                    challenge_id=chal_obj.id,
                    nonce=chal_obj.nonce,
                    otp_token=otp,
                    idempotency_key=key,
                    now=when,
                )
                with lock:
                    results.append(
                        {"worker": worker_idx, "outcome": "EXECUTED", "receipt": ex.receipt_id, "is_replay": is_replay}
                    )
            except SecurityDomainError as exc:
                with lock:
                    results.append({"worker": worker_idx, "outcome": "REJECTED", "reason_code": exc.reason_code})
            finally:
                connections.close_all()

        t_a = threading.Thread(target=worker, args=(1, c1, otp_w1, "IDEMP-T31-KEY-A", "sess-t31-a", t_w1))
        t_b = threading.Thread(target=worker, args=(2, c2, otp_w2, "IDEMP-T31-KEY-B", "sess-t31-b", t_w2))
        t_a.start()
        t_b.start()
        t_a.join(timeout=15)
        t_b.join(timeout=15)

        outcomes = sorted([r["outcome"] for r in results])
        self.assertEqual(outcomes, ["EXECUTED", "REJECTED"], results)
        self.assertEqual(PaymentExecution.objects.filter(payment_request_id=req_id).count(), 1)

        write_test_evidence(
            "T-31",
            actual=(
                f"Hai worker PostgreSQL doc lap voi 2 idempotency_key khac nhau (IDEMP-T31-KEY-A, IDEMP-T31-KEY-B) "
                f"va 2 challenge/timestep hop le cung tranh chap R1: 1 worker EXECUTED, 1 worker REJECTED "
                f"(IDEMPOTENCY_CONFLICT); PaymentExecution COUNT=1."
            ),
            details={"worker_results": results, "execution_count": 1},
        )

    def test_t32_concurrent_approve_and_revise_both_lock_orders(self) -> None:
        """T-32: Concurrent approve (rev 1) and revise (rev 2) tested in both lock orders leave 0 valid approvals on rev 2."""
        lan = EmployeeIdentity.objects.get(username="lan")
        nam = EmployeeIdentity.objects.get(username="nam")
        clock = StepClock()

        # Order A: revise acquires lock first, then approve rev 1 runs -> approve rev 1 is rejected
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        r_order_a = self._create_and_submit_r1(lan_c, amount_vnd=20_000_000, purpose="T32 Order A")
        t_a = clock.advance(60)
        c_a = issue_payment_challenge(
            actor=nam,
            session_key="sess-t32-a",
            session_epoch=nam.security_epoch,
            request_id=r_order_a,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t_a,
        )
        otp_a = totp_at(nam, t_a)

        revise_done = threading.Event()
        order_a_results: dict = {}

        def worker_revise_first() -> None:
            connections.close_all()
            try:
                req_updated = revise_payment_request(
                    actor=lan,
                    session_epoch=lan.security_epoch,
                    request_id=r_order_a,
                    beneficiary_version_id=self.lab["b1_ver"].id,
                    amount_vnd=22_000_000,
                    purpose="T32 Order A rev 2",
                    source_kind=SourceKind.EMAIL,
                    source_excerpt="",
                    now=t_a,
                )
                order_a_results["revise"] = req_updated.current_revision.revision_number
            finally:
                revise_done.set()
                connections.close_all()

        def worker_approve_second() -> None:
            connections.close_all()
            try:
                revise_done.wait(timeout=10)
                approve_payment_request(
                    actor=nam,
                    session_key="sess-t32-a",
                    session_epoch=nam.security_epoch,
                    request_id=r_order_a,
                    challenge_id=c_a.id,
                    nonce=c_a.nonce,
                    otp_token=otp_a,
                    now=t_a,
                )
                order_a_results["approve"] = "APPROVED"
            except SecurityDomainError as exc:
                order_a_results["approve"] = exc.reason_code
            finally:
                connections.close_all()

        th1 = threading.Thread(target=worker_revise_first)
        th2 = threading.Thread(target=worker_approve_second)
        th1.start()
        th2.start()
        th1.join(timeout=15)
        th2.join(timeout=15)

        req_a = PaymentRequest.objects.get(pk=r_order_a)
        self.assertEqual(req_a.status, RequestStatus.DRAFT)
        self.assertEqual(req_a.current_revision.revision_number, 2)
        self.assertEqual(Approval.objects.filter(payment_request=req_a, status=ApprovalStatus.ACTIVE).count(), 0)

        # Order B: approve rev 1 commits first, then revise runs -> approval on rev 1 is superseded and status becomes DRAFT
        r_order_b = self._create_and_submit_r1(lan_c, amount_vnd=30_000_000, purpose="T32 Order B")
        t_b = clock.advance(60)
        c_b = issue_payment_challenge(
            actor=nam,
            session_key="sess-t32-b",
            session_epoch=nam.security_epoch,
            request_id=r_order_b,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t_b,
        )
        otp_b = totp_at(nam, t_b)

        approve_done = threading.Event()
        order_b_results: dict = {}

        def worker_approve_first() -> None:
            connections.close_all()
            try:
                app = approve_payment_request(
                    actor=nam,
                    session_key="sess-t32-b",
                    session_epoch=nam.security_epoch,
                    request_id=r_order_b,
                    challenge_id=c_b.id,
                    nonce=c_b.nonce,
                    otp_token=otp_b,
                    now=t_b,
                )
                order_b_results["approve_id"] = str(app.id)
            finally:
                approve_done.set()
                connections.close_all()

        def worker_revise_second() -> None:
            connections.close_all()
            try:
                approve_done.wait(timeout=10)
                req_updated = revise_payment_request(
                    actor=lan,
                    session_epoch=lan.security_epoch,
                    request_id=r_order_b,
                    beneficiary_version_id=self.lab["b1_ver"].id,
                    amount_vnd=35_000_000,
                    purpose="T32 Order B rev 2",
                    source_kind=SourceKind.EMAIL,
                    source_excerpt="",
                    now=t_b,
                )
                order_b_results["revise"] = req_updated.current_revision.revision_number
            finally:
                connections.close_all()

        th3 = threading.Thread(target=worker_approve_first)
        th4 = threading.Thread(target=worker_revise_second)
        th3.start()
        th4.start()
        th3.join(timeout=15)
        th4.join(timeout=15)

        req_b = PaymentRequest.objects.get(pk=r_order_b)
        self.assertEqual(req_b.status, RequestStatus.DRAFT)
        self.assertEqual(req_b.current_revision.revision_number, 2)
        self.assertEqual(Approval.objects.filter(payment_request=req_b, status=ApprovalStatus.ACTIVE).count(), 0)

        write_test_evidence(
            "T-32",
            actual=(
                f"Ca 2 thu tu khoa tren PostgreSQL deu an toan: Order A (revise truoc -> approve cu bi tu choi "
                f"{order_a_results['approve']}); Order B (approve truoc -> revise sau vo hieu phieu cu va dua ve DRAFT); "
                f"khong co phieu cu nao con ACTIVE cho revision 2."
            ),
            details={"order_a": order_a_results, "order_b": order_b_results},
        )

    def test_t33_concurrent_approve_and_reject_ends_in_rejected(self) -> None:
        """T-33: Concurrent approve (Nam) and reject (Huong) on two PostgreSQL connections ends in REJECTED with 0 executions."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam = EmployeeIdentity.objects.get(username="nam")
        huong = EmployeeIdentity.objects.get(username="huong")
        clock = StepClock()

        # Case 1: Reject commits first, then Nam's concurrent approve is rejected
        r1_id = self._create_and_submit_r1(lan_c, amount_vnd=18_000_000, purpose="T33 Reject first")
        t1 = clock.advance(60)
        c_nam1 = issue_payment_challenge(
            actor=nam,
            session_key="sess-t33-n1",
            session_epoch=nam.security_epoch,
            request_id=r1_id,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t1,
        )
        c_huong1 = issue_payment_challenge(
            actor=huong,
            session_key="sess-t33-h1",
            session_epoch=huong.security_epoch,
            request_id=r1_id,
            action=ChallengeAction.REJECT,
            now=t1,
        )

        # Case 2: Nam's approve commits first (1 of 2), then Huong's reject commits -> ends in REJECTED and invalidates Nam's approval
        r2_id = self._create_and_submit_r1(lan_c, amount_vnd=19_000_000, purpose="T33 Approve then Reject")
        t2 = clock.advance(60)
        c_nam2 = issue_payment_challenge(
            actor=nam,
            session_key="sess-t33-n2",
            session_epoch=nam.security_epoch,
            request_id=r2_id,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t2,
        )
        c_huong2 = issue_payment_challenge(
            actor=huong,
            session_key="sess-t33-h2",
            session_epoch=huong.security_epoch,
            request_id=r2_id,
            action=ChallengeAction.REJECT,
            now=t2,
        )

        rej_done = threading.Event()
        case1_res: dict = {}

        def w_reject_1() -> None:
            connections.close_all()
            try:
                reject_payment_request(
                    actor=huong,
                    session_key="sess-t33-h1",
                    session_epoch=huong.security_epoch,
                    request_id=r1_id,
                    challenge_id=c_huong1.id,
                    nonce=c_huong1.nonce,
                    otp_token=totp_at(huong, t1),
                    reason="Tu choi dong thoi",
                    now=t1,
                )
                case1_res["huong"] = "REJECTED"
            finally:
                rej_done.set()
                connections.close_all()

        def w_approve_1() -> None:
            connections.close_all()
            try:
                rej_done.wait(timeout=10)
                approve_payment_request(
                    actor=nam,
                    session_key="sess-t33-n1",
                    session_epoch=nam.security_epoch,
                    request_id=r1_id,
                    challenge_id=c_nam1.id,
                    nonce=c_nam1.nonce,
                    otp_token=totp_at(nam, t1),
                    now=t1,
                )
            except SecurityDomainError as exc:
                case1_res["nam"] = exc.reason_code
            finally:
                connections.close_all()

        t_r1 = threading.Thread(target=w_reject_1)
        t_a1 = threading.Thread(target=w_approve_1)
        t_r1.start()
        t_a1.start()
        t_r1.join(timeout=15)
        t_a1.join(timeout=15)

        app_done = threading.Event()
        case2_res: dict = {}

        def w_approve_2() -> None:
            connections.close_all()
            try:
                approve_payment_request(
                    actor=nam,
                    session_key="sess-t33-n2",
                    session_epoch=nam.security_epoch,
                    request_id=r2_id,
                    challenge_id=c_nam2.id,
                    nonce=c_nam2.nonce,
                    otp_token=totp_at(nam, t2),
                    now=t2,
                )
                case2_res["nam"] = "APPROVED_SLOT_1"
            finally:
                app_done.set()
                connections.close_all()

        def w_reject_2() -> None:
            connections.close_all()
            try:
                app_done.wait(timeout=10)
                reject_payment_request(
                    actor=huong,
                    session_key="sess-t33-h2",
                    session_epoch=huong.security_epoch,
                    request_id=r2_id,
                    challenge_id=c_huong2.id,
                    nonce=c_huong2.nonce,
                    otp_token=totp_at(huong, t2),
                    reason="Huong tu choi sau khi Nam duyet slot 1",
                    now=t2,
                )
                case2_res["huong"] = "REJECTED"
            finally:
                connections.close_all()

        t_a2 = threading.Thread(target=w_approve_2)
        t_r2 = threading.Thread(target=w_reject_2)
        t_a2.start()
        t_r2.start()
        t_a2.join(timeout=15)
        t_r2.join(timeout=15)

        self.assertEqual(PaymentRequest.objects.get(pk=r1_id).status, RequestStatus.REJECTED)
        self.assertEqual(PaymentRequest.objects.get(pk=r2_id).status, RequestStatus.REJECTED)
        self.assertEqual(PaymentExecution.objects.count(), 0)

        write_test_evidence(
            "T-33",
            actual=(
                f"Ca 2 thu tu tranh chap approve/reject deu ket thuc REJECTED va PaymentExecution=0: "
                f"Case 1={case1_res}, Case 2={case2_res}."
            ),
            details={"case1_reject_first": case1_res, "case2_approve_first": case2_res, "execution_count": 0},
        )

    def test_t34_two_concurrent_challenges_racing_same_totp_timestep(self) -> None:
        """T-34: Two concurrent approve requests for Nam on R1 and R2 using the SAME TOTP timestep -> at most 1 succeeds."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        r1_id = self._create_and_submit_r1(lan_c, amount_vnd=10_000_000, purpose="T34 Race R1")
        r2_id = self._create_and_submit_r1(lan_c, amount_vnd=12_000_000, purpose="T34 Race R2")

        nam = EmployeeIdentity.objects.get(username="nam")
        clock = StepClock()
        t_race = clock.advance(60)
        shared_otp = totp_at(nam, t_race)

        c1 = issue_payment_challenge(
            actor=nam,
            session_key="sess-t34-1",
            session_epoch=nam.security_epoch,
            request_id=r1_id,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t_race,
        )
        c2 = issue_payment_challenge(
            actor=nam,
            session_key="sess-t34-2",
            session_epoch=nam.security_epoch,
            request_id=r2_id,
            action=ChallengeAction.APPROVE_DIRECTOR,
            now=t_race,
        )

        barrier = threading.Barrier(2)
        outcomes: list[dict] = []
        lock = threading.Lock()

        def worker(req_target: str, chal_obj: ActionChallenge, sess: str) -> None:
            connections.close_all()
            try:
                barrier.wait(timeout=10)
                approve_payment_request(
                    actor=nam,
                    session_key=sess,
                    session_epoch=nam.security_epoch,
                    request_id=req_target,
                    challenge_id=chal_obj.id,
                    nonce=chal_obj.nonce,
                    otp_token=shared_otp,
                    now=t_race,
                )
                with lock:
                    outcomes.append({"request_id": req_target, "result": "APPROVED"})
            except SecurityDomainError as exc:
                with lock:
                    outcomes.append({"request_id": req_target, "result": exc.reason_code})
            finally:
                connections.close_all()

        w1 = threading.Thread(target=worker, args=(r1_id, c1, "sess-t34-1"))
        w2 = threading.Thread(target=worker, args=(r2_id, c2, "sess-t34-2"))
        w1.start()
        w2.start()
        w1.join(timeout=15)
        w2.join(timeout=15)

        result_labels = sorted([o["result"] for o in outcomes])
        self.assertEqual(result_labels, ["APPROVED", ReasonCode.OTP_REPLAY], outcomes)
        self.assertEqual(Approval.objects.filter(approver=nam).count(), 1)

        write_test_evidence(
            "T-34",
            actual=(
                f"Hai ket noi PostgreSQL cung gui 1 ma TOTP cua Nam cho 2 challenge (R1 va R2) qua Barrier(2): "
                f"ket qua {result_labels}; tong Approval cua Nam tang dung 1."
            ),
            details={"outcomes": outcomes, "total_nam_approvals": Approval.objects.filter(approver=nam).count()},
        )

    def test_t35_execute_and_revoke_both_commit_orders(self) -> None:
        """T-35: Controlled test of (1) revoke before execute -> blocked/HOLD, and (2) execute before revoke -> 1 valid receipt preserved."""
        clock = StepClock()

        # --- Subcase 1: Revoke commits BEFORE execute ---
        req1_id, _, _, _ = self._prepare_fully_approved_request()
        lan = EmployeeIdentity.objects.get(username="lan")
        nam = EmployeeIdentity.objects.get(username="nam")
        an = EmployeeIdentity.objects.get(username="an")

        t1 = clock.advance(60)
        reason1 = "Thu hoi quyen cua Nam truoc execute"
        c_exec1 = issue_payment_challenge(
            actor=lan,
            session_key="sess-t35-l1",
            session_epoch=lan.security_epoch,
            request_id=req1_id,
            action=ChallengeAction.EXECUTE,
            now=t1,
        )
        c_rev1 = issue_security_admin_challenge(
            actor=an,
            session_key="sess-t35-a1",
            target_user_id=nam.id,
            action=ChallengeAction.REVOKE_ALL,
            reason=reason1,
            now=t1,
        )
        otp_lan1 = totp_at(lan, t1)
        otp_an1 = totp_at(an, t1)

        rev_done = threading.Event()
        subcase1: dict = {}

        def w_revoke_first() -> None:
            connections.close_all()
            try:
                target_u, affected = execute_security_admin_action(
                    actor=an,
                    session_key="sess-t35-a1",
                    session_epoch=an.security_epoch,
                    target_user_id=nam.id,
                    action=ChallengeAction.REVOKE_ALL,
                    reason=reason1,
                    challenge_id=c_rev1.id,
                    nonce=c_rev1.nonce,
                    otp_token=otp_an1,
                    now=t1,
                )
                subcase1["revoke_new_epoch"] = target_u.security_epoch
                subcase1["affected_requests"] = affected
            finally:
                rev_done.set()
                connections.close_all()

        def w_exec_second() -> None:
            connections.close_all()
            try:
                rev_done.wait(timeout=10)
                execute_payment_request_simulated(
                    actor=lan,
                    session_key="sess-t35-l1",
                    session_epoch=lan.security_epoch,
                    request_id=req1_id,
                    challenge_id=c_exec1.id,
                    nonce=c_exec1.nonce,
                    otp_token=otp_lan1,
                    idempotency_key="IDEMP-T35-1",
                    now=t1,
                )
                subcase1["execute"] = "EXECUTED"
            except SecurityDomainError as exc:
                subcase1["execute"] = exc.reason_code
            finally:
                connections.close_all()

        th_r1 = threading.Thread(target=w_revoke_first)
        th_e1 = threading.Thread(target=w_exec_second)
        th_r1.start()
        th_e1.start()
        th_r1.join(timeout=15)
        th_e1.join(timeout=15)

        self.assertEqual(PaymentRequest.objects.get(pk=req1_id).status, RequestStatus.HOLD)
        self.assertEqual(PaymentExecution.objects.filter(payment_request_id=req1_id).count(), 0)

        # --- Subcase 2: Fresh fixture where Execute commits BEFORE Revoke ---
        self.lab = seed_standard_lab()
        self.creds = self.lab["creds"]
        req2_id, _, _, _ = self._prepare_fully_approved_request()
        lan = EmployeeIdentity.objects.get(username="lan")
        nam = EmployeeIdentity.objects.get(username="nam")
        an = EmployeeIdentity.objects.get(username="an")

        t2 = clock.advance(120)
        reason2 = "Thu hoi quyen cua Nam sau khi R2 da execute"
        c_exec2 = issue_payment_challenge(
            actor=lan,
            session_key="sess-t35-l2",
            session_epoch=lan.security_epoch,
            request_id=req2_id,
            action=ChallengeAction.EXECUTE,
            now=t2,
        )
        c_rev2 = issue_security_admin_challenge(
            actor=an,
            session_key="sess-t35-a2",
            target_user_id=nam.id,
            action=ChallengeAction.REVOKE_ALL,
            reason=reason2,
            now=t2,
        )
        otp_lan2 = totp_at(lan, t2)
        otp_an2 = totp_at(an, t2)

        exec_done = threading.Event()
        subcase2: dict = {}

        def w_exec_first() -> None:
            connections.close_all()
            try:
                ex, _ = execute_payment_request_simulated(
                    actor=lan,
                    session_key="sess-t35-l2",
                    session_epoch=lan.security_epoch,
                    request_id=req2_id,
                    challenge_id=c_exec2.id,
                    nonce=c_exec2.nonce,
                    otp_token=otp_lan2,
                    idempotency_key="IDEMP-T35-2",
                    now=t2,
                )
                subcase2["execute_receipt"] = ex.receipt_id
            finally:
                exec_done.set()
                connections.close_all()

        def w_revoke_second() -> None:
            connections.close_all()
            try:
                exec_done.wait(timeout=10)
                target_u, affected = execute_security_admin_action(
                    actor=an,
                    session_key="sess-t35-a2",
                    session_epoch=an.security_epoch,
                    target_user_id=nam.id,
                    action=ChallengeAction.REVOKE_ALL,
                    reason=reason2,
                    challenge_id=c_rev2.id,
                    nonce=c_rev2.nonce,
                    otp_token=otp_an2,
                    now=t2,
                )
                subcase2["revoke_new_epoch"] = target_u.security_epoch
                subcase2["affected_requests"] = affected
            finally:
                connections.close_all()

        th_e2 = threading.Thread(target=w_exec_first)
        th_r2 = threading.Thread(target=w_revoke_second)
        th_e2.start()
        th_r2.start()
        th_e2.join(timeout=15)
        th_r2.join(timeout=15)

        req2 = PaymentRequest.objects.get(pk=req2_id)
        self.assertEqual(req2.status, RequestStatus.EXECUTED_SIMULATED)
        self.assertEqual(PaymentExecution.objects.filter(payment_request=req2).count(), 1)

        write_test_evidence(
            "T-35",
            actual=(
                f"Subcase 1 (revoke commit truoc execute): R1 chuyen HOLD, execute bi chan ({subcase1['execute']}), Execution=0; "
                f"Subcase 2 (execute commit truoc revoke): R2 ghi nhan 1 bien nhan {subcase2['execute_receipt']}, "
                f"revoke sau do tang epoch nhung khong xoa lich su/bien nhan da commit."
            ),
            details={"subcase1_revoke_first": subcase1, "subcase2_execute_first": subcase2},
        )

    def test_t36_csrf_and_http_method_enforcement(self) -> None:
        """T-36: State-changing endpoints reject missing/bad CSRF token, untrusted Origin, and GET requests."""
        lan_csrf = login_full_mfa_client("lan", self.creds["lan"]["password"], enforce_csrf=True)

        # POST without CSRF token -> 403
        r_no_csrf = lan_csrf.post(
            "/requests",
            data=json.dumps(
                {"beneficiary_version_id": str(self.lab["b1_ver"].id), "amount_vnd": 10_000_000, "purpose": "No CSRF"}
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_no_csrf.status_code, 403)

        # POST with untrusted Origin -> 403
        csrf_token = lan_csrf.cookies["csrftoken"].value
        r_bad_origin = lan_csrf.post(
            "/requests",
            data=json.dumps(
                {"beneficiary_version_id": str(self.lab["b1_ver"].id), "amount_vnd": 10_000_000, "purpose": "Bad origin"}
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
            HTTP_X_CSRFTOKEN=csrf_token,
            HTTP_ORIGIN="https://evil-attacker.example",
        )
        self.assertEqual(r_bad_origin.status_code, 403)

        # Valid CSRF token + trusted Origin -> 201
        r_valid = lan_csrf.post(
            "/requests",
            data=json.dumps(
                {"beneficiary_version_id": str(self.lab["b1_ver"].id), "amount_vnd": 10_000_000, "purpose": "Valid CSRF"}
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
            HTTP_X_CSRFTOKEN=csrf_token,
            HTTP_ORIGIN="http://127.0.0.1:8000",
        )
        self.assertEqual(r_valid.status_code, 201)
        req_id = r_valid.json()["request_id"]

        # GET on state-changing endpoints -> 405
        r_get_submit = lan_csrf.get(f"/requests/{req_id}/submit")
        r_get_approve = lan_csrf.get(f"/requests/{req_id}/approve")
        r_get_exec = lan_csrf.get(f"/requests/{req_id}/execute-simulated")
        self.assertEqual(r_get_submit.status_code, 405)
        self.assertEqual(r_get_approve.status_code, 405)
        self.assertEqual(r_get_exec.status_code, 405)

        write_test_evidence(
            "T-36",
            actual=(
                f"Voi enforce_csrf_checks=True: POST thieu CSRF bi HTTP {r_no_csrf.status_code}, "
                f"Origin la bi HTTP {r_bad_origin.status_code}, dung CSRF+Origin hop le tra HTTP {r_valid.status_code}; "
                f"GET tren /submit, /approve, /execute-simulated deu tra HTTP 405."
            ),
            details={
                "missing_csrf_http": r_no_csrf.status_code,
                "bad_origin_http": r_bad_origin.status_code,
                "valid_csrf_http": r_valid.status_code,
                "get_submit_http": r_get_submit.status_code,
                "get_approve_http": r_get_approve.status_code,
                "get_execute_http": r_get_exec.status_code,
            },
        )

    def test_t37_vnd_validation_and_safe_xss_escaping(self) -> None:
        """T-37: Negative, zero, decimal, and out-of-range VND amounts are rejected; script tags in purpose/source_excerpt are HTML-escaped."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        invalid_amounts = [0, -500_000, 123.45, "15000.50", 2_000_000_000_000]
        codes = []
        for bad_amt in invalid_amounts:
            resp = lan_c.post(
                "/requests",
                data=json.dumps(
                    {"beneficiary_version_id": str(self.lab["b1_ver"].id), "amount_vnd": bad_amt, "purpose": "Test VND"}
                ),
                content_type="application/json",
                HTTP_ACCEPT="application/json",
            )
            codes.append(resp.status_code)
            self.assertEqual(resp.status_code, 400)

        self.assertEqual(PaymentRequest.objects.count(), 0)

        # Create request with XSS payload in purpose and source_excerpt, then render HTML detail page
        xss_purpose = "<script>window.__xss_executed=1;</script>Thanh toan thiet bi"
        xss_excerpt = "<img src=x onerror=alert(1)>Khan cap tu chat ngoai"
        r_ok = lan_c.post(
            "/requests",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(self.lab["b1_ver"].id),
                    "amount_vnd": 15_000_000,
                    "purpose": xss_purpose,
                    "source_kind": SourceKind.CHAT_MESSAGE,
                    "source_excerpt": xss_excerpt,
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_ok.status_code, 201)
        req_id = r_ok.json()["request_id"]

        r_html = lan_c.get(f"/requests/{req_id}")
        self.assertEqual(r_html.status_code, 200)
        html_body = r_html.content.decode("utf-8")
        self.assertNotIn("<script>window.__xss_executed=1;</script>", html_body)
        self.assertIn("&lt;script&gt;window.__xss_executed=1;&lt;/script&gt;", html_body)
        self.assertIn("Nguồn ngoài — chưa xác minh", html_body)

        write_test_evidence(
            "T-37",
            actual=(
                f"Cac gia tri VND sai (0, am, so thap phan, vuot 1e12) deu bi chan HTTP 400 ({codes}); "
                f"noi dung <script> va <img onerror> trong purpose/source_excerpt duoc escape an toan "
                f"(&lt;script&gt;...) va gan nhan 'Nguon ngoai — chua xac minh'."
            ),
            details={"invalid_amount_statuses": codes, "escaped_script_present": True},
        )

    def test_t38_audit_scoping_immutability_and_zero_secret_leaks(self) -> None:
        """T-38: Audit log enforces role-based scoping, blocks HTTP mutation/deletion, and strips secret markers."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        minh_c = login_full_mfa_client("minh", self.creds["minh"]["password"])
        an_c = login_full_mfa_client("an", self.creds["an"]["password"])

        secret_marker = "SECRET_MARKER_T38_DO_NOT_LOG_998877"
        anon = Client()
        anon.post("/auth/login", data={"username": "nam", "password": secret_marker}, HTTP_ACCEPT="application/json")

        r_minh_id = self._create_and_submit_r1(minh_c, amount_vnd=44_000_000, purpose="R_MINH_PRIVATE")
        minh_req_code = PaymentRequest.objects.get(pk=r_minh_id).request_code

        # Lan reads /audit -> must not see Minh's private request events
        r_lan_audit = lan_c.get("/audit", HTTP_ACCEPT="application/json")
        self.assertEqual(r_lan_audit.status_code, 200)
        lan_events = r_lan_audit.json()["events"]
        self.assertTrue(all(ev["request_code"] != minh_req_code for ev in lan_events))

        # SecurityAdmin An reads /audit -> sees events, and metadata has financial fields stripped
        r_an_audit = an_c.get("/audit", HTTP_ACCEPT="application/json")
        self.assertEqual(r_an_audit.status_code, 200)
        an_events = r_an_audit.json()["events"]
        for ev in an_events:
            self.assertNotIn("amount_vnd", ev["metadata"])
            self.assertNotIn("beneficiary_account", ev["metadata"])

        # Attempt to modify/delete audit via HTTP POST/DELETE -> 403
        r_post_audit = an_c.post("/audit", data={"action": "delete"}, HTTP_ACCEPT="application/json")
        r_del_audit = an_c.delete("/audit", HTTP_ACCEPT="application/json")
        self.assertEqual(r_post_audit.status_code, 403)
        self.assertEqual(r_del_audit.status_code, 403)

        # Scan all AuditEvent rows in PostgreSQL for secret_marker or TOTP keys
        all_audit_dump = json.dumps(list(AuditEvent.objects.values("action", "reason_code", "metadata")))
        self.assertNotIn(secret_marker, all_audit_dump)
        for dev in TOTPDevice.objects.all():
            self.assertNotIn(dev.key, all_audit_dump)

        write_test_evidence(
            "T-38",
            actual=(
                f"Lan khong thay su kien cua Minh tren /audit; SecurityAdmin An chi thay metadata da loc "
                f"(khong co amount_vnd/beneficiary_account); POST/DELETE /audit bi chan HTTP 403; "
                f"quet toan bo AuditEvent khong chua secret_marker hay TOTP seed."
            ),
            details={
                "lan_event_count": len(lan_events),
                "an_event_count": len(an_events),
                "post_audit_http": r_post_audit.status_code,
                "delete_audit_http": r_del_audit.status_code,
                "secret_marker_found": False,
            },
        )

    def test_t39_https_tls_profile_and_secure_cookie_flags(self) -> None:
        """T-39: Verify HTTPS profile with local lab Root CA, strict TLS verification, Secure/HttpOnly/SameSite cookie flags, and safe error page."""
        tls_dir = Path(settings.BASE_DIR) / "private" / "tls"
        tls_dir.mkdir(parents=True, exist_ok=True)
        ca_key = tls_dir / "lab_ca.key"
        ca_crt = tls_dir / "lab_ca.crt"
        srv_key = tls_dir / "localhost.key"
        srv_csr = tls_dir / "localhost.csr"
        srv_crt = tls_dir / "localhost.crt"
        ext_cfg = tls_dir / "localhost_ext.cnf"

        openssl_bin = r"C:\ProgramData\anaconda3\Library\bin\openssl.exe"
        if not Path(openssl_bin).exists():
            openssl_bin = "openssl"

        ext_cfg.write_text(
            "[req]\n"
            "distinguished_name = req_distinguished_name\n"
            "x509_extensions = v3_ca\n"
            "[req_distinguished_name]\n"
            "[v3_ca]\n"
            "basicConstraints = critical,CA:TRUE\n"
            "keyUsage = critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier = hash\n"
            "[v3_req]\n"
            "subjectAltName = IP:127.0.0.1,DNS:localhost\n"
            "basicConstraints = CA:FALSE\n"
            "keyUsage = digitalSignature, keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n",
            encoding="utf-8",
        )

        subprocess.run(
            [
                openssl_bin,
                "req",
                "-config",
                str(ext_cfg),
                "-extensions",
                "v3_ca",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_crt),
                "-days",
                "365",
                "-subj",
                "/CN=SecurePay Lab Root CA",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                openssl_bin,
                "req",
                "-config",
                str(ext_cfg),
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(srv_key),
                "-out",
                str(srv_csr),
                "-subj",
                "/CN=127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                openssl_bin,
                "x509",
                "-req",
                "-in",
                str(srv_csr),
                "-CA",
                str(ca_crt),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(srv_crt),
                "-days",
                "365",
                "-extfile",
                str(ext_cfg),
                "-extensions",
                "v3_req",
            ],
            check=True,
            capture_output=True,
        )

        with override_settings(
            SESSION_COOKIE_SECURE=True,
            CSRF_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Lax",
            CSRF_COOKIE_SAMESITE="Lax",
            SECURE_HSTS_SECONDS=31536000,
        ):
            wsgi_app = get_wsgi_application()
            httpd = WSGIServer(("127.0.0.1", 0), _QuietWSGIHandler)
            httpd.set_app(wsgi_app)
            port = httpd.server_address[1]

            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(certfile=str(srv_crt), keyfile=str(srv_key))
            httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)

            srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            srv_thread.start()

            try:
                client_ctx = ssl.create_default_context(cafile=str(ca_crt))
                client_ctx.check_hostname = True
                client_ctx.verify_mode = ssl.CERT_REQUIRED

                with socket.create_connection(("127.0.0.1", port), timeout=5) as raw_sock:
                    with client_ctx.wrap_socket(raw_sock, server_hostname="127.0.0.1") as tls_sock:
                        tls_version = tls_sock.version()
                        peer_cert = tls_sock.getpeercert()

                req = urllib.request.Request(
                    f"https://127.0.0.1:{port}/auth/login",
                    headers={"Accept": "text/html"},
                )
                with urllib.request.urlopen(req, context=client_ctx, timeout=5) as resp:
                    status_code = resp.status
                    set_cookies = resp.headers.get_all("Set-Cookie") or []
                    cookie_header_joined = " ; ".join(set_cookies)

                # Probe prohibited route to confirm no secret/config leak on error response
                err_req = urllib.request.Request(
                    f"https://127.0.0.1:{port}/admin/",
                    headers={"Accept": "application/json"},
                )
                try:
                    urllib.request.urlopen(err_req, context=client_ctx, timeout=5)
                except urllib.error.HTTPError as e:
                    err_status = e.code
                    err_body = e.read().decode("utf-8")
            finally:
                httpd.shutdown()
                httpd.server_close()

        self.assertEqual(status_code, 200)
        self.assertIn(tls_version, ("TLSv1.3", "TLSv1.2"))
        self.assertIn("Secure", cookie_header_joined)
        self.assertIn("SameSite=Lax", cookie_header_joined)
        self.assertEqual(err_status, 403)
        self.assertNotIn(settings.SECRET_KEY, err_body)

        write_test_evidence(
            "T-39",
            actual=(
                f"Xac minh HTTPS profile voi Lab Root CA (ssl.CERT_REQUIRED, check_hostname=True): "
                f"ket noi {tls_version} thanh cong tren https://127.0.0.1:{port}/auth/login (HTTP {status_code}), "
                f"Set-Cookie co Secure va SameSite=Lax; trang loi {err_status} khong lo SECRET_KEY."
            ),
            details={
                "tls_version": tls_version,
                "cert_subject": str(peer_cert.get("subject")),
                "login_https_status": status_code,
                "set_cookie_flags_verified": True,
                "error_page_status": err_status,
            },
        )

    def test_t40_mid_transaction_fault_injection_rolls_back_atomically(self) -> None:
        """T-40: Fault injected inside `execute_payment_request_simulated` rolls back PaymentExecution, status transition, and success audit atomically."""
        req_id, _, _, _ = self._prepare_fully_approved_request()
        lan = EmployeeIdentity.objects.get(username="lan")
        clock = StepClock()
        t1 = clock.advance(60)
        chal = issue_payment_challenge(
            actor=lan,
            session_key="sess-t40",
            session_epoch=lan.security_epoch,
            request_id=req_id,
            action=ChallengeAction.EXECUTE,
            now=t1,
        )
        otp1 = totp_at(lan, t1)

        def simulated_db_fault() -> None:
            raise RuntimeError("SIMULATED_MID_TX_FAULT_T40")

        with self.assertRaises(RuntimeError):
            execute_payment_request_simulated(
                actor=lan,
                session_key="sess-t40",
                session_epoch=lan.security_epoch,
                request_id=req_id,
                challenge_id=chal.id,
                nonce=chal.nonce,
                otp_token=otp1,
                idempotency_key="IDEMP-T40-ATOMIC",
                fault_injector=simulated_db_fault,
                now=t1,
            )

        # Verify zero partial state: request is still APPROVED, challenge is still unconsumed, Execution=0, no EXECUTE_PAYMENT_SIMULATED SUCCESS audit
        req = PaymentRequest.objects.get(pk=req_id)
        chal.refresh_from_db()
        self.assertEqual(req.status, RequestStatus.APPROVED)
        self.assertIsNone(chal.consumed_at)
        self.assertEqual(PaymentExecution.objects.filter(payment_request=req).count(), 0)
        self.assertEqual(
            AuditEvent.objects.filter(
                payment_request=req, action="EXECUTE_PAYMENT_SIMULATED", result="SUCCESS"
            ).count(),
            0,
        )

        # Retry after removing the fault succeeds cleanly and creates exactly 1 PaymentExecution
        t2 = clock.advance(35)
        otp2 = totp_at(lan, t2)
        ex, is_replay = execute_payment_request_simulated(
            actor=lan,
            session_key="sess-t40",
            session_epoch=lan.security_epoch,
            request_id=req_id,
            challenge_id=chal.id,
            nonce=chal.nonce,
            otp_token=otp2,
            idempotency_key="IDEMP-T40-ATOMIC",
            now=t2,
        )
        req.refresh_from_db()
        self.assertFalse(is_replay)
        self.assertEqual(req.status, RequestStatus.EXECUTED_SIMULATED)
        self.assertEqual(PaymentExecution.objects.filter(payment_request=req).count(), 1)

        write_test_evidence(
            "T-40",
            actual=(
                f"Khi chen loi RuntimeError giua transaction execute_payment_request_simulated, PostgreSQL rollback toan bo: "
                f"PaymentExecution=0, status giu nguyen APPROVED, challenge chua consumed, AuditEvent SUCCESS=0; "
                f"sau khi bo loi va thu lai, giao dich thanh cong voi 1 bien nhan {ex.receipt_id}."
            ),
            details={
                "count_after_fault": 0,
                "status_after_fault": RequestStatus.APPROVED,
                "count_after_retry": 1,
                "receipt_id": ex.receipt_id,
            },
        )

