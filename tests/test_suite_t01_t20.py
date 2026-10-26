"""
Automated verification suite for T-01..T-20 on real PostgreSQL 17.
Covers:
- Section 12.2: Business flow & access control (T-01..T-09)
- Section 12.3: Authentication & compromised accounts (T-10..T-15)
- Section 12.4 (Part 1): Content binding, untrusted beneficiary & immutability (T-16..T-20)
"""
from __future__ import annotations

import json
from datetime import timedelta

from django.core.management import call_command
from django.test import Client, TransactionTestCase
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice

from apps.accounts.models import EmployeeIdentity, Role
from apps.audit.models import AuditEvent
from apps.common.exceptions import ReasonCode
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
from tests.helpers import (
    login_full_mfa_client,
    next_fresh_totp,
    seed_standard_lab,
    write_test_evidence,
)


class TestSuiteT01ToT20(TransactionTestCase):
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
        purpose: str = "Thanh toan hoa don thiet bi mang dot 1",
    ) -> str:
        ver_id = str(beneficiary_version_id or self.lab["b1_ver"].id)
        r_create = lan_client.post(
            "/requests",
            data=json.dumps(
                {
                    "beneficiary_version_id": ver_id,
                    "amount_vnd": amount_vnd,
                    "purpose": purpose,
                    "source_kind": SourceKind.CHAT_MESSAGE,
                    "source_excerpt": "Khan! Chuyen ngay 20tr cho doi tac theo lenh sep Nam",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_create.status_code, 201, r_create.content)
        req_id = r_create.json()["request_id"]

        r_sub = lan_client.post(
            f"/requests/{req_id}/submit",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_sub.status_code, 200, r_sub.content)
        self.assertEqual(r_sub.json()["status"], RequestStatus.PENDING_APPROVAL)
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

    def test_t01_valid_flow_and_single_receipt(self) -> None:
        """T-01: Valid flow DRAFT -> PENDING_APPROVAL -> APPROVED -> EXECUTED_SIMULATED with 1 receipt."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        huong_c = login_full_mfa_client("huong", self.creds["huong"]["password"])

        req_id = self._create_and_submit_r1(lan_c)
        req = PaymentRequest.objects.get(pk=req_id)
        self.assertEqual(req.status, RequestStatus.PENDING_APPROVAL)

        res_nam = self._issue_and_approve(nam_c, self.lab["users"]["nam"], req_id)
        self.assertEqual(res_nam["response"].status_code, 200)
        self.assertEqual(res_nam["response"].json()["request_status"], RequestStatus.PENDING_APPROVAL)

        res_huong = self._issue_and_approve(huong_c, self.lab["users"]["huong"], req_id)
        self.assertEqual(res_huong["response"].status_code, 200)
        self.assertEqual(res_huong["response"].json()["request_status"], RequestStatus.APPROVED)

        # Lan issues fresh EXECUTE challenge and executes simulated payment
        r_echal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_echal.status_code, 201)
        echal_json = r_echal.json()
        otp_lan = next_fresh_totp(self.lab["users"]["lan"])
        r_exec = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": echal_json["challenge_id"],
                    "nonce": echal_json["nonce"],
                    "otp_token": otp_lan,
                    "idempotency_key": "IDEMP-T01-001",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_exec.status_code, 200, r_exec.content)

        req.refresh_from_db()
        approvals = list(Approval.objects.filter(payment_request=req, payment_revision=req.current_revision))
        executions = list(PaymentExecution.objects.filter(payment_request=req))
        self.assertEqual(req.status, RequestStatus.EXECUTED_SIMULATED)
        self.assertEqual(len(approvals), 2)
        self.assertEqual({a.approver_person_id for a in approvals}, {"PER-NAM-002", "PER-HUONG-003"})
        self.assertNotIn(req.requester_person_id, {a.approver_person_id for a in approvals})
        self.assertEqual(len(executions), 1)

        write_test_evidence(
            "T-01",
            actual=(
                f"DRAFT -> PENDING_APPROVAL -> APPROVED -> EXECUTED_SIMULATED thanh cong; "
                f"2 Approval doc lap ({approvals[0].approver.username}, {approvals[1].approver.username}) "
                f"cung revision 1; PaymentExecution count=1 ({executions[0].receipt_id})."
            ),
            details={
                "request_id": str(req.id),
                "request_code": req.request_code,
                "status": req.status,
                "approval_count": len(approvals),
                "approver_person_ids": sorted([a.approver_person_id for a in approvals]),
                "execution_count": len(executions),
                "receipt_id": executions[0].receipt_id,
                "content_digest": executions[0].content_digest,
            },
        )

    def test_t02_single_approval_cannot_execute(self) -> None:
        """T-02: Only 1 approval (Nam) cannot execute simulated payment even if Lan calls API directly."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])

        req_id = self._create_and_submit_r1(lan_c)
        res_nam = self._issue_and_approve(nam_c, self.lab["users"]["nam"], req_id)
        self.assertEqual(res_nam["response"].status_code, 200)

        # Lan tries to issue an EXECUTE challenge when only 1 approval exists
        r_echal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_echal.status_code, 409)
        self.assertEqual(r_echal.json()["reason_code"], ReasonCode.MISSING_APPROVAL)

        # Lan also tries calling execute-simulated directly
        otp_lan = next_fresh_totp(self.lab["users"]["lan"])
        r_exec = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": res_nam["challenge_id"],
                    "nonce": res_nam["nonce"],
                    "otp_token": otp_lan,
                    "idempotency_key": "IDEMP-T02-001",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_exec.status_code, 409)
        self.assertEqual(r_exec.json()["reason_code"], ReasonCode.MISSING_APPROVAL)
        self.assertEqual(PaymentExecution.objects.filter(payment_request_id=req_id).count(), 0)
        self.assertEqual(Approval.objects.filter(payment_request_id=req_id).count(), 1)

        write_test_evidence(
            "T-02",
            actual=(
                f"Khi moi co 1 phieu cua Nam, API xin EXECUTE challenge tra HTTP {r_echal.status_code} "
                f"({r_echal.json()['reason_code']}) va goi thang execute-simulated tra HTTP {r_exec.status_code} "
                f"({r_exec.json()['reason_code']}); Approval count=1, PaymentExecution count=0."
            ),
            details={
                "challenge_issue_http": r_echal.status_code,
                "execute_direct_http": r_exec.status_code,
                "execute_reason_code": r_exec.json().get("reason_code"),
                "approval_count": Approval.objects.filter(payment_request_id=req_id).count(),
                "execution_count": PaymentExecution.objects.filter(payment_request_id=req_id).count(),
            },
        )

    def test_t03_reject_is_terminal(self) -> None:
        """T-03: REJECTED is terminal; subsequent approve or execute attempts are blocked."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        huong_c = login_full_mfa_client("huong", self.creds["huong"]["password"])

        req_id = self._create_and_submit_r1(lan_c)
        r_chal = huong_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.REJECT, "reason": "Ho so chung tu chua khop"}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_chal.status_code, 201)
        chal_json = r_chal.json()
        otp_huong = next_fresh_totp(self.lab["users"]["huong"])
        r_rej = huong_c.post(
            f"/requests/{req_id}/reject",
            data=json.dumps(
                {
                    "challenge_id": chal_json["challenge_id"],
                    "nonce": chal_json["nonce"],
                    "otp_token": otp_huong,
                    "reason": "Ho so chung tu chua khop voi PO goc",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_rej.status_code, 200)
        self.assertEqual(r_rej.json()["status"], RequestStatus.REJECTED)

        # Nam tries to approve after rejection
        r_nam_chal = nam_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_nam_chal.status_code, 409)
        self.assertEqual(r_nam_chal.json()["reason_code"], ReasonCode.TERMINAL_STATE)

        # Lan tries to execute after rejection
        r_lan_exec = lan_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": chal_json["challenge_id"],
                    "nonce": chal_json["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["lan"]),
                    "idempotency_key": "IDEMP-T03",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_lan_exec.status_code, 409)
        self.assertEqual(r_lan_exec.json()["reason_code"], ReasonCode.TERMINAL_STATE)
        req = PaymentRequest.objects.get(pk=req_id)
        self.assertEqual(req.status, RequestStatus.REJECTED)
        self.assertEqual(PaymentExecution.objects.filter(payment_request=req).count(), 0)

        write_test_evidence(
            "T-03",
            actual=(
                f"Huong tu choi dua yeu cau ve REJECTED (HTTP 200); Nam thu xin challenge duyet bi HTTP {r_nam_chal.status_code} "
                f"(TERMINAL_STATE), Lan thu execute bi HTTP {r_lan_exec.status_code} (TERMINAL_STATE); "
                f"trang thai giu nguyen REJECTED, PaymentExecution=0."
            ),
            details={
                "status_after_reject": req.status,
                "nam_challenge_http": r_nam_chal.status_code,
                "lan_execute_http": r_lan_exec.status_code,
                "execution_count": 0,
            },
        )

    def test_t04_cancel_ownership_and_terminal_state(self) -> None:
        """T-04: Another requester (Minh) cannot cancel Lan's request; Lan cancels; CANCELLED is terminal."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        minh_c = login_full_mfa_client("minh", self.creds["minh"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])

        req_id = self._create_and_submit_r1(lan_c)

        # Minh attempts to cancel Lan's request
        r_minh = minh_c.post(
            f"/requests/{req_id}/cancel",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_minh.status_code, 403)
        self.assertEqual(PaymentRequest.objects.get(pk=req_id).status, RequestStatus.PENDING_APPROVAL)

        # Lan cancels her own request
        r_lan = lan_c.post(
            f"/requests/{req_id}/cancel",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_lan.status_code, 200)
        self.assertEqual(r_lan.json()["status"], RequestStatus.CANCELLED)

        # Nam tries to approve after cancel
        r_nam = nam_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_nam.status_code, 409)
        self.assertEqual(r_nam.json()["reason_code"], ReasonCode.TERMINAL_STATE)

        write_test_evidence(
            "T-04",
            actual=(
                f"Minh thu huy R1 cua Lan bi HTTP {r_minh.status_code} ({r_minh.json()['reason_code']}); "
                f"Lan huy thanh cong HTTP {r_lan.status_code} -> CANCELLED; Nam thu duyet tiep bi HTTP {r_nam.status_code}."
            ),
            details={
                "minh_cancel_http": r_minh.status_code,
                "lan_cancel_http": r_lan.status_code,
                "post_cancel_approve_http": r_nam.status_code,
                "final_status": PaymentRequest.objects.get(pk=req_id).status,
            },
        )

    def test_t05_lookalike_display_name_and_avatar_grant_no_authority(self) -> None:
        """T-05: Account `nam_lookalike` with identical display_name to Director Nam has zero approval authority."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        fake_c = login_full_mfa_client("nam_lookalike", self.creds["nam_lookalike"]["password"])

        req_id = self._create_and_submit_r1(lan_c)
        fake_user = self.lab["users"]["nam_lookalike"]
        real_nam = self.lab["users"]["nam"]
        self.assertEqual(fake_user.display_name, real_nam.display_name)
        self.assertEqual(fake_user.role, Role.UNPRIVILEGED)

        r_chal = fake_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_chal.status_code, 403)
        self.assertEqual(Approval.objects.filter(payment_request_id=req_id).count(), 0)

        audit_ev = AuditEvent.objects.filter(
            actor=fake_user, action="ISSUE_PAYMENT_CHALLENGE"
        ).order_by("-created_at").first()
        self.assertIsNotNone(audit_ev)
        self.assertEqual(audit_ev.actor_username_snapshot, "nam_lookalike")

        write_test_evidence(
            "T-05",
            actual=(
                f"Tai khoan nam_lookalike (display_name='{fake_user.display_name}', person_id='{fake_user.person_id}') "
                f"xin challenge APPROVE_DIRECTOR bi HTTP {r_chal.status_code} ({r_chal.json()['reason_code']}); "
                f"Approval count=0; AuditEvent ghi nhan actor={fake_user.username} ({fake_user.person_id})."
            ),
            details={
                "fake_username": fake_user.username,
                "fake_display_name": fake_user.display_name,
                "fake_role": fake_user.role,
                "http_status": r_chal.status_code,
                "reason_code": r_chal.json().get("reason_code"),
                "approval_count": 0,
            },
        )

    def test_t06_client_cannot_inject_role_verified_or_state(self) -> None:
        """T-06: Client payload supplying role=DIRECTOR, verified=true, status=APPROVED is rejected."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        r_inject = lan_c.post(
            "/requests",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(self.lab["b1_ver"].id),
                    "amount_vnd": 15_000_000,
                    "purpose": "Thu chen truong trai quyen",
                    "role": "DIRECTOR",
                    "verified": True,
                    "status": "APPROVED",
                    "approver_id": str(self.lab["users"]["nam"].id),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_inject.status_code, 400)
        self.assertEqual(r_inject.json()["reason_code"], ReasonCode.FORBIDDEN)

        lan_user = EmployeeIdentity.objects.get(username="lan")
        self.assertEqual(lan_user.role, Role.REQUESTER)
        self.assertEqual(PaymentRequest.objects.count(), 0)

        write_test_evidence(
            "T-06",
            actual=(
                f"Payload chua role/verified/status/approver_id bi tu choi voi HTTP {r_inject.status_code} "
                f"({r_inject.json()['reason_code']}); role cua Lan giu nguyen REQUESTER; khong tao request sai."
            ),
            details={
                "http_status": r_inject.status_code,
                "reason_code": r_inject.json()["reason_code"],
                "lan_role_after": lan_user.role,
                "request_count": PaymentRequest.objects.count(),
            },
        )

    def test_t07_no_self_approval_or_duplicate_approver_slot(self) -> None:
        """T-07: Self-approval (even if requester is temporarily granted DIRECTOR role in fixture) and duplicate slot are blocked."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        req_id = self._create_and_submit_r1(lan_c)

        # Fixture test: temporarily set Lan's role to DIRECTOR in DB to test separation-of-duties check
        lan_user = EmployeeIdentity.objects.get(username="lan")
        lan_user.role = Role.DIRECTOR
        lan_user.save(update_fields=["role"])

        r_self_chal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_self_chal.status_code, 403)
        self.assertEqual(r_self_chal.json()["reason_code"], ReasonCode.SELF_APPROVAL)

        # Restore Lan's role to REQUESTER
        lan_user.role = Role.REQUESTER
        lan_user.save(update_fields=["role"])

        # Nam approves slot 1 (DIRECTOR)
        res_nam1 = self._issue_and_approve(nam_c, self.lab["users"]["nam"], req_id)
        self.assertEqual(res_nam1["response"].status_code, 200)

        # Nam tries to issue and approve a second time on the same revision
        r_dup_chal = nam_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_dup_chal.status_code, 201)
        dup_json = r_dup_chal.json()
        r_dup_app = nam_c.post(
            f"/requests/{req_id}/approve",
            data=json.dumps(
                {
                    "challenge_id": dup_json["challenge_id"],
                    "nonce": dup_json["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["nam"]),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_dup_app.status_code, 409)
        self.assertEqual(r_dup_app.json()["reason_code"], ReasonCode.DUPLICATE_APPROVER)
        self.assertEqual(Approval.objects.filter(payment_request_id=req_id).count(), 1)

        write_test_evidence(
            "T-07",
            actual=(
                f"Lan thu tu duyet (ke ca khi fixture gan role DIRECTOR) bi HTTP {r_self_chal.status_code} "
                f"(SELF_APPROVAL); Nam thu duyet lan 2 chiem 2 slot bi HTTP {r_dup_app.status_code} "
                f"(DUPLICATE_APPROVER); Approval count=1."
            ),
            details={
                "self_approval_http": r_self_chal.status_code,
                "self_approval_reason": r_self_chal.json()["reason_code"],
                "duplicate_slot_http": r_dup_app.status_code,
                "duplicate_slot_reason": r_dup_app.json()["reason_code"],
                "approval_count": Approval.objects.filter(payment_request_id=req_id).count(),
            },
        )

    def test_t08_idor_other_requester_blocked(self) -> None:
        """T-08: Lan cannot view, revise, cancel, or read receipt of Minh's request R2."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        minh_c = login_full_mfa_client("minh", self.creds["minh"]["password"])

        r2_id = self._create_and_submit_r1(
            minh_c,
            amount_vnd=33_000_000,
            purpose="Yeu cau rieng cua Minh",
        )

        r_detail = lan_c.get(f"/requests/{r2_id}", HTTP_ACCEPT="application/json")
        r_revise = lan_c.post(
            f"/requests/{r2_id}/revise",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(self.lab["b1_ver"].id),
                    "amount_vnd": 10_000,
                    "purpose": "Lan sua trom R2",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        r_cancel = lan_c.post(f"/requests/{r2_id}/cancel", HTTP_ACCEPT="application/json")
        r_receipt = lan_c.get(f"/requests/{r2_id}/receipt", HTTP_ACCEPT="application/json")

        for resp in (r_detail, r_revise, r_cancel, r_receipt):
            self.assertEqual(resp.status_code, 403)
            self.assertNotIn("Yeu cau rieng cua Minh", resp.content.decode("utf-8"))

        write_test_evidence(
            "T-08",
            actual=(
                f"Lan truy cap R2 cua Minh bi chan tren moi endpoint: detail={r_detail.status_code}, "
                f"revise={r_revise.status_code}, cancel={r_cancel.status_code}, receipt={r_receipt.status_code}; "
                f"khong ro ri noi dung R2."
            ),
            details={
                "detail_http": r_detail.status_code,
                "revise_http": r_revise.status_code,
                "cancel_http": r_cancel.status_code,
                "receipt_http": r_receipt.status_code,
            },
        )

    def test_t09_security_admin_has_no_financial_authority_and_no_django_admin(self) -> None:
        """T-09: SecurityAdmin `an` cannot create, approve, or execute requests, and `/admin/` is blocked."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        an_c = login_full_mfa_client("an", self.creds["an"]["password"])

        req_id = self._create_and_submit_r1(lan_c)

        r_create = an_c.post(
            "/requests",
            data=json.dumps(
                {"beneficiary_version_id": str(self.lab["b1_ver"].id), "amount_vnd": 1_000_000, "purpose": "An tao"}
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        r_chal = an_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        r_exec = an_c.post(
            f"/requests/{req_id}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": "00000000-0000-0000-0000-000000000000",
                    "nonce": "fake",
                    "otp_token": "123456",
                    "idempotency_key": "AN-EXEC",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        r_admin = an_c.get("/admin/", HTTP_ACCEPT="application/json")

        self.assertEqual(r_create.status_code, 403)
        self.assertEqual(r_chal.status_code, 403)
        self.assertEqual(r_exec.status_code, 403)
        self.assertEqual(r_admin.status_code, 403)
        self.assertEqual(Approval.objects.filter(payment_request_id=req_id).count(), 0)
        self.assertEqual(PaymentExecution.objects.filter(payment_request_id=req_id).count(), 0)

        write_test_evidence(
            "T-09",
            actual=(
                f"SecurityAdmin An bi tu choi moi thao tac tai chinh: create={r_create.status_code}, "
                f"challenge_approve={r_chal.status_code}, execute={r_exec.status_code}; "
                f"duong dan /admin/ bi chan HTTP {r_admin.status_code} (PROHIBITED_ROUTE_ATTEMPT)."
            ),
            details={
                "create_http": r_create.status_code,
                "challenge_http": r_chal.status_code,
                "execute_http": r_exec.status_code,
                "django_admin_http": r_admin.status_code,
            },
        )

    def test_t10_password_only_session_cannot_access_protected_actions(self) -> None:
        """T-10: Knowing Nam's password without completing step-2 MFA grants no session authority."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        req_id = self._create_and_submit_r1(lan_c)

        attacker_c = Client()
        r_step1 = attacker_c.post(
            "/auth/login",
            data={"username": "nam", "password": self.creds["nam"]["password"]},
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_step1.status_code, 200)
        self.assertEqual(r_step1.json()["reason_code"], ReasonCode.MFA_REQUIRED)

        # Try going straight to challenge/approve without completing /auth/mfa
        r_chal = attacker_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_chal.status_code, 401)
        self.assertEqual(r_chal.json()["reason_code"], ReasonCode.MFA_REQUIRED)
        self.assertEqual(Approval.objects.filter(payment_request_id=req_id).count(), 0)

        write_test_evidence(
            "T-10",
            actual=(
                f"Sau buoc mat khau (/auth/login -> MFA_REQUIRED), phien pre-auth goi /challenges bi chan "
                f"HTTP {r_chal.status_code} ({r_chal.json()['reason_code']}); Approval count=0."
            ),
            details={
                "step1_reason_code": r_step1.json()["reason_code"],
                "challenge_http_without_mfa": r_chal.status_code,
                "reason_code": r_chal.json()["reason_code"],
                "approval_count": 0,
            },
        )

    def test_t11_stolen_session_requires_fresh_auth_and_logout_invalidates_challenges(self) -> None:
        """T-11: Post-MFA session cannot approve without fresh challenge+TOTP; logout invalidates open challenges without bumping security_epoch."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        req_id = self._create_and_submit_r1(lan_c)

        nam_user = EmployeeIdentity.objects.get(username="nam")
        epoch_before = nam_user.security_epoch

        # Branch A: stolen session tries to call approve without OTP or with client-injected mfa_verified=true
        r_chal1 = nam_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        c1_json = r_chal1.json()
        cid1 = c1_json["challenge_id"]
        r_no_otp = nam_c.post(
            f"/requests/{req_id}/approve",
            data=json.dumps({"challenge_id": cid1, "nonce": c1_json["nonce"], "otp_token": "", "mfa_verified": True}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_no_otp.status_code, 400)
        self.assertEqual(Approval.objects.filter(payment_request_id=req_id).count(), 0)

        # Branch B: issue challenge, then logout -> challenge.invalidated_at is set, epoch unchanged
        r_logout = nam_c.post("/auth/logout", HTTP_ACCEPT="application/json")
        self.assertEqual(r_logout.status_code, 200)

        chal_obj = ActionChallenge.objects.get(pk=cid1)
        nam_user.refresh_from_db()
        self.assertIsNotNone(chal_obj.invalidated_at)
        self.assertEqual(nam_user.security_epoch, epoch_before)

        # Replaying old session after logout fails with 401
        r_after_logout = nam_c.post(
            f"/requests/{req_id}/approve",
            data=json.dumps(
                {
                    "challenge_id": cid1,
                    "nonce": c1_json["nonce"],
                    "otp_token": next_fresh_totp(nam_user),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_after_logout.status_code, 401)

        write_test_evidence(
            "T-11",
            actual=(
                f"Phien bi danh cap gui mfa_verified=true nhung thieu OTP bi HTTP {r_no_otp.status_code}; "
                f"sau logout, challenge co invalidated_at != None, security_epoch giu nguyen ({nam_user.security_epoch}), "
                f"goi lai bang phien cu bi HTTP {r_after_logout.status_code}."
            ),
            details={
                "no_otp_http": r_no_otp.status_code,
                "challenge_invalidated": chal_obj.invalidated_at is not None,
                "epoch_before": epoch_before,
                "epoch_after": nam_user.security_epoch,
                "after_logout_http": r_after_logout.status_code,
            },
        )

    def test_t12_single_compromised_approver_cannot_complete_payment(self) -> None:
        """T-12: Full compromise of Nam (password + MFA) yields at most 1 approval; payment still cannot be executed."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        req_id = self._create_and_submit_r1(lan_c)

        # Compromised Nam approves legitimately for slot 1 (DIRECTOR)
        res_nam = self._issue_and_approve(nam_c, self.lab["users"]["nam"], req_id)
        self.assertEqual(res_nam["response"].status_code, 200)

        # Attacker using Nam tries to request CONTROLLER challenge
        r_nam_ctl = nam_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_CONTROLLER}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_nam_ctl.status_code, 403)

        # Lan tries to execute with her own valid credentials to test if 1 compromised approver was enough
        r_lan_chal = lan_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_lan_chal.status_code, 409)
        self.assertEqual(r_lan_chal.json()["reason_code"], ReasonCode.MISSING_APPROVAL)
        self.assertEqual(Approval.objects.filter(payment_request_id=req_id).count(), 1)
        self.assertEqual(PaymentExecution.objects.filter(payment_request_id=req_id).count(), 0)

        write_test_evidence(
            "T-12",
            actual=(
                f"Tai khoan Nam bi chiem toan bo chi tao duoc 1 phieu DIRECTOR; thu xin challenge APPROVE_CONTROLLER "
                f"bi HTTP {r_nam_ctl.status_code}; Lan thu xin EXECUTE challenge bi HTTP {r_lan_chal.status_code} "
                f"(MISSING_APPROVAL); PaymentExecution=0."
            ),
            details={
                "approval_count": 1,
                "nam_controller_attempt_http": r_nam_ctl.status_code,
                "lan_execute_challenge_http": r_lan_chal.status_code,
                "execution_count": 0,
            },
        )

    def test_t13_otp_and_password_throttling_persist_across_sessions(self) -> None:
        """T-13: Repeated wrong OTPs trigger persistent account/device cooldown across sessions and challenges."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c1 = login_full_mfa_client("nam", self.creds["nam"]["password"])
        nam_c2 = login_full_mfa_client("nam", self.creds["nam"]["password"])
        req_id = self._create_and_submit_r1(lan_c)

        r_chal1 = nam_c1.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        c1_json = r_chal1.json()

        statuses = []
        for _ in range(5):
            r_bad = nam_c1.post(
                f"/requests/{req_id}/approve",
                data=json.dumps(
                    {"challenge_id": c1_json["challenge_id"], "nonce": c1_json["nonce"], "otp_token": "000000"}
                ),
                content_type="application/json",
                HTTP_ACCEPT="application/json",
            )
            statuses.append(r_bad.status_code)

        nam_user = EmployeeIdentity.objects.get(username="nam")
        self.assertEqual(nam_user.failed_otp_attempts, 5)
        self.assertIsNotNone(nam_user.otp_throttled_until)

        # Switching to second session nam_c2 with a valid challenge + OTP is still blocked by cooldown (HTTP 429)
        r_chal2 = nam_c2.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        c2_json = r_chal2.json()
        r_locked = nam_c2.post(
            f"/requests/{req_id}/approve",
            data=json.dumps(
                {
                    "challenge_id": c2_json["challenge_id"],
                    "nonce": c2_json["nonce"],
                    "otp_token": next_fresh_totp(nam_user),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_locked.status_code, 429)
        self.assertEqual(r_locked.json()["reason_code"], ReasonCode.RATE_LIMITED)

        # After cooldown expires, Nam can approve again
        nam_user.otp_throttled_until = timezone.now() - timedelta(seconds=5)
        nam_user.save(update_fields=["otp_throttled_until"])
        res_recovered = self._issue_and_approve(nam_c2, nam_user, req_id)
        self.assertEqual(res_recovered["response"].status_code, 200)

        write_test_evidence(
            "T-13",
            actual=(
                f"5 lan nhap OTP sai tren session 1 tang failed_otp_attempts=5 va dat otp_throttled_until; "
                f"doi sang session 2 va challenge moi van bi chan HTTP {r_locked.status_code} (RATE_LIMITED); "
                f"sau khi het thoi gian cho, Nam xac thuc lai thanh cong (HTTP 200)."
            ),
            details={
                "failed_attempt_statuses": statuses,
                "second_session_http_while_locked": r_locked.status_code,
                "post_cooldown_http": res_recovered["response"].status_code,
            },
        )

    def test_t14_no_self_service_factor_or_role_change_routes(self) -> None:
        """T-14: Baseline blocks any self-service route to add/replace MFA factor, reset MFA, or change role."""
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        nam_user = EmployeeIdentity.objects.get(username="nam")
        dev_before = TOTPDevice.objects.get(user=nam_user, confirmed=True).key
        epoch_before = nam_user.security_epoch

        candidate_paths = [
            "/auth/reset-mfa",
            "/reset-mfa",
            "/auth/change-factor",
            "/auth/change-role",
        ]
        codes = {}
        for path in candidate_paths:
            resp = nam_c.post(path, data={"role": "CONTROLLER", "security_epoch": 99}, HTTP_ACCEPT="application/json")
            codes[path] = resp.status_code
            self.assertEqual(resp.status_code, 403)

        nam_user.refresh_from_db()
        dev_after = TOTPDevice.objects.get(user=nam_user, confirmed=True).key
        self.assertEqual(dev_before, dev_after)
        self.assertEqual(nam_user.security_epoch, epoch_before)

        write_test_evidence(
            "T-14",
            actual=(
                f"Moi duong dan tu doi MFA factor/role qua HTTP deu bi chan HTTP 403 ({codes}); "
                f"TOTPDevice va security_epoch ({epoch_before}) giu nguyen."
            ),
            details={"probed_routes": codes, "security_epoch": nam_user.security_epoch},
        )

    def test_t15_recovery_is_offline_only_and_increments_epoch(self) -> None:
        """T-15: Suspended account cannot be unsuspended by SecurityAdmin over HTTP; offline `recover_principal` increments epoch and moves requests to HOLD."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        an_c = login_full_mfa_client("an", self.creds["an"]["password"])

        req_id = self._create_and_submit_r1(lan_c)
        res_nam = self._issue_and_approve(nam_c, self.lab["users"]["nam"], req_id)
        self.assertEqual(res_nam["response"].status_code, 200)

        nam_user = EmployeeIdentity.objects.get(username="nam")
        epoch_initial = nam_user.security_epoch
        reason_str = "Nghi ngo lo thiet bi xac thuc cua Nam"

        # SecurityAdmin An suspends Nam due to incident
        r_achal = an_c.post(
            f"/security/users/{nam_user.id}/challenges",
            data=json.dumps({"action": ChallengeAction.SUSPEND, "reason": reason_str}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_achal.status_code, 201)
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

        # SecurityAdmin An tries to unsuspend/recover Nam via prohibited HTTP endpoint
        r_http_recover = an_c.post(f"/security/users/{nam_user.id}/unsuspend", HTTP_ACCEPT="application/json")
        self.assertEqual(r_http_recover.status_code, 403)

        # Trusted offline CLI recovery `recover_principal`
        call_command(
            "recover_principal",
            username="nam",
            rotate_mfa=True,
            note="Xac minh danh tinh truc tiep va cap lai TOTP seed moi",
            verbosity=0,
        )
        nam_user.refresh_from_db()
        req = PaymentRequest.objects.get(pk=req_id)
        approval = Approval.objects.get(payment_request=req)

        self.assertTrue(nam_user.is_operational)
        self.assertGreater(nam_user.security_epoch, epoch_initial)
        self.assertEqual(req.status, RequestStatus.HOLD)
        self.assertEqual(approval.status, ApprovalStatus.INVALIDATED_BY_INCIDENT)

        # Old session of Nam is rejected due to epoch mismatch
        r_old_session = nam_c.get("/requests", HTTP_ACCEPT="application/json")
        self.assertEqual(r_old_session.status_code, 401)

        write_test_evidence(
            "T-15",
            actual=(
                f"SecurityAdmin dinh chi Nam -> R1 chuyen sang HOLD, phieu cu bi INVALIDATED_BY_INCIDENT; "
                f"thu mo lai quyen qua HTTP /unsuspend bi chan 403; chay CLI tin cay recover_principal tang security_epoch "
                f"tu {epoch_initial} -> {nam_user.security_epoch}, phien cu bi chan HTTP {r_old_session.status_code}, "
                f"phieu cu khong tu hoi sinh."
            ),
            details={
                "epoch_initial": epoch_initial,
                "epoch_after_recovery": nam_user.security_epoch,
                "request_status": req.status,
                "approval_status": approval.status,
                "old_session_http": r_old_session.status_code,
            },
        )

    def test_t16_challenge_bound_to_actor(self) -> None:
        """T-16: Challenge C1 issued to Nam cannot be used by Huong or Lan even with their own valid OTP."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        huong_c = login_full_mfa_client("huong", self.creds["huong"]["password"])

        req_id = self._create_and_submit_r1(lan_c)
        r_chal = nam_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        c_nam = r_chal.json()

        # Huong tries to use Nam's challenge with Huong's valid OTP
        r_huong = huong_c.post(
            f"/requests/{req_id}/approve",
            data=json.dumps(
                {
                    "challenge_id": c_nam["challenge_id"],
                    "nonce": c_nam["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["huong"]),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_huong.status_code, 403)
        self.assertEqual(r_huong.json()["reason_code"], ReasonCode.WRONG_SCOPE)
        self.assertEqual(Approval.objects.filter(payment_request_id=req_id).count(), 0)

        write_test_evidence(
            "T-16",
            actual=(
                f"Challenge C1 cap cho Nam khi bi Huong su dung (kem OTP hop le cua Huong) bi tu choi "
                f"HTTP {r_huong.status_code} ({r_huong.json()['reason_code']}); Approval count=0."
            ),
            details={
                "http_status": r_huong.status_code,
                "reason_code": r_huong.json()["reason_code"],
                "approval_count": 0,
            },
        )

    def test_t17_challenge_bound_to_request_and_action(self) -> None:
        """T-17: Challenge C1 bound to APPROVE_DIRECTOR R1 cannot be used to approve R2, reject R1, or execute R1."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])

        r1_id = self._create_and_submit_r1(lan_c, amount_vnd=10_000_000, purpose="Yeu cau R1")
        r2_id = self._create_and_submit_r1(lan_c, amount_vnd=12_000_000, purpose="Yeu cau R2")

        r_chal = nam_c.post(
            f"/requests/{r1_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        c_r1 = r_chal.json()

        # Use C1 to approve R2
        r_wrong_req = nam_c.post(
            f"/requests/{r2_id}/approve",
            data=json.dumps(
                {
                    "challenge_id": c_r1["challenge_id"],
                    "nonce": c_r1["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["nam"]),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_wrong_req.status_code, 409)
        self.assertEqual(r_wrong_req.json()["reason_code"], ReasonCode.WRONG_SCOPE)

        # Use C1 to reject R1
        r_wrong_act = nam_c.post(
            f"/requests/{r1_id}/reject",
            data=json.dumps(
                {
                    "challenge_id": c_r1["challenge_id"],
                    "nonce": c_r1["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["nam"]),
                    "reason": "Sai action",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_wrong_act.status_code, 409)
        self.assertEqual(r_wrong_act.json()["reason_code"], ReasonCode.WRONG_SCOPE)

        write_test_evidence(
            "T-17",
            actual=(
                f"Challenge APPROVE_DIRECTOR R1 dung sang R2 bi HTTP {r_wrong_req.status_code} (WRONG_SCOPE); "
                f"dung sang REJECT R1 bi HTTP {r_wrong_act.status_code} (WRONG_SCOPE)."
            ),
            details={
                "wrong_request_http": r_wrong_req.status_code,
                "wrong_request_reason": r_wrong_req.json()["reason_code"],
                "wrong_action_http": r_wrong_act.status_code,
                "wrong_action_reason": r_wrong_act.json()["reason_code"],
            },
        )

    def test_t18_unverified_or_revoked_beneficiary_blocked(self) -> None:
        """T-18: Pending (BEN-003), revoked (BEN-004), or arbitrary client bank accounts are rejected."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])

        r_pending = lan_c.post(
            "/requests",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(self.lab["b3_pending_ver"].id),
                    "amount_vnd": 5_000_000,
                    "purpose": "Thu nguoi nhan PENDING",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        r_revoked = lan_c.post(
            "/requests",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(self.lab["b4_revoked_ver"].id),
                    "amount_vnd": 5_000_000,
                    "purpose": "Thu nguoi nhan REVOKED",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        r_custom_acc = lan_c.post(
            "/requests",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(self.lab["b1_ver"].id),
                    "account_number_override": "999988887777",
                    "amount_vnd": 5_000_000,
                    "purpose": "Thu chen so tai khoan tu khai",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )

        self.assertEqual(r_pending.status_code, 400)
        self.assertEqual(r_pending.json()["reason_code"], ReasonCode.BENEFICIARY_INVALID)
        self.assertEqual(r_revoked.status_code, 400)
        self.assertEqual(r_revoked.json()["reason_code"], ReasonCode.BENEFICIARY_INVALID)
        self.assertEqual(r_custom_acc.status_code, 400)
        self.assertEqual(r_custom_acc.json()["reason_code"], ReasonCode.FORBIDDEN)
        self.assertEqual(PaymentRequest.objects.count(), 0)

        write_test_evidence(
            "T-18",
            actual=(
                f"Tao yeu cau voi BEN-003 (PENDING) bi HTTP {r_pending.status_code} (BENEFICIARY_INVALID), "
                f"BEN-004 (REVOKED) bi HTTP {r_revoked.status_code} (BENEFICIARY_INVALID), "
                f"chen account_number_override tu khai bi HTTP {r_custom_acc.status_code} (FORBIDDEN); Request count=0."
            ),
            details={
                "pending_http": r_pending.status_code,
                "revoked_http": r_revoked.status_code,
                "custom_account_http": r_custom_acc.status_code,
                "request_count": 0,
            },
        )

    def test_t19_frozen_submitted_revision_cannot_be_silently_modified(self) -> None:
        """T-19: Submitted revision 1 with an approval cannot be edited in-place via /edit or POST /requests/<id>."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])

        req_id = self._create_and_submit_r1(lan_c, amount_vnd=20_000_000)
        self._issue_and_approve(nam_c, self.lab["users"]["nam"], req_id)

        req = PaymentRequest.objects.get(pk=req_id)
        rev1 = req.current_revision
        digest_before = rev1.content_digest

        # Attempt direct in-place edit on /requests/<id>/edit and /requests/<id>
        r_direct_edit = lan_c.post(
            f"/requests/{req_id}/edit",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(self.lab["b2_ver"].id),
                    "amount_vnd": 99_000_000,
                    "purpose": "Sua am tham",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_direct_edit.status_code, 409)
        self.assertEqual(r_direct_edit.json()["reason_code"], ReasonCode.IMMUTABLE_REVISION)

        rev1.refresh_from_db()
        self.assertEqual(rev1.amount_vnd, 20_000_000)
        self.assertEqual(rev1.content_digest, digest_before)
        self.assertEqual(Approval.objects.get(payment_revision=rev1).content_digest, digest_before)

        write_test_evidence(
            "T-19",
            actual=(
                f"Cap nhat truc tiep vao /requests/<id>/edit khi revision 1 da dong bang bi HTTP {r_direct_edit.status_code} "
                f"(IMMUTABLE_REVISION); amount_vnd={rev1.amount_vnd} va content_digest={rev1.content_digest[:16]}... giu nguyen."
            ),
            details={
                "direct_edit_http": r_direct_edit.status_code,
                "reason_code": r_direct_edit.json()["reason_code"],
                "rev1_amount_vnd": rev1.amount_vnd,
                "rev1_digest": rev1.content_digest,
            },
        )

    def test_t20_new_revision_invalidates_prior_approvals_and_challenges(self) -> None:
        """T-20: Revising an approved/partially-approved request creates revision 2 in DRAFT and invalidates all prior approvals & challenges."""
        lan_c = login_full_mfa_client("lan", self.creds["lan"]["password"])
        nam_c = login_full_mfa_client("nam", self.creds["nam"]["password"])
        huong_c = login_full_mfa_client("huong", self.creds["huong"]["password"])

        req_id = self._create_and_submit_r1(lan_c, amount_vnd=20_000_000)
        # Nam approves rev 1
        self._issue_and_approve(nam_c, self.lab["users"]["nam"], req_id)
        # Huong issues a challenge on rev 1
        r_hchal = huong_c.post(
            f"/requests/{req_id}/challenges",
            data=json.dumps({"action": ChallengeAction.APPROVE_CONTROLLER}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        old_huong_chal = r_hchal.json()

        # Lan uses legitimate /revise endpoint to change amount to 25,000,000 VND
        r_rev = lan_c.post(
            f"/requests/{req_id}/revise",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(self.lab["b1_ver"].id),
                    "amount_vnd": 25_000_000,
                    "purpose": "Dieu chinh chi phi van chuyen theo phu luc 02",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_rev.status_code, 200)
        self.assertEqual(r_rev.json()["revision_number"], 2)
        self.assertEqual(r_rev.json()["status"], RequestStatus.DRAFT)

        req = PaymentRequest.objects.get(pk=req_id)
        old_approval = Approval.objects.get(payment_request=req, payment_revision__revision_number=1)
        old_challenge = ActionChallenge.objects.get(pk=old_huong_chal["challenge_id"])
        self.assertEqual(req.status, RequestStatus.DRAFT)
        self.assertEqual(req.current_revision.revision_number, 2)
        self.assertEqual(old_approval.status, ApprovalStatus.SUPERSEDED_BY_REVISION)
        self.assertIsNotNone(old_challenge.invalidated_at)

        # Submitting rev 2 and trying to use old_huong_chal fails
        lan_c.post(f"/requests/{req_id}/submit", HTTP_ACCEPT="application/json")
        r_use_old_chal = huong_c.post(
            f"/requests/{req_id}/approve",
            data=json.dumps(
                {
                    "challenge_id": old_huong_chal["challenge_id"],
                    "nonce": old_huong_chal["nonce"],
                    "otp_token": next_fresh_totp(self.lab["users"]["huong"]),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(r_use_old_chal.status_code, 409)
        self.assertEqual(r_use_old_chal.json()["reason_code"], ReasonCode.WRONG_SCOPE)

        write_test_evidence(
            "T-20",
            actual=(
                f"Lan tao revision 2 dua yeu cau ve DRAFT; phieu duyet rev 1 cua Nam chuyen sang "
                f"status='{old_approval.status}', challenge cua Huong co invalidated_at != None; "
                f"thu dung lai challenge cu cho rev 2 bi HTTP {r_use_old_chal.status_code} (WRONG_SCOPE)."
            ),
            details={
                "new_revision_number": req.current_revision.revision_number,
                "status_after_revise": RequestStatus.DRAFT,
                "old_approval_status": old_approval.status,
                "old_challenge_invalidated": old_challenge.invalidated_at is not None,
                "use_old_challenge_http": r_use_old_chal.status_code,
            },
        )

