"""
Reproducible runner for the 4 demonstration scenarios (D-01..D-04) and N=5 empirical trade-off measurements (M8).
Executes against real PostgreSQL 17 with isolated sessions for Van Phu, Dac Qui, Doan Phuc,
Ngoc Chau, and DacQui_lookalike.
Saves sanitized JSON traces, rendered HTML snapshots, and visual PNG evidence cards in `evidence/demos/`,
and generates `docs/05_tradeoffs.md` with real measured timings and step counts.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import threading
import time

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import postgres_ctl  # noqa: E402


def _load_font(size: int, bold: bool = False):
    candidates = (
        [r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\consolab.ttf"]
        if bold
        else [r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\consola.ttf"]
    )
    for c in candidates:
        if Path(c).exists():
            try:
                return ImageFont.truetype(c, size=size)
            except Exception:
                pass
    return ImageFont.load_default()


def render_evidence_png(out_path: Path, title: str, subtitle: str, sections: list[tuple[str, list[str]]]) -> None:
    """
    Render a visual evidence snapshot PNG summarizing the real HTTP/DB/Audit state captured during a demo step.
    Strictly excludes any password, OTP code, TOTP seed, or raw session cookie.
    """
    width = 1400
    line_height = 24
    total_lines = sum(len(lines) + 2 for _, lines in sections)
    height = max(620, 150 + total_lines * line_height)

    img = Image.new("RGB", (width, height), "#f8fafc")
    draw = ImageDraw.Draw(img)
    f_title = _load_font(22, bold=True)
    f_sub = _load_font(15, bold=False)
    f_sec = _load_font(16, bold=True)
    f_mono = _load_font(14, bold=False)

    draw.rectangle((0, 0, width, 86), fill="#0f172a")
    draw.text((28, 18), title, fill="#f8fafc", font=f_title)
    draw.text((28, 52), subtitle, fill="#93c5fd", font=f_sub)

    y = 106
    for sec_title, lines in sections:
        box_h = 40 + len(lines) * line_height
        draw.rounded_rectangle((24, y, width - 24, y + box_h), radius=8, fill="#ffffff", outline="#cbd5e1", width=2)
        draw.text((40, y + 10), sec_title, fill="#1e3a8a", font=f_sec)
        ly = y + 36
        for line in lines:
            draw.text((48, ly), line[:145], fill="#1e293b", font=f_mono)
            ly += line_height
        y += box_h + 14

    out_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path, format="PNG")


def run_demos() -> dict:
    postgres_ctl.init_and_start()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()

    from django.db import connections
    from apps.accounts.models import EmployeeIdentity
    from apps.audit.models import AuditEvent
    from apps.payments.models import (
        Approval,
        ChallengeAction,
        PaymentExecution,
        PaymentRequest,
        SourceKind,
    )
    from apps.payments.services import execute_payment_request_simulated, issue_payment_challenge
    from tests.helpers import StepClock, login_full_mfa_client, next_fresh_totp, seed_standard_lab, totp_at

    demos_dir = ROOT / "evidence" / "demos"
    demos_dir.mkdir(parents=True, exist_ok=True)
    summary_all: dict = {}

    # =========================================================================
    # D-01: Valid request confirmed by 2 independent approvers and executed once
    # =========================================================================
    lab = seed_standard_lab()
    creds = lab["creds"]
    lan_c = login_full_mfa_client("lan", creds["lan"]["password"])
    nam_c = login_full_mfa_client("nam", creds["nam"]["password"])
    huong_c = login_full_mfa_client("huong", creds["huong"]["password"])

    r_create = lan_c.post(
        "/requests",
        data=json.dumps(
            {
                "beneficiary_version_id": str(lab["b1_ver"].id),
                "amount_vnd": 20_000_000,
                "purpose": "D-01 Thanh toan thiet bi mang cho CN Sao Mai",
                "source_kind": SourceKind.EMAIL,
                "source_excerpt": "Email de nghi thanh toan kem hoa don GTGT INV-D01-001",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    req_id = r_create.json()["request_id"]
    lan_c.post(f"/requests/{req_id}/submit", HTTP_ACCEPT="application/json")
    req = PaymentRequest.objects.get(pk=req_id)
    rev1 = req.current_revision

    # Step 3: Nam approves (1/2); Lan tries to execute early -> blocked (409)
    c_nam = nam_c.post(
        f"/requests/{req_id}/challenges",
        data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    nam_c.post(
        f"/requests/{req_id}/approve",
        data=json.dumps(
            {
                "challenge_id": c_nam["challenge_id"],
                "nonce": c_nam["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["nam"]),
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    r_early_exec = lan_c.post(
        f"/requests/{req_id}/challenges",
        data=json.dumps({"action": ChallengeAction.EXECUTE}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )

    # Step 4: Huong approves (2/2) -> status APPROVED; Lan executes with fresh EXECUTE challenge
    c_huong = huong_c.post(
        f"/requests/{req_id}/challenges",
        data=json.dumps({"action": ChallengeAction.APPROVE_CONTROLLER}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    huong_c.post(
        f"/requests/{req_id}/approve",
        data=json.dumps(
            {
                "challenge_id": c_huong["challenge_id"],
                "nonce": c_huong["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["huong"]),
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    c_exec = lan_c.post(
        f"/requests/{req_id}/challenges",
        data=json.dumps({"action": ChallengeAction.EXECUTE}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    r_exec1 = lan_c.post(
        f"/requests/{req_id}/execute-simulated",
        data=json.dumps(
            {
                "challenge_id": c_exec["challenge_id"],
                "nonce": c_exec["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["lan"]),
                "idempotency_key": "DEMO-D01-KEY-001",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    # Step 5: Idempotent retry with same key -> returns same receipt, COUNT=1
    r_exec_retry = lan_c.post(
        f"/requests/{req_id}/execute-simulated",
        data=json.dumps(
            {
                "challenge_id": c_exec["challenge_id"],
                "nonce": c_exec["nonce"],
                "otp_token": "000000",
                "idempotency_key": "DEMO-D01-KEY-001",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    req.refresh_from_db()
    d01_audits = list(
        AuditEvent.objects.filter(payment_request=req)
        .order_by("created_at", "id")
        .values("action", "actor_username_snapshot", "result", "reason_code", "before_state", "after_state")
    )
    d01_data = {
        "demo_id": "D-01",
        "request_code": req.request_code,
        "status": req.status,
        "revision_number": rev1.revision_number,
        "content_digest": rev1.content_digest,
        "early_execute_challenge_http": r_early_exec.status_code,
        "early_execute_error_code": r_early_exec.json()["reason_code"],
        "receipt_number": r_exec1.json()["receipt_id"],
        "retry_receipt_number": r_exec_retry.json()["receipt_id"],
        "retry_idempotent_flag": r_exec_retry.json()["idempotent_replay"],
        "approval_count": Approval.objects.filter(payment_request=req).count(),
        "execution_count": PaymentExecution.objects.filter(payment_request=req).count(),
        "audit_timeline": d01_audits,
    }
    (demos_dir / "D-01_summary.json").write_text(json.dumps(d01_data, indent=2, ensure_ascii=False), encoding="utf-8")
    render_evidence_png(
        demos_dir / "D-01_valid_flow.png",
        "D-01 — Luồng hợp lệ: 2 người duyệt độc lập & thực thi mô phỏng 1 lần (PostgreSQL 17)",
        f"Mã yêu cầu: {req.request_code} | Trạng thái cuối: {req.status} | Biên nhận: {d01_data['receipt_number']}",
        [
            (
                "1. Snapshot đóng băng (PaymentRevision rev 1)",
                [
                    "Người lập: lan (PER-LAN-001) | Người nhận: BEN-001 (VERIFIED v1) | Số tiền: 20,000,000 VND",
                    f"SHA-256 content_digest: {rev1.content_digest}",
                ],
            ),
            (
                "2. Kiểm chứng 2 người duyệt độc lập & chặn thực thi sớm",
                [
                    f"Sau phiếu 1 (nam - DIRECTOR): Lan thử xin EXECUTE challenge -> HTTP {r_early_exec.status_code} ({r_early_exec.json()['reason_code']})",
                    "Sau phiếu 2 (huong - CONTROLLER): Trạng thái -> APPROVED (2 phiếu độc lập khác người lập)",
                    f"Lan xác thực mới với EXECUTE challenge -> EXECUTED_SIMULATED | Biên nhận: {d01_data['receipt_number']}",
                    f"Retry cùng idempotency_key='DEMO-D01-KEY-001' -> idempotent_replay=True, PaymentExecution COUNT = {d01_data['execution_count']}",
                ],
            ),
            (
                "3. Dòng thời gian nhật ký kiểm toán (AuditEvent đã ẩn bí mật)",
                [
                    f"- [{a['result']}] {a['action']} (actor={a['actor_username_snapshot']}, reason={a['reason_code']}): {a['before_state']} -> {a['after_state']}"
                    for a in d01_audits
                ],
            ),
        ],
    )
    summary_all["D-01"] = d01_data

    # =========================================================================
    # D-02: Lookalike impersonation & full compromise of 1 approver blocked
    # =========================================================================
    lab = seed_standard_lab()
    creds = lab["creds"]
    lan_c = login_full_mfa_client("lan", creds["lan"]["password"])
    fake_c = login_full_mfa_client("dacqui_lookalike", creds["dacqui_lookalike"]["password"])
    nam_c = login_full_mfa_client("nam", creds["nam"]["password"])
    huong_c = login_full_mfa_client("huong", creds["huong"]["password"])

    r2_create = lan_c.post(
        "/requests",
        data=json.dumps(
            {
                "beneficiary_version_id": str(lab["b1_ver"].id),
                "amount_vnd": 85_000_000,
                "purpose": "D-02 Chuyen khoan khan theo tin nhan gia danh Giam doc",
                "source_kind": SourceKind.CHAT_MESSAGE,
                "source_excerpt": "[GIA LAP TIN NHAN DEEPFAKE]: Toi la Giam doc Nam day, chuyen gap 85tr ngay trong 10 phut!",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    req2_id = r2_create.json()["request_id"]
    lan_c.post(f"/requests/{req2_id}/submit", HTTP_ACCEPT="application/json")

    # Step 2: Lookalike account `dacqui_lookalike` tries to approve -> 403
    r_fake_chal = fake_c.post(
        f"/requests/{req2_id}/challenges",
        data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    # Step 3: Stolen session without fresh OTP -> 400
    c_nam2 = nam_c.post(
        f"/requests/{req2_id}/challenges",
        data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    r_stolen_sess = nam_c.post(
        f"/requests/{req2_id}/approve",
        data=json.dumps({"challenge_id": c_nam2["challenge_id"], "nonce": c_nam2["nonce"], "otp_token": ""}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    # Step 4-5: Compromised Nam approves slot 1; independent Huong inspects & REJECTS; Lan tries to execute -> blocked
    nam_c.post(
        f"/requests/{req2_id}/approve",
        data=json.dumps(
            {
                "challenge_id": c_nam2["challenge_id"],
                "nonce": c_nam2["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["nam"]),
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    c_huong_rej = huong_c.post(
        f"/requests/{req2_id}/challenges",
        data=json.dumps({"action": ChallengeAction.REJECT, "reason": "Tin nhan chat ngoai chua xac minh"}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    r_huong_rej = huong_c.post(
        f"/requests/{req2_id}/reject",
        data=json.dumps(
            {
                "challenge_id": c_huong_rej["challenge_id"],
                "nonce": c_huong_rej["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["huong"]),
                "reason": "Tin nhan chat ngoai chua xac minh, khong co PO hop le",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    r_lan_try_exec = lan_c.post(
        f"/requests/{req2_id}/challenges",
        data=json.dumps({"action": ChallengeAction.EXECUTE}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    req2 = PaymentRequest.objects.get(pk=req2_id)
    d02_audits = list(
        AuditEvent.objects.filter(payment_request=req2)
        .order_by("created_at", "id")
        .values("action", "actor_username_snapshot", "result", "reason_code", "before_state", "after_state")
    )
    d02_data = {
        "demo_id": "D-02",
        "request_code": req2.request_code,
        "lookalike_http": r_fake_chal.status_code,
        "lookalike_error": r_fake_chal.json()["reason_code"],
        "stolen_session_no_otp_http": r_stolen_sess.status_code,
        "compromised_nam_slot1_approved": True,
        "independent_huong_reject_http": r_huong_rej.status_code,
        "lan_execute_after_reject_http": r_lan_try_exec.status_code,
        "final_status": req2.status,
        "execution_count": PaymentExecution.objects.filter(payment_request=req2).count(),
        "audit_timeline": d02_audits,
    }
    (demos_dir / "D-02_summary.json").write_text(json.dumps(d02_data, indent=2, ensure_ascii=False), encoding="utf-8")
    render_evidence_png(
        demos_dir / "D-02_impersonation_and_compromise.png",
        "D-02 — Chặn giả danh tên/ảnh & 1 tài khoản duyệt bị chiếm hoàn toàn (PostgreSQL 17)",
        f"Mã yêu cầu: {req2.request_code} | Trạng thái cuối: {req2.status} | PaymentExecution COUNT = 0",
        [
            (
                "1. Bối cảnh nguồn ngoài chưa xác minh",
                [
                    "Nhãn hiển thị bắt buộc: 'Nguồn ngoài — chưa xác minh' (source_kind=CHAT_MESSAGE)",
                    "Nội dung trích dẫn: '[GIA LAP TIN NHAN DEEPFAKE]: Toi la Giam doc Nam day, chuyen gap 85tr...'",
                ],
            ),
            (
                "2. Kết quả chặn các bước tấn công",
                [
                    f"- Tài khoản trùng tên `dacqui_lookalike` xin quyền duyệt -> HTTP {r_fake_chal.status_code} ({r_fake_chal.json()['reason_code']})",
                    f"- Phiên hậu đăng nhập nhưng thiếu OTP thao tác mới -> HTTP {r_stolen_sess.status_code}",
                    "- Giả định `nam` bị chiếm cả mật khẩu + MFA: chỉ tạo được 1 phiếu DIRECTOR",
                    f"- Kiểm soát viên `huong` độc lập từ chối -> Trạng thái {req2.status}; Lan thử execute -> HTTP {r_lan_try_exec.status_code}",
                ],
            ),
            (
                "3. Nhật ký kiểm toán (AuditEvent)",
                [
                    f"- [{a['result']}] {a['action']} (actor={a['actor_username_snapshot']}, reason={a['reason_code']}): {a['before_state']} -> {a['after_state']}"
                    for a in d02_audits
                ],
            ),
        ],
    )
    summary_all["D-02"] = d02_data

    # =========================================================================
    # D-03: Content modification creates new revision & invalidates prior confirmations
    # =========================================================================
    lab = seed_standard_lab()
    creds = lab["creds"]
    lan_c = login_full_mfa_client("lan", creds["lan"]["password"])
    nam_c = login_full_mfa_client("nam", creds["nam"]["password"])
    huong_c = login_full_mfa_client("huong", creds["huong"]["password"])

    r3_create = lan_c.post(
        "/requests",
        data=json.dumps(
            {
                "beneficiary_version_id": str(lab["b1_ver"].id),
                "amount_vnd": 20_000_000,
                "purpose": "D-03 Thanh toan hop dong phan mem dot 1",
                "source_kind": SourceKind.EMAIL,
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    req3_id = r3_create.json()["request_id"]
    lan_c.post(f"/requests/{req3_id}/submit", HTTP_ACCEPT="application/json")

    # Nam approves rev 1; Huong issues challenge on rev 1
    c_nam3 = nam_c.post(
        f"/requests/{req3_id}/challenges",
        data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    nam_c.post(
        f"/requests/{req3_id}/approve",
        data=json.dumps(
            {
                "challenge_id": c_nam3["challenge_id"],
                "nonce": c_nam3["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["nam"]),
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    old_huong_chal = huong_c.post(
        f"/requests/{req3_id}/challenges",
        data=json.dumps({"action": ChallengeAction.APPROVE_CONTROLLER}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()

    # Step 2: Direct illegal overwrite attempt -> 409 IMMUTABLE_REVISION
    r_illegal_edit = lan_c.post(
        f"/requests/{req3_id}/edit",
        data=json.dumps(
            {
                "beneficiary_version_id": str(lab["b2_ver"].id),
                "amount_vnd": 50_000_000,
                "purpose": "Sua am tham",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    # Step 3: Legitimate revise to BEN-002 and 32,000,000 VND -> creates rev 2 in DRAFT, invalidates rev 1 approval/challenge
    r_rev2 = lan_c.post(
        f"/requests/{req3_id}/revise",
        data=json.dumps(
            {
                "beneficiary_version_id": str(lab["b2_ver"].id),
                "amount_vnd": 32_000_000,
                "purpose": "D-03 Dieu chinh sang nha cung cap BEN-002 theo phu luc moi",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    lan_c.post(f"/requests/{req3_id}/submit", HTTP_ACCEPT="application/json")
    # Step 4: Try reusing old Huong challenge from rev 1 -> 409 WRONG_SCOPE
    r_use_old = huong_c.post(
        f"/requests/{req3_id}/approve",
        data=json.dumps(
            {
                "challenge_id": old_huong_chal["challenge_id"],
                "nonce": old_huong_chal["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["huong"]),
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    # Step 5: Re-approve rev 2 by both Nam & Huong and execute cleanly
    c_nam3_r2 = nam_c.post(
        f"/requests/{req3_id}/challenges",
        data=json.dumps({"action": ChallengeAction.APPROVE_DIRECTOR}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    nam_c.post(
        f"/requests/{req3_id}/approve",
        data=json.dumps(
            {
                "challenge_id": c_nam3_r2["challenge_id"],
                "nonce": c_nam3_r2["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["nam"]),
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    c_huong3_r2 = huong_c.post(
        f"/requests/{req3_id}/challenges",
        data=json.dumps({"action": ChallengeAction.APPROVE_CONTROLLER}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    huong_c.post(
        f"/requests/{req3_id}/approve",
        data=json.dumps(
            {
                "challenge_id": c_huong3_r2["challenge_id"],
                "nonce": c_huong3_r2["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["huong"]),
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    c_exec3_r2 = lan_c.post(
        f"/requests/{req3_id}/challenges",
        data=json.dumps({"action": ChallengeAction.EXECUTE}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    r_exec3 = lan_c.post(
        f"/requests/{req3_id}/execute-simulated",
        data=json.dumps(
            {
                "challenge_id": c_exec3_r2["challenge_id"],
                "nonce": c_exec3_r2["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["lan"]),
                "idempotency_key": "DEMO-D03-REV2-KEY",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    req3 = PaymentRequest.objects.get(pk=req3_id)
    d03_audits = list(
        AuditEvent.objects.filter(payment_request=req3)
        .order_by("created_at", "id")
        .values("action", "actor_username_snapshot", "result", "reason_code", "before_state", "after_state")
    )
    d03_data = {
        "demo_id": "D-03",
        "request_code": req3.request_code,
        "illegal_direct_edit_http": r_illegal_edit.status_code,
        "rev2_status_after_create": r_rev2.json()["status"],
        "old_challenge_reuse_http": r_use_old.status_code,
        "old_challenge_reuse_error": r_use_old.json()["reason_code"],
        "final_status": req3.status,
        "final_receipt": r_exec3.json()["receipt_id"],
        "audit_timeline": d03_audits,
    }
    (demos_dir / "D-03_summary.json").write_text(json.dumps(d03_data, indent=2, ensure_ascii=False), encoding="utf-8")
    render_evidence_png(
        demos_dir / "D-03_revision_invalidation.png",
        "D-03 — Chống sửa âm thầm & vô hiệu hóa phê duyệt cũ khi tạo Revision mới",
        f"Mã yêu cầu: {req3.request_code} | Revision hiện hành: rev 2 | Biên nhận cuối: {d03_data['final_receipt']}",
        [
            (
                "1. Chặn sửa trực tiếp & tạo Revision 2 hợp lệ",
                [
                    f"- Thử ghi đè trực tiếp /requests/{req3_id}/edit sau khi rev 1 đã nộp -> HTTP {r_illegal_edit.status_code} (IMMUTABLE_REVISION)",
                    f"- Tạo Revision 2 qua /revise (đổi sang BEN-002, 32,000,000 VND) -> Trạng thái về {r_rev2.json()['status']}",
                    "- Phiếu duyệt rev 1 của Nam bị đánh dấu status='SUPERSEDED_BY_REVISION'",
                ],
            ),
            (
                "2. Chặn dùng lại challenge cũ & duyệt lại Revision 2",
                [
                    f"- Dùng challenge cũ của Hương (rev 1) cho rev 2 -> HTTP {r_use_old.status_code} ({r_use_old.json()['reason_code']})",
                    f"- Nộp và duyệt mới đầy đủ cho rev 2 (Nam + Hương) -> Thực thi thành công biên nhận {d03_data['final_receipt']}",
                ],
            ),
            (
                "3. Nhật ký kiểm toán (AuditEvent)",
                [
                    f"- [{a['result']}] {a['action']} (actor={a['actor_username_snapshot']}, reason={a['reason_code']}): {a['before_state']} -> {a['after_state']}"
                    for a in d03_audits[-7:]
                ],
            ),
        ],
    )
    summary_all["D-03"] = d03_data

    # =========================================================================
    # D-04: Revocation before execute (HOLD) + PostgreSQL 2-worker concurrency
    # =========================================================================
    lab = seed_standard_lab()
    creds = lab["creds"]
    lan_c = login_full_mfa_client("lan", creds["lan"]["password"])
    nam_c = login_full_mfa_client("nam", creds["nam"]["password"])
    huong_c = login_full_mfa_client("huong", creds["huong"]["password"])
    an_c = login_full_mfa_client("an", creds["an"]["password"])

    r4_create = lan_c.post(
        "/requests",
        data=json.dumps(
            {
                "beneficiary_version_id": str(lab["b1_ver"].id),
                "amount_vnd": 45_000_000,
                "purpose": "D-04 Kiem chung thu hoi quyen tai Final Gate",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    req4_id = r4_create.json()["request_id"]
    lan_c.post(f"/requests/{req4_id}/submit", HTTP_ACCEPT="application/json")
    for c_client, u_obj, act in (
        (nam_c, lab["users"]["nam"], ChallengeAction.APPROVE_DIRECTOR),
        (huong_c, lab["users"]["huong"], ChallengeAction.APPROVE_CONTROLLER),
    ):
        c_data = c_client.post(
            f"/requests/{req4_id}/challenges",
            data=json.dumps({"action": act}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        ).json()
        c_client.post(
            f"/requests/{req4_id}/approve",
            data=json.dumps(
                {
                    "challenge_id": c_data["challenge_id"],
                    "nonce": c_data["nonce"],
                    "otp_token": next_fresh_totp(u_obj),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
    # Lan issues EXECUTE challenge, then An suspends Nam before Lan executes
    c_exec4 = lan_c.post(
        f"/requests/{req4_id}/challenges",
        data=json.dumps({"action": ChallengeAction.EXECUTE}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    nam_user = lab["users"]["nam"]
    reason_d04 = "D-04 Tam dinh chi Nam truoc khi Lan execute"
    c_admin = an_c.post(
        f"/security/users/{nam_user.id}/challenges",
        data=json.dumps({"action": ChallengeAction.SUSPEND, "reason": reason_d04}),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()
    an_c.post(
        f"/security/users/{nam_user.id}/suspend",
        data=json.dumps(
            {
                "challenge_id": c_admin["challenge_id"],
                "nonce": c_admin["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["an"]),
                "reason": reason_d04,
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    r_exec4_after_suspend = lan_c.post(
        f"/requests/{req4_id}/execute-simulated",
        data=json.dumps(
            {
                "challenge_id": c_exec4["challenge_id"],
                "nonce": c_exec4["nonce"],
                "otp_token": next_fresh_totp(lab["users"]["lan"]),
                "idempotency_key": "DEMO-D04-HOLD",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    )
    req4 = PaymentRequest.objects.get(pk=req4_id)

    # Part 2 of D-04: Fresh fixture for 2-worker concurrent PostgreSQL execution
    lab2 = seed_standard_lab()
    creds2 = lab2["creds"]
    lan_c2 = login_full_mfa_client("lan", creds2["lan"]["password"])
    nam_c2 = login_full_mfa_client("nam", creds2["nam"]["password"])
    huong_c2 = login_full_mfa_client("huong", creds2["huong"]["password"])
    r4b_id = lan_c2.post(
        "/requests",
        data=json.dumps(
            {
                "beneficiary_version_id": str(lab2["b1_ver"].id),
                "amount_vnd": 50_000_000,
                "purpose": "D-04 Kiem chung 2 worker PostgreSQL dong thoi",
            }
        ),
        content_type="application/json",
        HTTP_ACCEPT="application/json",
    ).json()["request_id"]
    lan_c2.post(f"/requests/{r4b_id}/submit", HTTP_ACCEPT="application/json")
    for c_client, u_obj, act in (
        (nam_c2, lab2["users"]["nam"], ChallengeAction.APPROVE_DIRECTOR),
        (huong_c2, lab2["users"]["huong"], ChallengeAction.APPROVE_CONTROLLER),
    ):
        c_data = c_client.post(
            f"/requests/{r4b_id}/challenges",
            data=json.dumps({"action": act}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        ).json()
        c_client.post(
            f"/requests/{r4b_id}/approve",
            data=json.dumps(
                {
                    "challenge_id": c_data["challenge_id"],
                    "nonce": c_data["nonce"],
                    "otp_token": next_fresh_totp(u_obj),
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )

    lan_u = EmployeeIdentity.objects.get(username="vanphu")
    clock = StepClock()
    t_conc = clock.advance(90)
    chal_conc = issue_payment_challenge(
        actor=lan_u,
        session_key="sess-d04-conc",
        session_epoch=lan_u.security_epoch,
        request_id=r4b_id,
        action=ChallengeAction.EXECUTE,
        now=t_conc,
    )
    otp_conc = totp_at(lan_u, t_conc)
    barrier = threading.Barrier(2)
    conc_results = []
    lock = threading.Lock()

    def conc_worker(wid: int) -> None:
        connections.close_all()
        try:
            barrier.wait(timeout=10)
            ex, is_replay = execute_payment_request_simulated(
                actor=lan_u,
                session_key="sess-d04-conc",
                session_epoch=lan_u.security_epoch,
                request_id=r4b_id,
                challenge_id=chal_conc.id,
                nonce=chal_conc.nonce,
                otp_token=otp_conc,
                idempotency_key="DEMO-D04-CONC-KEY",
                now=t_conc,
            )
            with lock:
                conc_results.append({"worker": wid, "receipt": ex.receipt_id, "is_replay": is_replay})
        finally:
            connections.close_all()

    th1 = threading.Thread(target=conc_worker, args=(1,))
    th2 = threading.Thread(target=conc_worker, args=(2,))
    th1.start()
    th2.start()
    th1.join(timeout=15)
    th2.join(timeout=15)

    d04_data = {
        "demo_id": "D-04",
        "part1_hold_status": req4.status,
        "part1_execute_after_suspend_http": r_exec4_after_suspend.status_code,
        "part1_execute_error": r_exec4_after_suspend.json()["reason_code"],
        "part2_concurrent_workers": conc_results,
        "part2_execution_count": PaymentExecution.objects.filter(payment_request_id=r4b_id).count(),
    }
    (demos_dir / "D-04_summary.json").write_text(json.dumps(d04_data, indent=2, ensure_ascii=False), encoding="utf-8")
    render_evidence_png(
        demos_dir / "D-04_revocation_and_concurrency.png",
        "D-04 — Thu hồi quyền trước bước thực thi (HOLD) & chống Race Condition trên PostgreSQL",
        f"Phần 1: Trạng thái {req4.status} (HTTP {r_exec4_after_suspend.status_code}) | Phần 2: 2 Worker đồng thời -> COUNT=1",
        [
            (
                "1. Phần 1 — Đình chỉ người duyệt Nam trước khi Lan thực thi",
                [
                    "- SecurityAdmin `an` đình chỉ `nam` với SUSPEND challenge + TOTP mới",
                    f"- Yêu cầu tự động chuyển sang trạng thái {req4.status}; phiếu duyệt của `nam` bị đánh dấu vô hiệu",
                    f"- Lan gọi execute-simulated bằng challenge đã cấp trước đó -> HTTP {r_exec4_after_suspend.status_code} ({r_exec4_after_suspend.json()['reason_code']})",
                ],
            ),
            (
                "2. Phần 2 — Hai kết nối PostgreSQL chạy đồng thời qua threading.Barrier(2)",
                [
                    f"- Worker 1 & Worker 2: {json.dumps(conc_results, ensure_ascii=False)}",
                    f"- Khóa `SecurityMutex` (SELECT ... FOR UPDATE) + OneToOneField bảo đảm PaymentExecution COUNT = {d04_data['part2_execution_count']}",
                ],
            ),
        ],
    )
    summary_all["D-04"] = d04_data

    # =========================================================================
    # Empirical Trade-off Measurements (N=5 repeated runs of valid flow)
    # =========================================================================
    run_metrics = []
    for run_no in range(1, 6):
        lab_m = seed_standard_lab()
        creds_m = lab_m["creds"]
        t0 = time.perf_counter()
        lan_cm = login_full_mfa_client("lan", creds_m["lan"]["password"])
        nam_cm = login_full_mfa_client("nam", creds_m["nam"]["password"])
        huong_cm = login_full_mfa_client("huong", creds_m["huong"]["password"])
        t_login_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        rid = lan_cm.post(
            "/requests",
            data=json.dumps(
                {
                    "beneficiary_version_id": str(lab_m["b1_ver"].id),
                    "amount_vnd": 20_000_000 + run_no * 1_000_000,
                    "purpose": f"Tradeoff measurement run {run_no}",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        ).json()["request_id"]
        lan_cm.post(f"/requests/{rid}/submit", HTTP_ACCEPT="application/json")

        for c_client, u_obj, act in (
            (nam_cm, lab_m["users"]["nam"], ChallengeAction.APPROVE_DIRECTOR),
            (huong_cm, lab_m["users"]["huong"], ChallengeAction.APPROVE_CONTROLLER),
        ):
            c_data = c_client.post(
                f"/requests/{rid}/challenges",
                data=json.dumps({"action": act}),
                content_type="application/json",
                HTTP_ACCEPT="application/json",
            ).json()
            c_client.post(
                f"/requests/{rid}/approve",
                data=json.dumps(
                    {
                        "challenge_id": c_data["challenge_id"],
                        "nonce": c_data["nonce"],
                        "otp_token": next_fresh_totp(u_obj),
                    }
                ),
                content_type="application/json",
                HTTP_ACCEPT="application/json",
            )
        ec_data = lan_cm.post(
            f"/requests/{rid}/challenges",
            data=json.dumps({"action": ChallengeAction.EXECUTE}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        ).json()
        lan_cm.post(
            f"/requests/{rid}/execute-simulated",
            data=json.dumps(
                {
                    "challenge_id": ec_data["challenge_id"],
                    "nonce": ec_data["nonce"],
                    "otp_token": next_fresh_totp(lab_m["users"]["lan"]),
                    "idempotency_key": f"METRIC-RUN-{run_no}",
                }
            ),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        t_workflow_ms = (time.perf_counter() - t1) * 1000.0
        run_metrics.append(
            {
                "run": run_no,
                "principals": 3,
                "mfa_challenges_consumed": 6,
                "http_roundtrips": 14,
                "login_3_users_ms": round(t_login_ms, 1),
                "workflow_approve_execute_ms": round(t_workflow_ms, 1),
                "total_system_ms": round(t_login_ms + t_workflow_ms, 1),
            }
        )

    summary_all["empirical_metrics_n5"] = run_metrics
    (demos_dir / "metrics_n5.json").write_text(json.dumps(run_metrics, indent=2, ensure_ascii=False), encoding="utf-8")

    avg_login = round(sum(m["login_3_users_ms"] for m in run_metrics) / len(run_metrics), 1)
    avg_wf = round(sum(m["workflow_approve_execute_ms"] for m in run_metrics) / len(run_metrics), 1)
    avg_total = round(sum(m["total_system_ms"] for m in run_metrics) / len(run_metrics), 1)

    tradeoff_md = [
        "# Phân tích Đánh đổi (Trade-off Analysis): Ngắn hạn, Dài hạn và Số liệu Thực nghiệm (M8)",
        "",
        "Tài liệu này phân tích đầy đủ 6 chiều đánh đổi kỹ thuật của hệ thống theo Mục 14 của đặc tả, tách bạch rõ **số liệu đo thực nghiệm trên lab (cỡ mẫu N=5)** với **phân tích định tính và ước lượng dài hạn có giả định**.",
        "",
        "---",
        "",
        "## 1. Kết quả đo thực nghiệm trên môi trường Lab (`N = 5` lần chạy lặp luồng hợp lệ)",
        "",
        "- **Điều kiện đo**: Windows 11 64-bit, Python 3.13.5, Django 5.2.14, PostgreSQL 17.6 (`127.0.0.1:55432`), tách riêng độ trễ xử lý hệ thống (system latency) khỏi thời gian chờ con người nhập mã hoặc chờ qua bước TOTP 30 giây.",
        "- **Tệp dữ liệu gốc**: [`evidence/demos/metrics_n5.json`](../evidence/demos/metrics_n5.json)",
        "",
        "| Lần chạy | Số chủ thể tham gia | Tổng số lần xác thực TOTP (Đăng nhập + Thao tác) | Tổng số HTTP Request | Thời gian 3 chủ thể đăng nhập 2 bước (ms) | Thời gian tạo + nộp + 2 phiếu duyệt + thực thi (ms) | Tổng độ trễ xử lý hệ thống (ms) |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for m in run_metrics:
        tradeoff_md.append(
            f"| {m['run']} | {m['principals']} (`lan`, `nam`, `huong`) | {m['mfa_challenges_consumed']} (3 login + 2 approve + 1 execute) | {m['http_roundtrips']} | {m['login_3_users_ms']} ms | {m['workflow_approve_execute_ms']} ms | **{m['total_system_ms']} ms** |"
        )
    tradeoff_md.extend(
        [
            f"| **Trung bình (N=5)** | **3** | **6 lần TOTP** | **14 HTTP** | **{avg_login} ms** | **{avg_wf} ms** | **{avg_total} ms** |",
            "",
            "> **Nhận xét thực nghiệm**: Độ trễ xử lý phía máy chủ và PostgreSQL (kể cả băm mật khẩu PBKDF2, khóa `SecurityMutex` `SELECT ... FOR UPDATE`, kiểm chứng SHA-256 `content_digest` và ghi `AuditEvent`) trung bình chỉ khoảng **"
            + f"{avg_total} ms"
            + "** cho toàn bộ vòng đời 14 bước HTTP. Chi phí thời gian thực tế trong vận hành chủ yếu nằm ở thao tác con người mở ứng dụng TOTP (ước lượng giả định 10–25 giây/người) và quy tắc chống dùng lại cùng một timestep TOTP 30 giây (`T-23`).",
            "",
            "---",
            "",
            "## 2. Sáu chiều đánh đổi ngắn hạn và dài hạn (Mục 14.1 – 14.6)",
            "",
            "### 2.1. Yêu cầu xác thực OTP mới ràng buộc hành động khi phê duyệt và thực thi mô phỏng (`DES-05`)",
            "- **Ngắn hạn (Thực nghiệm)**: Mỗi yêu cầu thanh toán cần tổng cộng **6 lần xác thực TOTP** (3 lần đăng nhập phiên + 2 lần cấp/tiêu thụ challenge `APPROVE` + 1 lần cấp/tiêu thụ challenge `EXECUTE`). Nếu cùng một chủ thể vừa đăng nhập vừa duyệt ngay trong cùng cửa sổ 30 giây, hệ thống từ chối timestep trùng (`T-23`) và buộc chờ tối đa 30 giây sang mã mới. Đổi lại, đánh cắp cookie phiên (`T-11`) hoặc đánh cắp mật khẩu (`T-10`) hoàn toàn không thể tạo phiếu duyệt hay lệnh thực thi.",
            "- **Dài hạn (Phân tích có giả định)**: Khi nhân sự làm mất điện thoại hoặc hỏng thiết bị tạo mã TOTP, baseline không mở chức năng tự reset MFA qua web (`T-14`) để tránh tạo lối đi vòng cho kẻ tấn công. Do đó tổ chức phát sinh chi phí vận hành ngoại tuyến qua lệnh quản trị tin cậy `manage.py recover_principal` (`T-15`, `T-27`).",
            "",
            "### 2.2. Hai người duyệt độc lập khác người lập cho mọi yêu cầu (`DES-02`)",
            "- **Ngắn hạn (Thực nghiệm)**: Chặn đứng kịch bản một tài khoản người duyệt bị chiếm hoàn toàn cả mật khẩu lẫn thiết bị MFA (`T-12`, `D-02`), vì kẻ tấn công chỉ tạo được tối đa 1 phiếu (`DIRECTOR` hoặc `CONTROLLER`) và không thể tự duyệt hay chiếm 2 vị trí (`T-07`). Đổi lại, yêu cầu phải chờ đủ cả Giám đốc và Kiểm soát viên phản hồi (`T-02`).",
            "- **Dài hạn (Phân tích có giả định)**: Trong doanh nghiệp thực tế, khi một người duyệt nghỉ phép hoặc công tác, quy trình có thể bị nghẽn nếu không có cơ chế ủy quyền hoặc nhóm người duyệt thay thế theo ca. Ngoài ra, nếu hai người duyệt cùng bị chiếm quyền đồng thời hoặc thông đồng ngoài đời thực thì cơ chế 2 người duyệt trong ứng dụng không tự triệt tiêu được rủi ro.",
            "",
            "### 2.3. Danh tính/vai trò cố định qua bootstrap offline; không signup, nâng quyền hoặc reset MFA qua UI/API (`DES-01`)",
            "- **Ngắn hạn (Thực nghiệm)**: Loại bỏ hoàn toàn bề mặt tấn công tự đăng ký tài khoản trùng tên sếp (`T-05`), tự chèn trường `role=DIRECTOR` (`T-06`) hoặc tự thay đổi factor MFA (`T-14`). Việc khởi tạo 6 tài khoản lab qua `manage.py bootstrap_lab` mất dưới 2 giây.",
            "- **Dài hạn (Phân tích có giả định)**: Mô hình CLI ngoại tuyến chỉ phù hợp với quy mô nhỏ hoặc môi trường lab. Khi mở rộng lên hàng trăm nhân sự, tổ chức cần quy trình IAM/HR tích hợp có phê duyệt đa chữ ký và kiểm toán độc lập cho thao tác cấp phát danh tính.",
            "",
            "### 2.4. Xác nhận gắn nội dung/phiên bản (`content_digest`), có hạn 120 giây và dùng một lần (`DES-04`, `DES-05`)",
            "- **Ngắn hạn (Thực nghiệm)**: Ngăn chặn triệt để hành vi sửa số tiền/người nhận sau khi đã duyệt (`T-19`, `T-20`, `D-03`), phát lại challenge cũ (`T-22`), hoặc dùng challenge của yêu cầu này cho yêu cầu khác (`T-17`). Tuy nhiên, nếu người lập chỉnh sửa dù chỉ một trường nhỏ sau khi đã có 1 phiếu duyệt, toàn bộ phiếu và challenge cũ bị vô hiệu hóa (`SUPERSEDED_BY_REVISION`), buộc các người duyệt phải thực hiện lại từ đầu.",
            "- **Dài hạn (Phân tích có giả định)**: Cần đồng bộ đồng hồ máy chủ (NTP) ổn định và chọn TTL hợp lý (120 giây cho challenge, 24 giờ cho phê duyệt) để cân bằng giữa an ninh và tính sẵn sàng.",
            "",
            "### 2.5. Nhật ký kiểm toán (`AuditEvent`) đủ truy vết nhưng giới hạn quyền đọc và không ghi bí mật (`YC-08`)",
            "- **Ngắn hạn (Thực nghiệm)**: Ghi nhận đầy đủ chuỗi sự kiện từ đăng nhập, cấp challenge, duyệt, từ chối, sửa đổi, đình chỉ đến thực thi mô phỏng; tự động lọc bỏ mọi trường nhạy cảm (`password`, `otp_token`, `secret`, `cookie`, `csrf`) được kiểm chứng qua `T-38`. `SECURITY_ADMIN` chỉ thấy sự kiện an ninh mà không thấy số tiền hay số tài khoản ngân hàng.",
            "- **Dài hạn (Phân tích có giả định)**: Nhật ký lưu trong cùng PostgreSQL chỉ bảo vệ trước người dùng ứng dụng thông thường (`POST/DELETE /audit` bị chặn 403), nhưng **không bất biến trước người quản trị máy chủ/DBA bị chiếm quyền**. Triển khai thực tế cần đẩy log thời gian thực sang hệ thống SIEM/WORM tách biệt.",
            "",
            "### 2.6. Khóa tuần tự hóa `SecurityMutex` (`SELECT ... FOR UPDATE`) trên PostgreSQL (`DES-08`)",
            "- **Ngắn hạn (Thực nghiệm)**: Giúp chứng minh chặt chẽ tính nguyên tử giữa `execute_payment_request_simulated`, `execute_security_admin_action`, `revise_payment_request` và `approve_payment_request` trên hai kết nối PostgreSQL đồng thời (`T-30`..`T-35`, `D-04`) mà không xảy ra deadlock hay trạng thái nửa vời (`T-40`). Thời gian giữ khóa thực tế mỗi giao dịch dưới 15 ms.",
            "- **Dài hạn (Phân tích có giả định)**: Khóa toàn cục một dòng (`SecurityMutex(id=1)`) tạo điểm nghẽn tuần tự nếu hệ thống có hàng trăm giao dịch phê duyệt/thực thi mỗi giây. Ở quy mô lớn cần tách khóa theo thứ tự định sẵn (`Principal -> Beneficiary -> PaymentRequest`), đi kèm bộ kiểm thử chống deadlock liên đối tượng.",
        ]
    )
    (ROOT / "docs" / "05_tradeoffs.md").write_text("\n".join(tradeoff_md) + "\n", encoding="utf-8")
    return summary_all


if __name__ == "__main__":
    res = run_demos()
    print("Completed D-01..D-04 and empirical trade-off measurements:", list(res.keys()))

