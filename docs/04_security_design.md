# 04 — Thiết Kế Cơ Chế Bảo Vệ, Ma Trận Quyền, Máy Trạng Thái Và Final Gate (M1)

## 1. Ma trận phân quyền phía Máy chủ (Server-Side Authorization Matrix)

Mọi kiểm tra quyền đều được thực thi trực tiếp trong tầng `services.py` và `views.py` dựa trên `request.user` đã qua xác thực đầy đủ (`auth_mfa_verified == True` và `session_security_epoch == user.security_epoch`). Ẩn nút trên giao diện HTML chỉ phục vụ trải nghiệm người dùng.

| Hành động / Endpoint | `REQUESTER` (Lan, Minh) | `DIRECTOR` (Nam) | `CONTROLLER` (Hương) | `SECURITY_ADMIN` (An) | `UNPRIVILEGED` (Tài khoản trùng tên) |
|---|---|---|---|---|---|
| **Tạo yêu cầu (`POST /requests`)** | **Có** (cho chính mình) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) |
| **Sửa nháp / Gửi duyệt (`POST /requests/{id}/submit`)** | **Có** (chỉ khi `requester == actor` và trạng thái `DRAFT`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) |
| **Tạo revision mới (`POST /requests/{id}/revise`)** | **Có** (chỉ của mình, trước trạng thái cuối; nếu ở `HOLD` thì nguyên nhân sự cố phải đã được khắc phục) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) |
| **Hủy yêu cầu (`POST /requests/{id}/cancel`)** | **Có** (chỉ của mình, khi chưa ở trạng thái cuối và chưa quá hạn) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) |
| **Xem chi tiết yêu cầu / Biên nhận (`GET /requests/{id}`, `/receipt`)** | **Chỉ của mình** (gọi ID của người khác bị từ chối `403 FORBIDDEN`) | **Có** (trong phạm vi công ty giả lập) | **Có** (trong phạm vi công ty giả lập) | **Chỉ xem metadata sự cố** (không xem biên nhận tài chính) | Không (`403 FORBIDDEN`) |
| **Xin Challenge Thanh toán (`POST /requests/{id}/challenges`)** | **Chỉ loại `EXECUTE`** (khi là chủ yêu cầu & yêu cầu đã `APPROVED`) | **Chỉ loại `APPROVE_DIRECTOR` hoặc `REJECT`** (khác `person_id` người lập) | **Chỉ loại `APPROVE_CONTROLLER` hoặc `REJECT`** (khác `person_id` người lập) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) |
| **Phê duyệt (`POST /requests/{id}/approve`)** | Không (`403 SELF_APPROVAL` / `FORBIDDEN`) | **Slot `DIRECTOR`** + Challenge `APPROVE_DIRECTOR` + OTP mới (`person_id != requester`) | **Slot `CONTROLLER`** + Challenge `APPROVE_CONTROLLER` + OTP mới (`person_id != requester` & `!= director`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) |
| **Từ chối (`POST /requests/{id}/reject`)** | Không (`403 FORBIDDEN`) | **Có** + Challenge `REJECT` + OTP mới + Lý do | **Có** + Challenge `REJECT` + OTP mới + Lý do | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) |
| **Thực thi mô phỏng (`POST /requests/{id}/execute-simulated`)** | **Có** (chỉ chủ yêu cầu, đủ 2 phiếu hợp lệ + Challenge `EXECUTE` + OTP mới + `Idempotency-Key`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) |
| **Xin Challenge An ninh & Đình chỉ / Thu hồi (`POST /security/users/{id}/...`)** | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | Không (`403 FORBIDDEN`) | **Có** + Challenge `SUSPEND` / `REVOKE_ALL` + OTP mới + Lý do | Không (`403 FORBIDDEN`) |
| **Xem Nhật ký (`GET /audit`)** | Timeline các yêu cầu của chính mình | Timeline các yêu cầu nghiệp vụ trong phạm vi | Timeline các yêu cầu nghiệp vụ trong phạm vi | Nhật ký an ninh toàn hệ thống (đã lọc dữ liệu giao dịch thừa) | Không (`403 FORBIDDEN`) |
| **Cấp role / Reset MFA / Sửa Beneficiary / Mở `/admin/`** | **Cấm qua UI/API** | **Cấm qua UI/API** | **Cấm qua UI/API** | **Cấm qua UI/API** | **Cấm qua UI/API** |

---

## 2. Máy trạng thái Yêu cầu thanh toán (State Machine & Invariants)

### 2.1. Bảng chuyển trạng thái chi tiết

| Trạng thái nguồn | Sự kiện / Thao tác | Điều kiện bắt buộc phía Server (dưới khóa `SecurityMutex(id=1)`) | Trạng thái đích | Tác động dữ liệu & Hiệu lực xác nhận |
|---|---|---|---|---|
| *(Khởi tạo)* | `create_draft` (`REQUESTER`) | `amount_vnd` nguyên dương trong miền; `beneficiary` và `beneficiary_version` ở trạng thái `VERIFIED`. | `DRAFT` (Revision 1) | Tạo `PaymentRequest` và `PaymentRevision(revision_number=1, is_frozen=False)`. |
| `DRAFT` | `submit_request` (`REQUESTER`) | Đúng chủ yêu cầu; `beneficiary.active_version == revision.beneficiary_version` và `VERIFIED`. | `PENDING_APPROVAL` (0/2 phiếu) | Chụp snapshot ngân hàng/tài khoản, tính `content_digest`, đặt `is_frozen=True`, `submitted_at=now`, `expires_at=now + 24h`. |
| `PENDING_APPROVAL` (0/2) | `approve_request` (`DIRECTOR` hoặc `CONTROLLER`) | Chưa hết hạn (`now < expires_at`); đúng `slot`; `approver.person_id != requester.person_id`; Challenge hợp lệ, chưa dùng, khớp `revision`/`digest`; mã TOTP mới hợp lệ. | `PENDING_APPROVAL` (1/2 phiếu) | Đánh dấu `challenge.consumed_at=now`; tạo 1 bản ghi `Approval(status='ACTIVE')`. |
| `PENDING_APPROVAL` (1/2) | `approve_request` (Slot còn lại) | Chưa hết hạn; đúng slot còn thiếu; `approver.person_id` khác cả `requester.person_id` và `existing_approver.person_id`; phiếu trước vẫn còn hợp lệ; Challenge + TOTP mới hợp lệ. | `APPROVED` (2/2 phiếu) | Tạo bản ghi `Approval` thứ hai; chuyển trạng thái hiển thị của request sang `APPROVED`. |
| `PENDING_APPROVAL` hoặc `APPROVED` | `reject_request` (`DIRECTOR` hoặc `CONTROLLER`) | Chưa ở trạng thái cuối; chưa hết hạn; `actor.person_id != requester.person_id`; Challenge `REJECT` + TOTP mới + có lý do từ chối. | `REJECTED` *(Trạng thái cuối)* | Tiêu thụ challenge; vô hiệu hóa các challenge đang mở của request; không thể duyệt hay thực thi tiếp. |
| `DRAFT`, `PENDING_APPROVAL`, `APPROVED`, `HOLD` | `cancel_request` (`REQUESTER`) | Đúng chủ yêu cầu (`actor.id == request.requester_id`); chưa ở trạng thái cuối; chưa quá hạn. | `CANCELLED` *(Trạng thái cuối)* | Vô hiệu hóa các challenge đang mở và các phiếu duyệt cũ; kết thúc vòng đời yêu cầu. |
| `PENDING_APPROVAL` hoặc `APPROVED` | Sự cố an ninh (`suspend`, `revoke_all`, đổi `role`, reset MFA, hoặc thu hồi/đổi version `Beneficiary`) | `requester` hoặc một `approver` có phiếu `ACTIVE` bị tăng `security_epoch`/đình chỉ/đổi role, hoặc `beneficiary` bị thu hồi/đổi version. | `HOLD` *(Chặn thực thi)* | Các phiếu của cá nhân gặp sự cố chuyển sang `INVALIDATED_BY_INCIDENT`; hủy các challenge mở liên quan; ghi rõ `hold_reason`. |
| `DRAFT`, `PENDING_APPROVAL`, `APPROVED`, `HOLD` | `revise_request` (`REQUESTER`) | Đúng chủ yêu cầu; chưa ở trạng thái cuối; nếu đang ở `HOLD` thì `requester` phải đang `is_active` và `beneficiary` được chọn cho bản mới phải `VERIFIED`. | `DRAFT` (Revision $N+1$) | Đánh dấu mọi `Approval` cũ sang `SUPERSEDED_BY_REVISION`; vô hiệu hóa mọi `ActionChallenge` cũ; tạo `PaymentRevision` mới với `revision_number = N + 1`. |
| `PENDING_APPROVAL`, `APPROVED`, `HOLD` | Quá thời hạn (`now >= expires_at`) | Phát hiện bởi kiểm tra giờ server UTC ngay trong bất kỳ thao tác mutation nào hoặc lệnh `expire_requests`. | `EXPIRED` *(Trạng thái cuối)* | Đánh dấu các phiếu `ACTIVE` sang `EXPIRED`; chặn hoàn toàn việc duyệt hoặc thực thi. |
| `APPROVED` | `execute_simulated` (`REQUESTER`) | Vượt qua toàn bộ **Final Gate** (xem mục 4 bên dưới) + Challenge `EXECUTE` + mã TOTP mới + `Idempotency-Key`. | `EXECUTED_SIMULATED` *(Trạng thái cuối)* | Tiêu thụ challenge; tạo duy nhất 1 `PaymentExecution`; ghi `AuditEvent` thành công trong cùng transaction. |

---

## 3. Thiết kế Ràng buộc Ngữ cảnh Xác nhận (`ActionChallenge` + TOTP)

### 3.1. Tại sao phải kết hợp `ActionChallenge` với mã TOTP?
Mã TOTP 6 chữ số theo chuẩn RFC 6238 chỉ phụ thuộc vào khóa bí mật của thiết bị (`TOTPDevice`) và thời gian hiện tại (cửa sổ 30 giây), **không** mang thông tin về số tiền, số tài khoản hay loại hành động. Nếu chỉ kiểm tra mã TOTP:
- Một mã TOTP vừa dùng để đăng nhập có thể bị tái sử dụng ngay trong cùng cửa sổ 30 giây.
- Một yêu cầu xác thực cho hành động A (hoặc yêu cầu thanh toán 2 triệu VND) có thể bị tráo sang hành động B (hoặc yêu cầu 200 triệu VND).

Do đó, hệ thống tách bạch rõ hai lớp:
1. **`TOTPDevice` (của `django-otp`)**: Xác minh người thực hiện đang nắm giữ yếu tố xác thực thứ hai tại timestep mới (`t > device.last_t`), chống dùng lại mã OTP trong cùng cửa sổ 30 giây (`T-23`, `T-34`).
2. **`ActionChallenge` (do máy chủ phát hành)**: Đóng vai trò "phiếu ủy quyền ngữ cảnh tạm thời" có thời hạn 120 giây và chỉ dùng 1 lần, khóa chặt:
   - **Ai được dùng**: `actor_id`, `actor_person_id`, `session_key_hash`, `device_id`, `actor_epoch`.
   - **Dùng cho hành động gì**: `action` (`APPROVE_DIRECTOR`, `APPROVE_CONTROLLER`, `REJECT`, `EXECUTE`, `SUSPEND`, `REVOKE_ALL`).
   - **Dùng trên nội dung nào**:
     - Với thanh toán: `payment_request_id`, `payment_revision_id`, `content_digest` (SHA-256 của bản chụp đã đóng băng), `beneficiary_version_id`.
     - Với quản trị an ninh: `target_user_id`, `target_user_epoch`, `reason_text` và `content_digest` của thao tác quản trị.

---

## 4. Đặc tả Thuật toán Final Gate và Tính Nguyên Tử (DES-08)

Mọi lệnh thực thi mô phỏng (`execute_payment_request`) bắt buộc đi qua trình tự nguyên tử dưới đây trên PostgreSQL:

```python
with transaction.atomic():
    # 1. Khóa tuần tự toàn cục để chống race giữa execute, revise, approve, reject, revoke
    acquire_security_mutex()  # SELECT id FROM common_securitymutex WHERE id = 1 FOR UPDATE

    # 2. Đọc lại (re-read) trạng thái mới nhất từ PostgreSQL
    actor = EmployeeIdentity.objects.select_for_update().get(pk=actor_id)
    req = PaymentRequest.objects.select_for_update().select_related(
        "current_revision", "requester"
    ).get(pk=request_id)
    rev = req.current_revision

    # 3. Kiểm tra Idempotency / Đã thực thi trước đó
    existing_exec = PaymentExecution.objects.filter(payment_request=req).first()
    if existing_exec is not None:
        if (
            existing_exec.executor_id == actor.id
            and existing_exec.idempotency_key == idempotency_key
            and existing_exec.payload_fingerprint == payload_fingerprint
        ):
            record_audit_event(..., result="SUCCESS", reason_code="IDEMPOTENT_REPLAY")
            return existing_exec, True  # Trả lại biên nhận cũ, không tạo giao dịch mới
        raise SecurityDomainError(ReasonCode.IDEMPOTENCY_CONFLICT, status_code=409)

    # 4. Kiểm tra quyền sở hữu và trạng thái hoạt động của REQUESTER
    if actor.role != Role.REQUESTER or req.requester_id != actor.id or req.requester_person_id != actor.person_id:
        raise SecurityDomainError(ReasonCode.FORBIDDEN, status_code=403)
    if not actor.is_active or actor.is_suspended or session_epoch != actor.security_epoch:
        raise SecurityDomainError(ReasonCode.PRINCIPAL_REVOKED, status_code=403)

    # 5. Kiểm tra trạng thái yêu cầu và thời hạn theo giờ UTC của server
    if req.status in TERMINAL_STATES:
        raise SecurityDomainError(ReasonCode.TERMINAL_STATE, status_code=409)
    if req.expires_at and now >= req.expires_at:
        mark_request_expired(req, now)
        raise SecurityDomainError(ReasonCode.CHALLENGE_EXPIRED, status_code=409)
    if req.status == RequestStatus.HOLD:
        raise SecurityDomainError(ReasonCode.PRINCIPAL_REVOKED, status_code=409)

    # 6. Kiểm tra tính toàn vẹn của Revision và Beneficiary hiện hành
    expected_digest = compute_revision_digest(rev)
    if not rev.is_frozen or rev.content_digest != expected_digest:
        raise SecurityDomainError(ReasonCode.SNAPSHOT_MISMATCH, status_code=409)
    beneficiary = Beneficiary.objects.select_for_update().get(pk=rev.beneficiary_id)
    ben_version = BeneficiaryVersion.objects.get(pk=rev.beneficiary_version_id)
    if (
        beneficiary.status != BeneficiaryStatus.VERIFIED
        or beneficiary.active_version_id != ben_version.id
        or ben_version.status != BeneficiaryStatus.VERIFIED
    ):
        move_request_to_hold(req, "Beneficiary invalid or changed")
        raise SecurityDomainError(ReasonCode.BENEFICIARY_INVALID, status_code=409)

    # 7. Kiểm tra đủ 2 phê duyệt độc lập còn hiệu lực (DIRECTOR + CONTROLLER)
    approvals = list(
        Approval.objects.select_related("approver")
        .filter(payment_revision=rev, status=ApprovalStatus.ACTIVE)
    )
    Validate:
      - Có đúng 1 phiếu slot DIRECTOR và 1 phiếu slot CONTROLLER
      - Cả 2 phiếu có expires_at > now
      - Cả 2 phiếu có content_digest == rev.content_digest và beneficiary_version_id == ben_version.id
      - director.person_id != controller.person_id
      - director.person_id != actor.person_id và controller.person_id != actor.person_id
      - Cả director và controller hiện tại vẫn is_active, không suspended, giữ đúng role (DIRECTOR / CONTROLLER)
      - director.security_epoch == director_approval.approver_epoch_at_signing
      - controller.security_epoch == controller_approval.approver_epoch_at_signing
      - actor.security_epoch == director_approval.requester_epoch_at_signing == controller_approval.requester_epoch_at_signing

    # 8. Kiểm tra ActionChallenge loại EXECUTE và mã TOTP mới
    challenge = validate_and_consume_challenge(
        challenge_id=challenge_id,
        nonce=nonce,
        actor=actor,
        session_key=session_key,
        expected_action=ChallengeAction.EXECUTE,
        payment_request=req,
        payment_revision=rev,
        expected_digest=rev.content_digest,
        expected_beneficiary_version_id=ben_version.id,
        otp_token=otp_token,
        now=now,
    )

    # 9. Ghi PaymentExecution, cập nhật trạng thái EXECUTED_SIMULATED và AuditEvent trong cùng transaction
    execution = PaymentExecution.objects.create(...)
    req.status = RequestStatus.EXECUTED_SIMULATED
    req.save(...)
    record_audit_event(..., result="SUCCESS", reason_code="EXECUTED_SIMULATED")
```

> **Lưu ý về xử lý lỗi và Throttle**: Khi lỗi thuộc về xác thực/nghiệp vụ thông thường (ví dụ nhập sai OTP, challenge hết hạn, thiếu phiếu duyệt), hàm dịch vụ cập nhật bộ đếm throttle (nếu là lỗi OTP), ghi `AuditEvent(result='DENIED')` và cho phép khối `transaction.atomic()` **commit** bản ghi từ chối/throttle đó trước khi trả phản hồi lỗi cho client. Ngược lại, nếu có lỗi cơ sở dữ liệu/hệ thống xảy ra trong bước 9 (sau khi tạo `PaymentExecution`), ngoại lệ không bị nuốt sẽ làm **rollback** toàn bộ bước 8 và bước 9, đảm bảo không bao giờ tồn tại trạng thái ghi một nửa (`T-40`).

