# 03 — Kiến Trúc Hệ Thống, Luồng Dữ Liệu, Ranh Giới Tin Cậy Và Mô Hình Dữ Liệu (M1)

## 1. Kiến trúc tổng thể hệ thống (YC-03)

Hệ thống **SecurePay Lab** được thiết kế theo kiến trúc **Modular Monolith** trên nền tảng **Python 3.12+ / Django 5.2 LTS** kết hợp cơ sở dữ liệu quan hệ **PostgreSQL 16/17**, triển khai phía sau tầng **Reverse Proxy TLS (Caddy / HTTPS Profile)** hoặc cổng loopback nội bộ (`127.0.0.1`) dành cho môi trường phát triển/kiểm thử.

### 1.1. Các phân hệ phần mềm chính
1. **`apps/common`**:
   - Quản lý thực thể khóa đồng bộ toàn cục `SecurityMutex(id=1)` và tiện ích ngữ cảnh giao dịch `locked_security_transaction()`.
   - Chuẩn hóa mã lỗi (`ReasonCode`), ngoại lệ nghiệp vụ (`SecurityDomainError`) và hàm băm `canonical_json_sha256()`.
2. **`apps/accounts`**:
   - Quản lý danh tính nhân viên (`EmployeeIdentity` kế thừa `AbstractUser`), `person_id`, vai trò (`role`), trạng thái hoạt động, `security_epoch`, và bộ đếm giới hạn thử sai mật khẩu/OTP (`failed_password_attempts`, `password_throttled_until`, `failed_otp_attempts`, `otp_throttled_until`).
   - Tích hợp `django-otp` (`TOTPDevice`) để xác thực đa yếu tố và kiểm soát chống dùng lại timestep (`last_t`).
   - Middleware `SecurityEpochSessionMiddleware` kiểm tra phiên tiền xác thực (`preauth`), phiên đầy đủ sau MFA, thời gian không hoạt động (30 phút), thời gian sống tối đa (8 giờ) và sự khớp nối `session_security_epoch == user.security_epoch`.
   - Cung cấp các thao tác quản trị an ninh bị giới hạn (`suspend_user`, `revoke_all_user_sessions`) và các lệnh CLI ngoại tuyến (`bootstrap_lab`, `recover_principal`).
3. **`apps/beneficiaries`**:
   - Quản lý danh mục người thụ hưởng (`Beneficiary`) và lịch sử phiên bản tài khoản ngân hàng bất biến (`BeneficiaryVersion` với trạng thái `PENDING`, `VERIFIED`, `REVOKED`).
   - Cung cấp công cụ vận hành ngoại tuyến (`manage_beneficiary`) để thêm/cập nhật phiên bản tài khoản hoặc thu hồi người thụ hưởng kèm kiểm tra ảnh hưởng tới các yêu cầu đang chờ.
4. **`apps/payments`**:
   - Quản lý vòng đời yêu cầu thanh toán (`PaymentRequest`), bản chụp phiên bản bất biến (`PaymentRevision`), thách thức xác thực gắn ngữ cảnh (`ActionChallenge`), phiếu phê duyệt (`Approval`) và biên nhận thực thi mô phỏng (`PaymentExecution`).
   - Thực thi **Final Gate** nguyên tử dưới khóa `SecurityMutex(id=1)` trước khi tạo bản ghi `PaymentExecution`.
5. **`apps/audit`**:
   - Ghi nhận mọi sự kiện thành công và từ chối quan trọng vào bảng `AuditEvent` với `reason_code`, `before_state`, `after_state`, `correlation_id` và `metadata` đã được lọc sạch bí mật.
   - Cung cấp giao diện truy vấn nhật ký phân quyền chặt theo vai trò (`REQUESTER` xem timeline của mình; `DIRECTOR`/`CONTROLLER` xem timeline nghiệp vụ; `SECURITY_ADMIN` xem nhật ký an ninh đã ẩn chi tiết nội dung giao dịch không cần thiết).

---

## 2. Luồng dữ liệu (DFD) và Ranh giới tin cậy (Trust Boundaries)

Hệ thống thiết lập **4 Ranh giới tin cậy (Trust Boundaries)** rõ rệt:

| Ranh giới | Tên ranh giới | Dữ liệu đi qua | Nơi kiểm tra & Biện pháp kiểm soát |
|---|---|---|---|
| **TB-01** | **Kênh liên lạc bên ngoài $\rightarrow$ Người lập yêu cầu (`REQUESTER`)** | Tin nhắn văn bản/Zalo/Email/Giọng nói yêu cầu chuyển tiền, tên/ảnh người gửi, số tài khoản mới. | **Không tin cậy**: Chỉ được nhập vào trường `source_kind` và `source_excerpt` (tối đa 2.000 ký tự). Server validate độ dài, escape toàn bộ ký tự HTML/script và hiển thị nhãn cảnh báo `"Nguồn ngoài — chưa xác minh"`. Không thể nhập số tài khoản tự do ngoài danh mục `BeneficiaryVersion` (`VERIFIED`). |
| **TB-02** | **Trình duyệt người dùng / HTTP Client $\rightarrow$ Tầng Web Application (Django)** | Cookie phiên, CSRF token, thông tin đăng nhập, mã TOTP, form tạo/sửa yêu cầu, lệnh xin challenge, lệnh duyệt/từ chối/thực thi/đình chỉ, `Idempotency-Key`. | **Không tin cậy hoàn toàn phía Client**: Kiểm tra TLS (ở profile HTTPS), kiểm tra `CsrfViewMiddleware`, xác thực phiên + `security_epoch` tại Middleware và kiểm tra lại trong Service dưới khóa `SecurityMutex(id=1)`. Bỏ qua/từ chối mọi trường authority do client tự khai (`role`, `verified`, `status`, `approver_id`). |
| **TB-03** | **Tầng Web Application $\rightarrow$ Cơ sở dữ liệu PostgreSQL (Mạng nội bộ)** | Các truy vấn đọc/ghi ORM, khóa `SELECT ... FOR UPDATE` trên `SecurityMutex(id=1)`, giao dịch `transaction.atomic()`, ràng buộc toàn vẹn (`CheckConstraint`, `UniqueConstraint`, `OneToOneField`). | **Ranh giới thực thi nguyên tử**: Chỉ ứng dụng Web kết nối tới PostgreSQL qua cổng nội bộ; DB không mở ra Internet. Mọi bất biến đa bảng (2 `person_id` độc lập, khớp `content_digest`, khớp `security_epoch`, chưa hết hạn) được kiểm tra sau khi giữ khóa `SecurityMutex(id=1)`. |
| **TB-04** | **Quản trị vận hành ngoại tuyến (Trusted CLI) $\rightarrow$ Hệ thống / PostgreSQL** | Lệnh khởi tạo danh tính ban đầu (`bootstrap_lab`), xác minh/thu hồi người thụ hưởng (`manage_beneficiary`), khôi phục tài khoản & đặt lại MFA (`recover_principal`). | **Ranh giới quản trị tin cậy có kiểm toán**: Không mở qua Web UI/API hay `/admin/`. Khi chạy qua CLI vẫn phải đi qua `SecurityMutex(id=1)`, tăng `security_epoch`, chuyển các yêu cầu bị ảnh hưởng sang `HOLD` và ghi `AuditEvent`. |

---

## 3. Thiết kế Mô hình dữ liệu tối thiểu (ERD & Schema Specification)

### 3.1. Bảng `accounts_employeeidentity` (Custom User Model)
- `id`: `UUIDField(primary_key=True, default=uuid4)`
- `username`: `CharField(max_length=150, unique=True)`
- `person_id`: `CharField(max_length=64, unique=True)` — Mã định danh cá nhân thực đã xác minh nhân thân ngoại tuyến (ví dụ: `PER-LAN-001`, `PER-NAM-002`, `PER-HUONG-003`). Hai tài khoản có cùng `person_id` không bao giờ tồn tại ở baseline, và mọi kiểm tra tách nhiệm vụ đều so sánh cả `user.id` lẫn `person_id`.
- `display_name`: `CharField(max_length=150)` — Tên hiển thị (không dùng để phân quyền).
- `role`: `CharField(choices=['REQUESTER', 'DIRECTOR', 'CONTROLLER', 'SECURITY_ADMIN', 'UNPRIVILEGED'])`
- `is_active`: `BooleanField(default=True)`
- `is_suspended`: `BooleanField(default=False)`
- `suspension_reason`: `CharField(max_length=500, blank=True)`
- `identity_verified_at`: `DateTimeField(null=True, blank=True)`
- `security_epoch`: `PositiveIntegerField(default=1)` — Tăng đơn điệu mỗi khi đình chỉ, thu hồi phiên, đổi vai trò hoặc đặt lại MFA.
- `failed_password_attempts`: `PositiveIntegerField(default=0)`
- `password_throttled_until`: `DateTimeField(null=True, blank=True)`
- `failed_otp_attempts`: `PositiveIntegerField(default=0)`
- `otp_throttled_until`: `DateTimeField(null=True, blank=True)`

### 3.2. Bảng `otp_totp_totpdevice` (Thư viện `django-otp`)
- Liên kết tới `EmployeeIdentity`, lưu `key` (hex secret trong DB cục bộ), `step=30`, `digits=6`, `confirmed=True`, `last_t` (timestep cuối cùng đã chấp nhận để chống dùng lại cùng mã OTP trong cửa sổ 30 giây), cùng cơ chế throttling của thiết bị.

### 3.3. Bảng `beneficiaries_beneficiary` & `beneficiaries_beneficiaryversion`
- **`Beneficiary`**:
  - `id`: `UUIDField(primary_key=True)`
  - `code`: `CharField(max_length=50, unique=True)` (ví dụ: `BEN-001`, `BEN-002`, `BEN-003`)
  - `status`: `CharField(choices=['PENDING', 'VERIFIED', 'REVOKED'])`
  - `active_version`: `ForeignKey('BeneficiaryVersion', null=True, blank=True, on_delete=PROTECT, related_name='+')`
  - `registry_epoch`: `PositiveIntegerField(default=1)`
- **`BeneficiaryVersion`** (Bất biến sau khi tạo):
  - `id`: `UUIDField(primary_key=True)`
  - `beneficiary`: `ForeignKey(Beneficiary, on_delete=PROTECT, related_name='versions')`
  - `version_number`: `PositiveIntegerField()`
  - `vendor_name`: `CharField(max_length=200)`
  - `bank_name`: `CharField(max_length=150)`
  - `account_number`: `CharField(max_length=64)`
  - `verification_reference`: `CharField(max_length=300)` — Tham chiếu hợp đồng/biên bản đối chiếu độc lập.
  - `status`: `CharField(choices=['PENDING', 'VERIFIED', 'REVOKED'])`
  - `verified_by_summary`: `CharField(max_length=200, blank=True)`
  - `created_at`: `DateTimeField(auto_now_add=True)`
  - **Ràng buộc DB**: `UniqueConstraint(fields=['beneficiary', 'version_number'])`.

### 3.4. Bảng `payments_paymentrequest` & `payments_paymentrevision`
- **`PaymentRequest`**:
  - `id`: `UUIDField(primary_key=True)`
  - `request_code`: `CharField(max_length=32, unique=True)` (ví dụ: `REQ-2026-0001`)
  - `requester`: `ForeignKey(EmployeeIdentity, on_delete=PROTECT, related_name='payment_requests')`
  - `requester_person_id`: `CharField(max_length=64)`
  - `current_revision`: `ForeignKey('PaymentRevision', null=True, blank=True, on_delete=PROTECT, related_name='+')`
  - `status`: `CharField(choices=['DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'HOLD', 'REJECTED', 'CANCELLED', 'EXPIRED', 'EXECUTED_SIMULATED'])`
  - `hold_reason`: `CharField(max_length=500, blank=True)`
  - `submitted_at`: `DateTimeField(null=True, blank=True)`
  - `expires_at`: `DateTimeField(null=True, blank=True)` — Mặc định `submitted_at + 24 giờ` cho revision hiện hành.
  - `created_at`, `updated_at`: `DateTimeField`
- **`PaymentRevision`** (Đóng băng khi submit):
  - `id`: `UUIDField(primary_key=True)`
  - `payment_request`: `ForeignKey(PaymentRequest, on_delete=PROTECT, related_name='revisions')`
  - `revision_number`: `PositiveIntegerField()`
  - `amount_vnd`: `BigIntegerField()` — Số nguyên VND (`1 <= amount_vnd <= 1_000_000_000_000`).
  - `currency`: `CharField(max_length=8, default='VND')`
  - `beneficiary`: `ForeignKey(Beneficiary, on_delete=PROTECT)`
  - `beneficiary_version`: `ForeignKey(BeneficiaryVersion, on_delete=PROTECT)`
  - `beneficiary_name_snapshot`: `CharField(max_length=200)`
  - `bank_name_snapshot`: `CharField(max_length=150)`
  - `account_number_snapshot`: `CharField(max_length=64)`
  - `purpose`: `CharField(max_length=500)`
  - `source_kind`: `CharField(max_length=50)` (`INTERNAL_INVOICE`, `CHAT_MESSAGE`, `EMAIL`, `PHONE_CALL`, `OTHER`)
  - `source_excerpt`: `CharField(max_length=2000, blank=True)` — Văn bản trích dẫn nguồn ngoài chưa xác minh.
  - `content_digest`: `CharField(max_length=64)` — SHA-256 hex digest của canonical JSON.
  - `is_frozen`: `BooleanField(default=False)`
  - `frozen_at`: `DateTimeField(null=True, blank=True)`
  - **Ràng buộc DB**:
    - `UniqueConstraint(fields=['payment_request', 'revision_number'])`
    - `CheckConstraint(condition=Q(amount_vnd__gt=0) & Q(amount_vnd__lte=1000000000000))`

### 3.5. Bảng `payments_actionchallenge`
- `id`: `UUIDField(primary_key=True)`
- `nonce`: `CharField(max_length=64, unique=True)` — Sinh bằng `secrets.token_urlsafe(32)`.
- `actor`: `ForeignKey(EmployeeIdentity, on_delete=PROTECT, related_name='challenges')`
- `actor_person_id`: `CharField(max_length=64)`
- `session_key_hash`: `CharField(max_length=64)` — SHA-256 của `session.session_key` (không lưu raw session key).
- `device_id`: `IntegerField()` — ID của `TOTPDevice` đã confirmed.
- `actor_epoch`: `PositiveIntegerField()`
- `action`: `CharField(choices=['APPROVE_DIRECTOR', 'APPROVE_CONTROLLER', 'REJECT', 'EXECUTE', 'SUSPEND', 'REVOKE_ALL'])`
- `target_type`: `CharField(choices=['PAYMENT_REQUEST', 'EMPLOYEE_IDENTITY'])`
- `payment_request`: `ForeignKey(PaymentRequest, null=True, blank=True, on_delete=PROTECT)`
- `payment_revision`: `ForeignKey(PaymentRevision, null=True, blank=True, on_delete=PROTECT)`
- `content_digest`: `CharField(max_length=64)` — Với thanh toán là `revision.content_digest`; với quản trị an ninh là `action_digest` của thao tác/target/lý do.
- `beneficiary_version`: `ForeignKey(BeneficiaryVersion, null=True, blank=True, on_delete=PROTECT)`
- `target_user`: `ForeignKey(EmployeeIdentity, null=True, blank=True, on_delete=PROTECT, related_name='targeted_challenges')`
- `target_user_epoch`: `PositiveIntegerField(null=True, blank=True)`
- `reason_text`: `CharField(max_length=500, blank=True)`
- `created_at`: `DateTimeField()`
- `expires_at`: `DateTimeField()` — Mặc định `created_at + 120 giây`.
- `consumed_at`: `DateTimeField(null=True, blank=True)`
- `invalidated_at`: `DateTimeField(null=True, blank=True)`

### 3.6. Bảng `payments_approval`
- `id`: `UUIDField(primary_key=True)`
- `payment_request`: `ForeignKey(PaymentRequest, on_delete=PROTECT, related_name='approvals')`
- `payment_revision`: `ForeignKey(PaymentRevision, on_delete=PROTECT, related_name='approvals')`
- `approver`: `ForeignKey(EmployeeIdentity, on_delete=PROTECT, related_name='given_approvals')`
- `approver_person_id`: `CharField(max_length=64)`
- `slot`: `CharField(choices=['DIRECTOR', 'CONTROLLER'])`
- `content_digest`: `CharField(max_length=64)`
- `beneficiary_version`: `ForeignKey(BeneficiaryVersion, on_delete=PROTECT)`
- `approver_epoch_at_signing`: `PositiveIntegerField()`
- `requester_epoch_at_signing`: `PositiveIntegerField()`
- `challenge`: `OneToOneField(ActionChallenge, on_delete=PROTECT)`
- `status`: `CharField(choices=['ACTIVE', 'SUPERSEDED_BY_REVISION', 'INVALIDATED_BY_INCIDENT', 'EXPIRED'], default='ACTIVE')`
- `created_at`: `DateTimeField()`
- `expires_at`: `DateTimeField()` — Không vượt quá `payment_request.expires_at`.
- **Ràng buộc DB**:
  - `UniqueConstraint(fields=['payment_revision', 'slot'])`
  - `UniqueConstraint(fields=['payment_revision', 'approver_person_id'])`
  - `UniqueConstraint(fields=['payment_revision', 'approver'])`

### 3.7. Bảng `payments_paymentexecution`
- `id`: `UUIDField(primary_key=True)`
- `payment_request`: `OneToOneField(PaymentRequest, on_delete=PROTECT, related_name='execution')` — Đảm bảo tối đa 1 thực thi cho mỗi yêu cầu.
- `payment_revision`: `ForeignKey(PaymentRevision, on_delete=PROTECT)`
- `content_digest`: `CharField(max_length=64)`
- `amount_vnd`: `BigIntegerField()`
- `currency`: `CharField(max_length=8, default='VND')`
- `beneficiary_name_snapshot`: `CharField(max_length=200)`
- `bank_name_snapshot`: `CharField(max_length=150)`
- `account_number_snapshot`: `CharField(max_length=64)`
- `executor`: `ForeignKey(EmployeeIdentity, on_delete=PROTECT)`
- `executor_person_id`: `CharField(max_length=64)`
- `challenge`: `OneToOneField(ActionChallenge, on_delete=PROTECT)`
- `idempotency_key`: `CharField(max_length=128)`
- `payload_fingerprint`: `CharField(max_length=64)` — Dùng để phân biệt retry hợp lệ cùng payload với xung đột idempotency.
- `receipt_id`: `CharField(max_length=64, unique=True)` (ví dụ: `SIM-RCPT-2026-...`)
- `execution_label`: `CharField(max_length=64, default='SIMULATED_ONLY_NO_REAL_BANK_TRANSFER')`
- `executed_at`: `DateTimeField()`

### 3.8. Bảng `audit_auditevent` & `common_securitymutex`
- **`AuditEvent`**:
  - `id`: `UUIDField(primary_key=True)`
  - `actor`: `ForeignKey(EmployeeIdentity, null=True, blank=True, on_delete=PROTECT)`
  - `actor_username_snapshot`: `CharField(max_length=150, blank=True)`
  - `actor_person_id`: `CharField(max_length=64, blank=True)`
  - `actor_role`: `CharField(max_length=32, blank=True)`
  - `action`: `CharField(max_length=64)`
  - `payment_request`: `ForeignKey(PaymentRequest, null=True, blank=True, on_delete=PROTECT)`
  - `revision_number`: `PositiveIntegerField(null=True, blank=True)`
  - `target_user`: `ForeignKey(EmployeeIdentity, null=True, blank=True, on_delete=PROTECT, related_name='targeted_audit_events')`
  - `result`: `CharField(choices=['SUCCESS', 'DENIED', 'ERROR'])`
  - `reason_code`: `CharField(max_length=64)`
  - `before_state`: `CharField(max_length=64, blank=True)`
  - `after_state`: `CharField(max_length=64, blank=True)`
  - `correlation_id`: `CharField(max_length=64)`
  - `metadata`: `JSONField(default=dict)` — Đã qua bộ lọc `sanitize_audit_metadata()` đảm bảo tuyệt đối không chứa `password`, `otp`, `token`, `secret`, `seed`, `cookie`, `session_key`, `csrf`.
  - `created_at`: `DateTimeField(db_index=True)`
- **`SecurityMutex`**:
  - `id`: `IntegerField(primary_key=True)` — Luôn có sẵn hàng `id=1` được tạo từ data migration. Nếu thiếu hàng `id=1`, hàm `acquire_security_mutex()` lập tức từ chối an toàn (`Fail-Closed`).

