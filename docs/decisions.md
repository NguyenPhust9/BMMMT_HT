# Nhật Ký Quyết Định Thiết Kế Và Triển Khai (Design & Implementation Decisions)

Tài liệu này ghi nhận toàn bộ các quyết định thiết kế cơ sở (`DES-01..DES-10`) từ đặc tả đề tài và các quyết định kỹ thuật chi tiết được lựa chọn trong quá trình triển khai `securepay_lab`.

## 1. Các quyết định Baseline bắt buộc (DES-01 .. DES-10)

| Mã | Quyết định thiết kế | Trạng thái | Nơi thực thi dự kiến / thực tế |
|---|---|---|---|
| **DES-01** | Danh tính và vai trò được cấp qua bootstrap ngoại tuyến đáng tin cậy (`manage.py bootstrap_lab`). Không mở public signup, không tự nâng quyền, không impersonation, không reset MFA qua UI/API; không mở Django admin (`/admin/`) để sửa dữ liệu nghiệp vụ. | Đã chốt (M0) | `apps/accounts/management/commands/bootstrap_lab.py`, `config/urls.py` |
| **DES-02** | Mọi yêu cầu thanh toán đều cần đủ 2 người duyệt độc lập (`DIRECTOR` và `CONTROLLER`), là 2 cá nhân thực khác nhau (`person_id` khác nhau) và đều khác `person_id` của `REQUESTER`. Không có ngưỡng số tiền để miễn người duyệt thứ hai. | Đã chốt (M0) | `apps/payments/services.py`, `apps/payments/models.py` |
| **DES-03** | Chỉ `REQUESTER` đã tạo yêu cầu mới được thực thi mô phỏng (`EXECUTE_SIMULATED`) sau khi đủ 2 phiếu duyệt hợp lệ; thao tác thực thi bắt buộc có `ActionChallenge` loại `EXECUTE` và mã TOTP mới. `DIRECTOR`, `CONTROLLER` và `SECURITY_ADMIN` không có quyền execute. | Đã chốt (M0) | `apps/payments/services.py`, `apps/payments/views.py` |
| **DES-04** | Số tiền (`amount_vnd`) là số nguyên dương VND (`1 <= amount_vnd <= 1_000_000_000_000`), số tài khoản là chuỗi ký tự. Khi gửi duyệt (`SUBMIT`), bản ghi `PaymentRevision` được đóng băng bất biến kèm `content_digest` (SHA-256 canonical JSON). Mọi chỉnh sửa nội dung sau khi nộp đều tạo `revision_number` mới ở trạng thái `DRAFT` và vô hiệu hóa mọi phê duyệt/challenge cũ. | Đã chốt (M0) | `apps/payments/models.py`, `apps/payments/services.py` |
| **DES-05** | `ActionChallenge` phía máy chủ ràng buộc: `actor`, `person_id`, `session_key`, `device_id`, `security_epoch`, `action`, `request_id`, `revision_id`, `content_digest`, `beneficiary_version_id`, `expires_at` (TTL 120 giây) và chỉ tiêu thụ một lần (`consumed_at`). Mã TOTP 6 chữ số chỉ xác minh yếu tố thiết bị của tài khoản và chống dùng lại timestep (`last_t`), không gọi TOTP là "chữ ký số giao dịch". | Đã chốt (M0) | `apps/payments/models.py`, `apps/accounts/services.py`, `apps/payments/services.py` |
| **DES-06** | Dữ liệu từ kênh bên ngoài chỉ gồm `source_kind` và `source_excerpt` (tối đa 2.000 ký tự), luôn được validate và escape khi hiển thị cùng nhãn `"Nguồn ngoài — chưa xác minh"`. Không cho phép upload file nhị phân, không phân loại deepfake, không tự động tin vì trùng tên/ảnh lãnh đạo. | Đã chốt (M0) | `apps/payments/forms.py`, `templates/payments/` |
| **DES-07** | Danh mục người thụ hưởng (`Beneficiary` & `BeneficiaryVersion`) có phiên bản bất biến, được xác minh trước qua quy trình độc lập ngoại tuyến (`manage.py manage_beneficiary`). Không cho phép người dùng nhập tự do hoặc sửa số tài khoản nhận trực tiếp trên giao diện tạo yêu cầu. | Đã chốt (M0) | `apps/beneficiaries/models.py`, `apps/beneficiaries/management/commands/manage_beneficiary.py` |
| **DES-08** | Mọi thao tác thay đổi trạng thái nhạy cảm (xác thực MFA/OTP, gửi duyệt, cấp/tiêu thụ challenge, duyệt/từ chối, sửa revision, thực thi mô phỏng, đình chỉ/thu hồi, cập nhật vai trò/người nhận qua CLI) đều phải khóa hàng `SecurityMutex(id=1)` bằng `select_for_update()` bên trong `transaction.atomic()` trên PostgreSQL, sau đó đọc lại toàn bộ điều kiện từ DB. `PaymentExecution` là duy nhất cho mỗi `PaymentRequest` (`OneToOneField`) và commit cùng lúc với `AuditEvent`. | Đã chốt (M0) | `apps/common/mutex.py`, `apps/payments/services.py`, `apps/accounts/services.py` |
| **DES-09** | `SECURITY_ADMIN` chỉ có quyền xem danh sách trạng thái tài khoản, xem log an ninh đã lọc, đình chỉ (`SUSPEND`) và thu hồi phiên/xác nhận (`REVOKE_ALL`) với challenge + OTP mới + lý do. Khôi phục tài khoản hoặc đặt lại MFA/role chỉ thực hiện qua công cụ vận hành ngoại tuyến (`manage.py recover_principal`), bắt buộc tăng `security_epoch` và yêu cầu duyệt lại các yêu cầu đang chờ. | Đã chốt (M0) | `apps/accounts/views.py`, `apps/accounts/management/commands/recover_principal.py` |
| **DES-10** | Luồng lõi chạy trên dữ liệu giả lập cục bộ (`127.0.0.1`) với PostgreSQL thật. Hỗ trợ cả cấu hình HTTP loopback để phát triển/kiểm thử nhanh và profile HTTPS cục bộ (`Caddy` / reverse proxy TLS với chứng chỉ CA riêng của lab) để kiểm chứng `T-39` mà không tự ý can thiệp System Trust Store của máy chủ người dùng. | Đã chốt (M0) | `compose.yaml`, `config/settings.py`, `scripts/` |

---

## 2. Các quyết định kỹ thuật bổ sung (TECH-01 .. TECH-06)

### TECH-01: Chuẩn hóa Canonical JSON cho `content_digest`
- **Quyết định**: Hàm tạo `content_digest` cho `PaymentRevision` chuẩn hóa Unicode theo dạng `NFC`, sắp xếp khóa từ điển (`sort_keys=True`, `separators=(',', ':')`, `ensure_ascii=False`) trên tập trường quyết định gồm:
  - `request_id` (UUID string)
  - `revision_number` (int)
  - `amount_vnd` (int)
  - `currency` (`"VND"`)
  - `beneficiary_id` (UUID string)
  - `beneficiary_version_id` (UUID string)
  - `beneficiary_name_snapshot` (str)
  - `bank_name_snapshot` (str)
  - `account_number_snapshot` (str)
  - `purpose` (str)
  - `source_kind` (str)
  - `source_excerpt` (str)
- Đối với `ActionChallenge` quản trị (`SUSPEND`, `REVOKE_ALL`), `action_digest` được tính SHA-256 trên canonical JSON của `{"action": action, "target_user_id": str(target_user.id), "target_epoch": target_user.security_epoch, "reason": reason.strip()}`.

### TECH-02: Bảo toàn bộ đếm giới hạn thử sai (Throttle Persistence) khi từ chối xác thực
- **Quyết định**: Khi kiểm tra mật khẩu hoặc mã TOTP thất bại bên trong một thao tác nghiệp vụ, nếu chỉ ném ngoại lệ làm rollback toàn bộ transaction thì bộ đếm lỗi (`failed_attempts`, `throttled_until` hoặc bộ đếm của `TOTPDevice`) và `AuditEvent` từ chối sẽ bị mất. Do đó, nhánh từ chối xác thực/nghiệp vụ thông thường sẽ ghi nhận tăng bộ đếm throttle và `AuditEvent` từ chối rồi **commit** giao dịch đó trước khi trả về mã lỗi HTTP (`400`/`401`/`403`/`409`/`429`), trong khi không tạo bất kỳ hiệu ứng thành công nào (`Approval`, `PaymentExecution`). Ngược lại, nếu xảy ra lỗi hệ thống/cơ sở dữ liệu bất ngờ giữa lúc ghi `PaymentExecution` và `AuditEvent` thành công (`T-40`), toàn bộ transaction thành công sẽ bị rollback hoàn toàn.

### TECH-03: Cơ chế phiên hai giai đoạn (Pre-Auth Session vs Full MFA Session)
- **Quyết định**:
  - Bước 1 (`/auth/login`): Kiểm tra username/password và giới hạn thử sai mật khẩu. Nếu đúng, xóa dữ liệu phiên cũ, tạo phiên tạm chỉ chứa `preauth_user_id`, `preauth_epoch`, `preauth_expires_at` (hạn 5 phút) và `preauth_used = False`. Phiên này bị mọi endpoint nghiệp vụ từ chối với mã `MFA_REQUIRED` (`401`).
  - Bước 2 (`/auth/mfa`): Dưới khóa `SecurityMutex(id=1)`, kiểm tra `preauth_user_id` còn active, `user.security_epoch == preauth_epoch`, chưa quá 5 phút, và xác thực mã TOTP trên `TOTPDevice` đã confirmed. Nếu hợp lệ, gọi `request.session.cycle_key()` (rotate session ID), xóa các khóa `preauth_*`, ghi `auth_user_id`, `auth_security_epoch = checked_epoch`, `auth_mfa_verified = True`, `session_created_at`, `session_last_activity_at`.

### TECH-04: Quản lý hiệu lực phiếu duyệt (`Approval`) và trạng thái `HOLD`
- **Quyết định**:
  - Mỗi bản ghi `Approval` lưu cả `approver_epoch_at_signing` và `requester_epoch_at_signing` cùng trạng thái `status` (`ACTIVE`, `SUPERSEDED_BY_REVISION`, `INVALIDATED_BY_INCIDENT`, `EXPIRED`).
  - Khi một tài khoản bị `SUSPEND`, `REVOKE_ALL`, đổi `role`, hoặc đặt lại MFA qua CLI (`security_epoch` tăng lên), mọi yêu cầu đang ở `PENDING_APPROVAL` hoặc `APPROVED` (chưa thực thi) có liên quan đến tài khoản đó (là `requester` hoặc là người đã ký `Approval` đang `ACTIVE`) sẽ được chuyển sang trạng thái `HOLD`, và các phiếu `Approval` của người bị sự cố chuyển sang `INVALIDATED_BY_INCIDENT` (vẫn giữ nguyên bản ghi lịch sử để giải thích, không xóa khỏi DB).
  - Ngay cả khi trạng thái hiển thị chưa kịp chuyển, **Final Gate** trong `execute_payment_request` luôn kiểm tra trực tiếp `approver.is_active`, `approver.role == slot`, `approver.security_epoch == approval.approver_epoch_at_signing`, và `requester.security_epoch == approval.requester_epoch_at_signing`.

