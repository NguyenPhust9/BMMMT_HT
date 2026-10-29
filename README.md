# SecurePay Lab — Hệ thống xác minh và phê duyệt yêu cầu thanh toán nội bộ (Đề tài 5)

Prototype nghiên cứu học phần **Bảo mật mạng máy tính và hệ thống** giải quyết bài toán: **Xác minh và phê duyệt yêu cầu thanh toán nội bộ trước nguy cơ giả mạo danh tính (deepfake/display-name spoofing) và chiếm quyền tài khoản**.

> **Lưu ý phạm vi**: Toàn bộ tài khoản, danh mục người nhận và giao dịch trong kho mã này là **dữ liệu mô phỏng** phục vụ kiểm thử bảo mật. Trạng thái cuối là `EXECUTED_SIMULATED` (biên nhận mô phỏng nội bộ), tuyệt đối không kết nối ngân hàng hay chuyển tiền thật.

---

## 1. Kiến trúc và các chốt kiểm soát bảo mật cốt lõi (`DES-01` .. `DES-10`)

1. **Khởi tạo tin cậy ngoại tuyến (`DES-01`)**: Danh tính nhân sự (`EmployeeIdentity`), vai trò (`Role`: `REQUESTER`, `DIRECTOR`, `CONTROLLER`, `SECURITY_ADMIN`), mã định danh cá nhân thực (`person_id`) và thiết bị TOTP (`TOTPDevice`) được khởi tạo qua lệnh ngoại tuyến `python manage.py bootstrap_lab`. Hệ thống **không mở** đăng ký công khai, không cho tự nâng quyền, không cho tự đổi/reset MFA qua giao diện web và không gắn `/admin/` cho tác vụ nghiệp vụ.
2. **Hai người duyệt độc lập bắt buộc (`DES-02`)**: Mọi yêu cầu thanh toán phải có đủ **02 phiếu phê duyệt hợp lệ** từ hai vai trò khác nhau (`DIRECTOR` và `CONTROLLER`), thuộc hai con người thực khác nhau (`person_id` độc lập) và đều khác người lập yêu cầu (`REQUESTER`).
3. **Chỉ chủ sở hữu yêu cầu mới được thực thi mô phỏng (`DES-03`)**: Sau khi đạt trạng thái `APPROVED`, chỉ chính `REQUESTER` đã lập yêu cầu đó mới có quyền gọi `POST /requests/<id>/execute-simulated` kèm một `ActionChallenge(action=EXECUTE)` mới và mã TOTP mới.
4. **Đóng băng nội dung bất biến & chống sửa âm thầm (`DES-04`)**: Mỗi lần nộp yêu cầu đóng băng một bản ghi `PaymentRevision` kèm mã băm SHA-256 chuẩn hóa (`content_digest`). Mọi chỉnh sửa hợp lệ thông qua `/revise` bắt buộc tạo revision mới ở trạng thái `DRAFT` và tự động vô hiệu hóa toàn bộ phiếu duyệt/challenge của revision cũ.
5. **Xác thực thao tác mới ràng buộc ngữ cảnh & chống phát lại (`DES-05`)**: Mỗi thao tác nhạy cảm (`APPROVE`, `REJECT`, `EXECUTE`, `ADMIN_REVOKE`) yêu cầu một `ActionChallenge` do máy chủ cấp (TTL 120 giây, dùng 1 lần) gắn chặt với `actor_id`, `person_id`, `session_key`, `totp_device_id`, `security_epoch`, `request_id`, `revision_id`, `content_digest` và `beneficiary_version_id`. Thiết bị `TOTPDevice` lưu `last_t` trên PostgreSQL để chặn dùng lại cùng một mã/timestep TOTP 30 giây (`T-23`, `T-34`).
6. **Cô lập nguồn ngoài chưa xác minh (`DES-06`)**: Trường `source_kind` và `source_excerpt` (email, chat, cuộc gọi) chỉ lưu dưới dạng văn bản thuần đã escape HTML và luôn gắn nhãn cảnh báo `Nguồn ngoài — chưa xác minh`.
7. **Danh mục người nhận tiền tin cậy có phiên bản (`DES-07`)**: Chỉ cho phép lập/duyệt/thực thi tới `Beneficiary` có trạng thái `VERIFIED`. Thay đổi hoặc thu hồi người nhận qua CLI `manage.py manage_beneficiary` trước bước thực thi sẽ bị Final Gate chặn lại (`T-28`).
8. **Tính nguyên tử và chống tranh chấp trên PostgreSQL thật (`DES-08`)**: Mọi giao dịch nhạy cảm khóa `SecurityMutex(id=1)` bằng `SELECT ... FOR UPDATE` bên trong `transaction.atomic()` trên **PostgreSQL 17**, kết hợp ràng buộc `OneToOneField` trên `PaymentExecution` để đảm bảo mỗi yêu cầu chỉ tạo tối đa 01 biên nhận mô phỏng ngay cả khi 2 kết nối chạy đua đồng thời (`T-30`..`T-35`, `T-40`).
9. **Tách biệt quyền Quản trị viên an ninh & Thu hồi khẩn cấp (`DES-09`)**: `SECURITY_ADMIN` chỉ có quyền xem danh sách tài khoản, đọc nhật ký an ninh đã lọc thông tin tài chính và thực hiện `SUSPEND` hoặc `REVOKE_ALL` (tăng `security_epoch`, đẩy các yêu cầu liên quan sang `HOLD`). Khôi phục tài khoản chỉ thực hiện qua CLI ngoại tuyến `manage.py recover_principal`.

---

## 2. Yêu cầu môi trường & Cài đặt nhanh

- **Hệ điều hành**: Windows 10/11 hoặc Linux/macOS
- **Python**: `3.13.x` (hoặc `>= 3.11`)
- **Cơ sở dữ liệu**: **PostgreSQL 17** (tự động khởi tạo cụm cục bộ cô lập tại `private/pgdata` trên cổng `127.0.0.1:55432` hoặc chạy qua `docker compose up -d db`)

### Chạy nhanh bằng 1 lệnh duy nhất

```powershell
# Tự động kích hoạt .venv, bật PostgreSQL 17, migrate, khởi tạo dữ liệu mẫu và chạy web tại http://127.0.0.1:8000
python app.py

# (Tùy chọn) Đặt lại toàn bộ dữ liệu demo về trạng thái ban đầu rồi khởi chạy
python app.py --reset
```

### Các lệnh thiết lập và kiểm thử chi tiết trên Windows PowerShell

```powershell
# 1. Thiết lập môi trường ảo, khởi chạy PostgreSQL 17 (cổng 55432), migrate và seed dữ liệu lab
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1

# 2. Kiểm tra cấu hình hệ thống Django & PostgreSQL
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1

# 3. Chạy toàn bộ 40 ca kiểm thử tự động (T-01..T-40) trên PostgreSQL thật
.\.venv\Scripts\python.exe .\scripts\run_all_tests.py

# 4. Chạy 4 kịch bản demo (D-01..D-04) và đo thực nghiệm N=5 cho phân tích Trade-off
.\.venv\Scripts\python.exe .\scripts\run_demos_and_capture.py

# 5. Khởi chạy máy chủ web cục bộ (HTTP loopback: http://127.0.0.1:8000)
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
```

---

## 3. Danh sách nhân sự và dữ liệu mô phỏng (Sau khi chạy `bootstrap_lab`)

Thông tin đăng nhập và mã TOTP khởi tạo cho từng phiên chạy được sinh tự động vào tệp cục bộ `private/demo_credentials.json` (tệp này nằm trong `.gitignore`, **không bao giờ đưa vào Git hoặc báo cáo**).

| Tài khoản (`username`) | Họ tên hiển thị | Vai trò (`role`) | Mã định danh (`person_id`) | Ghi chú kiểm thử |
|---|---|---|---|---|
| `vanphu` | Nguyễn Văn Phú | `REQUESTER` | `PER-VANPHU-001` | Người lập yêu cầu & thực thi mô phỏng yêu cầu của mình |
| `minh` | Lê Hoàng Minh | `REQUESTER` | `PER-MINH-005` | Người lập thứ hai để kiểm thử cô lập quyền sở hữu (`T-04`, `T-08`) |
| `dacqui` | Bùi Đắc Quí | `DIRECTOR` | `PER-DACQUI-002` | Người duyệt độc lập 1 (Giám đốc) |
| `doanphuc` | Đoàn Phúc | `CONTROLLER` | `PER-DOANPHUC-003` | Người duyệt độc lập 2 (Kiểm soát viên tài chính) |
| `ngocchau` | Đặng Ngọc Châu (Quản trị an ninh) | `SECURITY_ADMIN` | `PER-NGOCCHAU-004` | Quản trị an ninh (`SUSPEND`/`REVOKE_ALL`, không có quyền tài chính) |
| `dacqui_lookalike` | Bùi Đắc Quí (Giám đốc) | `UNPRIVILEGED` | `PER-FAKE-006` | Tài khoản giả danh trùng tên hiển thị với Giám đốc Quí (`T-05`, `D-02`) |

---

## 4. Kết quả kiểm thử thực tế (`T-01` .. `T-40`)

- **Tổng số ca kiểm thử**: `40` ca (`PASS`: **40/40** trên PostgreSQL 17.6).
- **Bảng kết quả CSV**: [`evidence/test_results.csv`](evidence/test_results.csv)
- **Chỉ mục bằng chứng**: [`evidence/index.md`](evidence/index.md)
- **Nhật ký chi tiết từng ca**: [`evidence/logs/`](evidence/logs/)
- **Bằng chứng 4 kịch bản Demo (`D-01`..`D-04`)**: [`evidence/demos/`](evidence/demos/)

---

## 5. Bản đồ thư mục bàn giao (`SP-01` .. `SP-05`)

- `deliverables/Bao_cao_De_tai_5.docx` & `deliverables/Bao_cao_De_tai_5.md`: Báo cáo tổng kết đồ án đầy đủ 10 chương + Phụ lục A/B (`SP-01`).
- `docs/diagrams/*.mmd`, `*.svg`, `*.png`: 07 bộ sơ đồ kiến trúc, DFD, ERD, máy trạng thái và sequence diagrams (`SP-02`).
- `apps/`, `config/`, `templates/`, `static/`, `compose.yaml`, `requirements.lock`, `versions.txt`: Mã nguồn prototype và cấu hình môi trường (`SP-03`).
- `tests/`, `evidence/test_results.csv`, `evidence/index.md`, `evidence/logs/`: Bộ kiểm thử tự động `T-01..T-40` và bằng chứng thực thi thực tế (`SP-04`).
- `deliverables/Slide_De_tai_5.pptx` & `deliverables/Kich_ban_demo.md`: Slide thuyết trình 12 trang và kịch bản trình diễn `D-01..D-04` có thể tái lập (`SP-05`).
