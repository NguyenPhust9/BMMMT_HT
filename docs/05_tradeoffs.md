# Phân tích Đánh đổi (Trade-off Analysis): Ngắn hạn, Dài hạn và Số liệu Thực nghiệm (M8)

Tài liệu này phân tích đầy đủ 6 chiều đánh đổi kỹ thuật của hệ thống theo Mục 14 của đặc tả, tách bạch rõ **số liệu đo thực nghiệm trên lab (cỡ mẫu N=5)** với **phân tích định tính và ước lượng dài hạn có giả định**.

---

## 1. Kết quả đo thực nghiệm trên môi trường Lab (`N = 5` lần chạy lặp luồng hợp lệ)

- **Điều kiện đo**: Windows 11 64-bit, Python 3.13.5, Django 5.2.14, PostgreSQL 17.6 (`127.0.0.1:55432`), tách riêng độ trễ xử lý hệ thống (system latency) khỏi thời gian chờ con người nhập mã hoặc chờ qua bước TOTP 30 giây.
- **Tệp dữ liệu gốc**: [`evidence/demos/metrics_n5.json`](../evidence/demos/metrics_n5.json)

| Lần chạy | Số chủ thể tham gia | Tổng số lần xác thực TOTP (Đăng nhập + Thao tác) | Tổng số HTTP Request | Thời gian 3 chủ thể đăng nhập 2 bước (ms) | Thời gian tạo + nộp + 2 phiếu duyệt + thực thi (ms) | Tổng độ trễ xử lý hệ thống (ms) |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 3 (`lan`, `nam`, `huong`) | 6 (3 login + 2 approve + 1 execute) | 14 | 1956.8 ms | 169.9 ms | **2126.8 ms** |
| 2 | 3 (`lan`, `nam`, `huong`) | 6 (3 login + 2 approve + 1 execute) | 14 | 2155.6 ms | 189.3 ms | **2345.0 ms** |
| 3 | 3 (`lan`, `nam`, `huong`) | 6 (3 login + 2 approve + 1 execute) | 14 | 2103.9 ms | 171.0 ms | **2274.9 ms** |
| 4 | 3 (`lan`, `nam`, `huong`) | 6 (3 login + 2 approve + 1 execute) | 14 | 1927.8 ms | 166.8 ms | **2094.5 ms** |
| 5 | 3 (`lan`, `nam`, `huong`) | 6 (3 login + 2 approve + 1 execute) | 14 | 1925.9 ms | 166.8 ms | **2092.7 ms** |
| **Trung bình (N=5)** | **3** | **6 lần TOTP** | **14 HTTP** | **2014.0 ms** | **172.8 ms** | **2186.8 ms** |

> **Nhận xét thực nghiệm**: Độ trễ xử lý phía máy chủ và PostgreSQL (kể cả băm mật khẩu PBKDF2, khóa `SecurityMutex` `SELECT ... FOR UPDATE`, kiểm chứng SHA-256 `content_digest` và ghi `AuditEvent`) trung bình chỉ khoảng **2186.8 ms** cho toàn bộ vòng đời 14 bước HTTP. Chi phí thời gian thực tế trong vận hành chủ yếu nằm ở thao tác con người mở ứng dụng TOTP (ước lượng giả định 10–25 giây/người) và quy tắc chống dùng lại cùng một timestep TOTP 30 giây (`T-23`).

---

## 2. Sáu chiều đánh đổi ngắn hạn và dài hạn (Mục 14.1 – 14.6)

### 2.1. Yêu cầu xác thực OTP mới ràng buộc hành động khi phê duyệt và thực thi mô phỏng (`DES-05`)
- **Ngắn hạn (Thực nghiệm)**: Mỗi yêu cầu thanh toán cần tổng cộng **6 lần xác thực TOTP** (3 lần đăng nhập phiên + 2 lần cấp/tiêu thụ challenge `APPROVE` + 1 lần cấp/tiêu thụ challenge `EXECUTE`). Nếu cùng một chủ thể vừa đăng nhập vừa duyệt ngay trong cùng cửa sổ 30 giây, hệ thống từ chối timestep trùng (`T-23`) và buộc chờ tối đa 30 giây sang mã mới. Đổi lại, đánh cắp cookie phiên (`T-11`) hoặc đánh cắp mật khẩu (`T-10`) hoàn toàn không thể tạo phiếu duyệt hay lệnh thực thi.
- **Dài hạn (Phân tích có giả định)**: Khi nhân sự làm mất điện thoại hoặc hỏng thiết bị tạo mã TOTP, baseline không mở chức năng tự reset MFA qua web (`T-14`) để tránh tạo lối đi vòng cho kẻ tấn công. Do đó tổ chức phát sinh chi phí vận hành ngoại tuyến qua lệnh quản trị tin cậy `manage.py recover_principal` (`T-15`, `T-27`).

### 2.2. Hai người duyệt độc lập khác người lập cho mọi yêu cầu (`DES-02`)
- **Ngắn hạn (Thực nghiệm)**: Chặn đứng kịch bản một tài khoản người duyệt bị chiếm hoàn toàn cả mật khẩu lẫn thiết bị MFA (`T-12`, `D-02`), vì kẻ tấn công chỉ tạo được tối đa 1 phiếu (`DIRECTOR` hoặc `CONTROLLER`) và không thể tự duyệt hay chiếm 2 vị trí (`T-07`). Đổi lại, yêu cầu phải chờ đủ cả Giám đốc và Kiểm soát viên phản hồi (`T-02`).
- **Dài hạn (Phân tích có giả định)**: Trong doanh nghiệp thực tế, khi một người duyệt nghỉ phép hoặc công tác, quy trình có thể bị nghẽn nếu không có cơ chế ủy quyền hoặc nhóm người duyệt thay thế theo ca. Ngoài ra, nếu hai người duyệt cùng bị chiếm quyền đồng thời hoặc thông đồng ngoài đời thực thì cơ chế 2 người duyệt trong ứng dụng không tự triệt tiêu được rủi ro.

### 2.3. Danh tính/vai trò cố định qua bootstrap offline; không signup, nâng quyền hoặc reset MFA qua UI/API (`DES-01`)
- **Ngắn hạn (Thực nghiệm)**: Loại bỏ hoàn toàn bề mặt tấn công tự đăng ký tài khoản trùng tên sếp (`T-05`), tự chèn trường `role=DIRECTOR` (`T-06`) hoặc tự thay đổi factor MFA (`T-14`). Việc khởi tạo 6 tài khoản lab qua `manage.py bootstrap_lab` mất dưới 2 giây.
- **Dài hạn (Phân tích có giả định)**: Mô hình CLI ngoại tuyến chỉ phù hợp với quy mô nhỏ hoặc môi trường lab. Khi mở rộng lên hàng trăm nhân sự, tổ chức cần quy trình IAM/HR tích hợp có phê duyệt đa chữ ký và kiểm toán độc lập cho thao tác cấp phát danh tính.

### 2.4. Xác nhận gắn nội dung/phiên bản (`content_digest`), có hạn 120 giây và dùng một lần (`DES-04`, `DES-05`)
- **Ngắn hạn (Thực nghiệm)**: Ngăn chặn triệt để hành vi sửa số tiền/người nhận sau khi đã duyệt (`T-19`, `T-20`, `D-03`), phát lại challenge cũ (`T-22`), hoặc dùng challenge của yêu cầu này cho yêu cầu khác (`T-17`). Tuy nhiên, nếu người lập chỉnh sửa dù chỉ một trường nhỏ sau khi đã có 1 phiếu duyệt, toàn bộ phiếu và challenge cũ bị vô hiệu hóa (`SUPERSEDED_BY_REVISION`), buộc các người duyệt phải thực hiện lại từ đầu.
- **Dài hạn (Phân tích có giả định)**: Cần đồng bộ đồng hồ máy chủ (NTP) ổn định và chọn TTL hợp lý (120 giây cho challenge, 24 giờ cho phê duyệt) để cân bằng giữa an ninh và tính sẵn sàng.

### 2.5. Nhật ký kiểm toán (`AuditEvent`) đủ truy vết nhưng giới hạn quyền đọc và không ghi bí mật (`YC-08`)
- **Ngắn hạn (Thực nghiệm)**: Ghi nhận đầy đủ chuỗi sự kiện từ đăng nhập, cấp challenge, duyệt, từ chối, sửa đổi, đình chỉ đến thực thi mô phỏng; tự động lọc bỏ mọi trường nhạy cảm (`password`, `otp_token`, `secret`, `cookie`, `csrf`) được kiểm chứng qua `T-38`. `SECURITY_ADMIN` chỉ thấy sự kiện an ninh mà không thấy số tiền hay số tài khoản ngân hàng.
- **Dài hạn (Phân tích có giả định)**: Nhật ký lưu trong cùng PostgreSQL chỉ bảo vệ trước người dùng ứng dụng thông thường (`POST/DELETE /audit` bị chặn 403), nhưng **không bất biến trước người quản trị máy chủ/DBA bị chiếm quyền**. Triển khai thực tế cần đẩy log thời gian thực sang hệ thống SIEM/WORM tách biệt.

### 2.6. Khóa tuần tự hóa `SecurityMutex` (`SELECT ... FOR UPDATE`) trên PostgreSQL (`DES-08`)
- **Ngắn hạn (Thực nghiệm)**: Giúp chứng minh chặt chẽ tính nguyên tử giữa `execute_payment_request_simulated`, `execute_security_admin_action`, `revise_payment_request` và `approve_payment_request` trên hai kết nối PostgreSQL đồng thời (`T-30`..`T-35`, `D-04`) mà không xảy ra deadlock hay trạng thái nửa vời (`T-40`). Thời gian giữ khóa thực tế mỗi giao dịch dưới 15 ms.
- **Dài hạn (Phân tích có giả định)**: Khóa toàn cục một dòng (`SecurityMutex(id=1)`) tạo điểm nghẽn tuần tự nếu hệ thống có hàng trăm giao dịch phê duyệt/thực thi mỗi giây. Ở quy mô lớn cần tách khóa theo thứ tự định sẵn (`Principal -> Beneficiary -> PaymentRequest`), đi kèm bộ kiểm thử chống deadlock liên đối tượng.
