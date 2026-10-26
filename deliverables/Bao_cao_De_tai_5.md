# BÁO CÁO ĐỒ ÁN MÔN HỌC: BẢO MẬT MẠNG MÁY TÍNH VÀ HỆ THỐNG
## ĐỀ TÀI 5: HỆ THỐNG XÁC MINH VÀ PHÊ DUYỆT YÊU CẦU THANH TOÁN NỘI BỘ TRƯỚC NGUY CƠ GIẢ MẠO VÀ CHIẾM QUYỀN TÀI KHOẢN

- **Ngày hoàn thành**: `2026-10-24 13:15:05 UTC`
- **Phiên bản mã nguồn**: `securepay-lab-v1.0.0`
- **Môi trường kiểm chứng**: `Windows 11 64-bit | Python 3.13.5 | Django 5.2.14 | PostgreSQL 17.6 (127.0.0.1:55432)`
- **Kết quả kiểm thử tự động**: **40/40 PASS** (`T-01` .. `T-40` trên PostgreSQL thật)

---

# Chương 1. Giới thiệu bài toán, mục tiêu và phạm vi Prototype

# 01 — Phạm Vi Đề Tài, Giả Định Tin Cậy Và Kế Hoạch Thực Hiện (M0)

## 1. Bài toán thực tế và mục tiêu hệ thống (GT-01, YC-01)

### 1.1. Tình huống nghiệp vụ cụ thể
Trong một doanh nghiệp giả lập (**Công ty TNHH Minh Phát Lab**), kế toán **Lan (`REQUESTER`)** nhận được tin nhắn từ kênh bên ngoài (Zalo/Telegram/Email/Cuộc gọi) tự xưng là Giám đốc **Nam (`DIRECTOR`)**:
> *"Chuyển gấp 20.000.000 VND cho nhà cung cấp theo số tài khoản mới đây, đừng gọi lại vì tôi đang họp kín."*

Trong môi trường số hiện đại:
- Tên hiển thị, ảnh đại diện, giọng nói, video hoặc ảnh chụp màn hình ủy nhiệm chi đều có thể bị giả mạo (deepfake, spoofing).
- Ngay cả tài khoản nhắn tin thật hoặc tài khoản hệ thống nội bộ của Giám đốc Nam cũng có thể đã bị kẻ tấn công chiếm quyền điều khiển (Account Takeover - ATO).

### 1.2. Cách hệ thống giải quyết vấn đề
Hệ thống **SecurePay Lab** là cổng xác minh và phê duyệt yêu cầu thanh toán nội bộ trước khi thực hiện lệnh thanh toán mô phỏng:
1. **Không mặc định tin nguồn ngoài (TC-01, TC-02)**: Mọi tin nhắn/yêu cầu bên ngoài chỉ được lưu dưới dạng văn bản trích dẫn (`source_kind`, `source_excerpt`) gắn nhãn **"Nguồn ngoài — chưa xác minh"**, hoàn toàn không tự sinh quyền hay tự thay đổi danh mục tài khoản thụ hưởng.
2. **Danh mục người thụ hưởng xác minh trước (DES-07)**: Người lập yêu cầu (`REQUESTER`) chỉ được chọn người thụ hưởng ở trạng thái `VERIFIED` với phiên bản (`BeneficiaryVersion`) bất biến đã được kiểm tra độc lập từ trước qua kênh hồ sơ/hợp đồng gốc.
3. **Đóng băng nội dung theo phiên bản (DES-04)**: Khi gửi duyệt (`SUBMIT`), hệ thống chụp nhanh (`snapshot`) thông tin ngân hàng, số tài khoản, tên người nhận, số tiền (nguyên dương VND), mục đích, nguồn trích dẫn và tạo mã băm `content_digest` (SHA-256 trên canonical JSON). Mọi sửa đổi sau khi nộp đều buộc tạo `PaymentRevision` mới và hủy hiệu lực toàn bộ phê duyệt/challenge cũ.
4. **Hai người duyệt độc lập khác người lập (DES-02)**: Mọi yêu cầu thanh toán (không phân biệt hạn mức tiền) bắt buộc phải có đủ 2 phê duyệt còn hiệu lực từ 2 cá nhân độc lập (`person_id` khác nhau và đều khác `person_id` của `REQUESTER`): một phiếu ở slot `DIRECTOR` và một phiếu ở slot `CONTROLLER`.
5. **Xác thực mới (Fresh Step-Up MFA) gắn ngữ cảnh hành động (DES-05)**: Đăng nhập đã có MFA chưa đủ để duyệt hay thực thi. Mỗi thao tác nhạy cảm (`APPROVE_DIRECTOR`, `APPROVE_CONTROLLER`, `REJECT`, `EXECUTE`, `SUSPEND`, `REVOKE_ALL`) đều yêu cầu server cấp `ActionChallenge` có thời hạn ngắn (120 giây), dùng một lần, ràng buộc chặt với `actor`, `session`, `device`, `security_epoch`, `action`, `request_id`, `revision_id`, `content_digest`, `beneficiary_version_id`, kèm mã TOTP ở timestep mới (chống replay timestep trên cùng thiết bị).
6. **Thực thi mô phỏng bởi đúng người lập (DES-03, DES-08)**: Chỉ chính `REQUESTER` đã lập yêu cầu mới được quyền thực thi mô phỏng (`EXECUTE_SIMULATED`) sau khi qua **Final Gate** dưới khóa giao dịch `SecurityMutex(id=1)` trên PostgreSQL. Kết quả chỉ tạo đúng 1 bản ghi `PaymentExecution` (gắn nhãn `SIMULATED`) và nhật ký `AuditEvent` trong cùng một transaction. Hệ thống **không** kết nối ngân hàng và **không** chuyển tiền thật.

### 1.3. Tuyên bố bảo vệ trong phạm vi giả định
- Trong các giả định tin cậy đã công bố, **một danh tính bị chiếm hoàn toàn (kể cả mất mật khẩu, phiên và TOTP seed của một người duyệt)** chỉ có thể tạo tối đa 1 phiếu duyệt của chính vai trò đó, không thể tự tạo đủ 2 phê duyệt độc lập, và không thể sửa đổi số tiền hoặc tài khoản thụ hưởng đã được người kia duyệt.
- **Không tuyên bố** "tài khoản bị chiếm không bao giờ hoàn tất được giao dịch" trong trường hợp người duyệt độc lập còn lại cũng duyệt thật cùng nội dung đó (ví dụ cả hai cùng bị lừa về mặt nghiệp vụ ngoài đời, hoặc cả hai tài khoản đều bị chiếm). Hệ thống cũng không phân loại deepfake âm thanh/hình ảnh và không chặn lệnh chuyển tiền nếu nhân viên tự ý chuyển ngoài ngân hàng không qua hệ thống.

---

## 2. Phân loại yêu cầu đề bài, lựa chọn thiết kế nhóm và phần mở rộng

Đề bài gốc (Phụ lục 19) không đặt mã số cụ thể. Các mã `GT-01`, `SEC-01..05`, `YC-01..08`, `TC-01..03`, `SP-01..05` (tổng cộng **22 mục**) là hệ thống mã truy vết do nhóm thiết lập để kiểm soát độ bao phủ 100% yêu cầu của giảng viên. Đề tài chọn **Hướng 1 – Security: Thiết kế hệ thống an toàn** (không triển khai Hướng 2).

| Phân nhóm | Nội dung cụ thể |
|---|---|
| **Yêu cầu gốc từ đề bài (22 mục)** | `GT-01` (Mục tiêu thiết kế hệ thống an toàn), `SEC-01..05` (5 câu hỏi Hướng 1), `YC-01..08` (8 yêu cầu chung), `TC-01..03` (3 nguyên tắc không mặc định tin thông tin bên ngoài), `SP-01..05` (5 sản phẩm bàn giao: Báo cáo, Sơ đồ, Source/Prototype, Test cases & kết quả, Slide & Demo). |
| **Lựa chọn thiết kế baseline của nhóm (DES-01..10)** | Website nội bộ Django 5.2 + PostgreSQL; 4 vai trò (`REQUESTER`, `DIRECTOR`, `CONTROLLER`, `SECURITY_ADMIN`); 2 người duyệt độc lập cho mọi yêu cầu; `REQUESTER` là người thực thi mô phỏng; `ActionChallenge` TTL 120s + `django-otp` TOTP chống replay timestep; `SecurityMutex(id=1)` khóa tuần tự các thao tác nhạy cảm; Bootstrap offline cố định; bộ 40 test cases (`T-01..T-40`) và 4 kịch bản demo (`D-01..D-04`). |
| **Được phép mô phỏng** | Danh tính nhân viên ban đầu (`person_id`), danh mục nhà cung cấp (`Beneficiary`), nội dung tin nhắn giả mạo từ bên ngoài, quy trình xác minh nhân thân/hợp đồng ngoại tuyến ngoài ứng dụng, và bút toán thực thi thanh toán (`EXECUTED_SIMULATED`). |
| **Ngoài phạm vi baseline (Out of Scope)** | Kết nối API ngân hàng thật, chuyển tiền thật, tích hợp Zalo/Email/SMS thật, mô hình AI phát hiện deepfake/giọng nói giả, ứng dụng di động, kiến trúc microservice/Redis/Celery, blockchain, tự đăng ký tài khoản (public signup) hoặc tự reset MFA qua UI/API. |
| **Phần mở rộng tùy chọn (Sau nghiệm thu lõi)** | WebAuthn/Passkeys chống phishing tốt hơn TOTP, giao diện đề xuất người nhận mới chờ xác minh độc lập, đẩy log sang kho lưu trữ bất biến độc lập (WORM/SIEM), tách khóa chi tiết theo từng `PaymentRequest`/`EmployeeIdentity` thay cho `SecurityMutex` toàn cục. |

---

## 3. Bốn vai trò và ranh giới quản trị (SEC-02, DES-01, DES-09)

1. **`REQUESTER` (Kế toán thanh toán — ví dụ: Lan, Minh)**:
   - Tạo, chỉnh sửa bản nháp, gửi duyệt (`submit`), tạo phiên bản mới (`revise`), hủy (`cancel`) yêu cầu do chính mình lập khi chưa ở trạng thái kết thúc.
   - Thực thi mô phỏng (`execute-simulated`) yêu cầu của chính mình khi đã đủ 2 phiếu duyệt hợp lệ, kèm challenge `EXECUTE` và mã TOTP mới.
   - Chỉ xem được yêu cầu, biên nhận và timeline nhật ký nghiệp vụ của chính mình.
2. **`DIRECTOR` (Giám đốc phê duyệt — ví dụ: Nam)**:
   - Xem các yêu cầu thanh toán trong phạm vi công ty giả lập.
   - Phê duyệt vào slot `DIRECTOR` hoặc từ chối (`reject`) bằng challenge và mã TOTP mới. Không được tự duyệt yêu cầu do cùng `person_id` lập, không được thực thi thanh toán.
3. **`CONTROLLER` (Kiểm soát viên tài chính — ví dụ: Hương)**:
   - Xem các yêu cầu thanh toán trong phạm vi công ty giả lập.
   - Phê duyệt vào slot `CONTROLLER` hoặc từ chối (`reject`) bằng challenge và mã TOTP mới. Độc lập với `DIRECTOR` và `REQUESTER`, không được thực thi thanh toán.
4. **`SECURITY_ADMIN` (Quản trị an ninh ứng dụng — ví dụ: An)**:
   - Xem danh sách trạng thái bảo mật tài khoản và nhật ký an ninh (`AuditEvent` đã lọc bớt chi tiết nội dung nhạy cảm không cần thiết).
   - Đình chỉ tài khoản (`suspend`) hoặc thu hồi toàn bộ phiên/xác nhận (`revoke-all`) khi nghi ngờ lộ lọt/chiếm quyền, bắt buộc qua challenge quản trị (`SUSPEND` / `REVOKE_ALL`), mã TOTP mới và lý do.
   - **Giới hạn nghiêm ngặt**: Không có quyền tạo user, không đổi `role`, không reset MFA, không sửa danh mục `Beneficiary`, không tạo/duyệt/thực thi yêu cầu thanh toán, và không mở `/admin/` của Django để can thiệp dữ liệu nghiệp vụ.

> **Tài khoản kiểm thử mạo danh**: Bootstrap tạo thêm tài khoản có `display_name` trùng tên Giám đốc ("Nguyễn Văn Nam") nhưng thuộc `person_id` khác và không có quyền `DIRECTOR` để kiểm chứng `T-05` (tên/ảnh hiển thị không tạo quyền).

---

## 4. Giả định tin cậy và giới hạn bảo vệ (TC-01, TC-02, TC-03)

### 4.1. Những gì hệ thống KHÔNG mặc định tin
- Mọi tham số từ phía trình duyệt (hidden inputs, query params, headers tự gửi, cookie, `role`, `verified`, `status`, `approver_id`).
- Tên hiển thị (`display_name`), ảnh đại diện, nội dung tin nhắn trích dẫn (`source_excerpt`), số tài khoản viết trong lời nhắn.
- Phiên đăng nhập có sẵn (vì phiên có thể bị đánh cắp sau khi đăng nhập) hoặc mã OTP đã dùng ở bước đăng nhập/thao tác trước.
- Quyết định đơn lẻ của bất kỳ 1 tài khoản nào (kể cả Giám đốc hay Quản trị an ninh).

### 4.2. Căn cứ kỹ thuật để hệ thống tin, kiểm chứng hoặc từ chối (TC-03)
- **Tin vào**: Mã nguồn máy chủ và cơ sở dữ liệu PostgreSQL, đồng hồ UTC của máy chủ, quy trình bootstrap/vận hành ngoại tuyến tạo `person_id` đã xác minh nhân thân và danh mục `BeneficiaryVersion` (`VERIFIED`).
- **Kiểm chứng bằng**:
  1. Phiên xác thực hợp lệ có `session_security_epoch == user.security_epoch` và chưa quá hạn (30 phút không hoạt động / 8 giờ tối đa).
  2. Quyền (`role`), trạng thái `is_active` và tính độc lập của `person_id` truy vấn trực tiếp từ PostgreSQL dưới khóa `SecurityMutex(id=1)`.
  3. Sự khớp nối nguyên vẹn giữa `PaymentRevision.content_digest`, `ActionChallenge.content_digest`, `Approval.content_digest` và `BeneficiaryVersion` đang active.
  4. Mã TOTP hợp lệ ở timestep mới (`last_t` tăng nghiêm ngặt trên `TOTPDevice`) gắn với `ActionChallenge` chưa hết hạn (`now < expires_at`) và chưa tiêu thụ (`consumed_at IS NULL`).
- **Từ chối khi**: Vi phạm bất kỳ điều kiện nào ở trên, đồng thời ghi nhận `AuditEvent` kèm `reason_code` tường minh (`AUTH_REQUIRED`, `MFA_REQUIRED`, `FORBIDDEN`, `SELF_APPROVAL`, `MISSING_APPROVAL`, `SNAPSHOT_MISMATCH`, `WRONG_SCOPE`, `CHALLENGE_EXPIRED`, `CHALLENGE_USED`, `OTP_REPLAY`, `PRINCIPAL_REVOKED`, `BENEFICIARY_INVALID`, `TERMINAL_STATE`, `IDEMPOTENCY_CONFLICT`, `RATE_LIMITED`).

### 4.3. Rủi ro còn lại (Residual Risks) được công bố rõ
1. **Hai người duyệt cùng bị chiếm quyền hoặc thông đồng / cùng bị lừa nghiệp vụ**: Nếu cả `DIRECTOR` và `CONTROLLER` đều bị kẻ tấn công chiếm cả mật khẩu + thiết bị TOTP, hoặc cả hai cùng tin một hợp đồng giả ngoài đời và duyệt cho một `Beneficiary` đã có sẵn trong danh mục, hệ thống kỹ thuật không thể tự biết sự thật ngoài đời.
2. **Thiết bị đầu cuối hoặc máy chủ/DB bị chiếm quyền root/DBA**: Nếu máy chủ hoặc PostgreSQL bị can thiệp trực tiếp ngoài ứng dụng, kẻ tấn công có thể sửa bảng dữ liệu hoặc nhật ký.
3. **Phishing thời gian thực ( Adversary-in-the-Middle )**: TOTP 6 số có thể bị lừa nhập qua trang giả mạo trong cửa sổ hiệu lực ngắn; tuy nhiên challenge gắn ngữ cảnh trên server vẫn ngăn việc dùng mã OTP đó cho một yêu cầu/số tiền khác với challenge đang mở.

---

## 5. Danh sách rủi ro ưu tiên và thứ tự triển khai M0–M9

### 5.1. Tám nhóm rủi ro ưu tiên (R-01..R-08)
- **R-01**: Giả danh qua tin nhắn bên ngoài hoặc tạo tài khoản trùng tên lãnh đạo (`T-05`, `T-06`, `T-18`).
- **R-02**: Chiếm mật khẩu, chiếm phiên làm việc hoặc chiếm hoàn toàn 1 tài khoản duyệt (`T-10..T-15`, `T-25..T-27`).
- **R-03**: Vượt quyền, tự duyệt, 1 người duyệt 2 slot, hoặc truy cập trái phép yêu cầu của người khác - IDOR (`T-02`, `T-04`, `T-07..T-09`, `T-24`).
- **R-04**: Sửa nội dung sau khi gửi/duyệt hoặc dùng chéo xác nhận giữa các yêu cầu/phiên bản/hành động (`T-16..T-20`, `T-28`, `T-32`).
- **R-05**: Phát lại (replay) challenge, dùng lại timestep TOTP, hoặc dùng xác nhận đã quá hạn (`T-21..T-23`, `T-29`, `T-34`).
- **R-06**: Chạy đua đồng thời (race conditions) gây thực thi kép, duyệt/sửa chồng chéo hoặc ghi dữ liệu một nửa khi lỗi DB (`T-30..T-35`, `T-40`).
- **R-07**: Lợi dụng tài khoản quản trị an ninh hoặc quy trình khôi phục làm lối đi vòng (`T-09`, `T-14`, `T-15`, `T-26..T-28`).
- **R-08**: Tấn công bề mặt web (CSRF, XSS qua trích dẫn tin nhắn, lộ bí mật trong log/audit, cấu hình phiên/HTTPS) (`T-08`, `T-36..T-39`).

### 5.2. Thứ tự công việc theo lộ trình M0–M9
- **M0**: Chốt phạm vi, giả định tin cậy, quyết định baseline (`docs/decisions.md`), bảng truy vết 22 mục (`docs/traceability.csv`) và trạng thái dự án (`PROJECT_STATUS.md`).
- **M1**: Thiết kế chi tiết mô hình đe dọa (`docs/02_threat_model.md`), kiến trúc & DFD (`docs/03_architecture.md`), cơ chế bảo mật & máy trạng thái (`docs/04_security_design.md`) và các sơ đồ Mermaid/SVG (`docs/diagrams/`).
- **M2**: Khởi tạo dự án Django + PostgreSQL trong `securepay_lab`, cấu hình môi trường riêng, migrations, khóa `SecurityMutex`, và lệnh bootstrap/seed ngoại tuyến an toàn.
- **M3**: Hiện thực hóa xác thực 2 bước (pre-auth session -> MFA), quản lý `security_epoch`, throttling, phân quyền phía máy chủ và khóa bề mặt admin.
- **M4**: Hiện thực hóa luồng yêu cầu thanh toán, đóng băng `PaymentRevision`, cấp `ActionChallenge`, 2 người duyệt độc lập và thực thi mô phỏng (`PaymentExecution`).
- **M5**: Hiện thực hóa các cơ chế chống sửa đổi nội dung, hết hạn theo giờ server, chống replay challenge/TOTP, idempotency và xử lý đồng thời với `SecurityMutex`.
- **M6**: Hiện thực hóa tính năng quản trị an ninh (`suspend`, `revoke-all`), quy trình khôi phục ngoại tuyến qua CLI, và hệ thống nhật ký `AuditEvent` phân quyền chặt.
- **M7**: Viết và chạy thực tế toàn bộ 40 test cases (`T-01..T-40`) trên PostgreSQL thật, thu thập log/bằng chứng vào `evidence/test_results.csv`, sửa triệt để mọi lỗi phát sinh.
- **M8**: Chạy và thu thập bằng chứng cho 4 kịch bản demo (`D-01..D-04`), đo đạc thực nghiệm và phân tích trade-off ngắn hạn/dài hạn (`docs/05_tradeoffs.md`).
- **M9**: Xuất báo cáo Word (`deliverables/Bao_cao_De_tai_5.docx`), slide thuyết trình (`deliverables/Slide_De_tai_5.pptx`), kịch bản demo (`deliverables/Kich_ban_demo.md`), kiểm tra cài mới và nghiệm thu cuối cùng.



---

# Chương 2. Đối chiếu yêu cầu đề bài và Quyết định thiết kế (`DES-01` .. `DES-10`)

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



---

# Chương 3. Người dùng, tài sản bảo vệ và Mô hình đe dọa (Threat Model)

# 02 — Mô Hình Đe Dọa, Tài Sản Cần Bảo Vệ Và Ma Trận Rủi Ro (M1)

## 1. Danh mục tài sản cần bảo vệ (SEC-01, YC-02)

| Mã tài sản | Tên tài sản / Dữ liệu | Thuộc tính an toàn cần bảo vệ | Hậu quả nếu bị xâm phạm | Cơ chế bảo vệ chính trên Server/DB |
|---|---|---|---|---|
| **AST-01** | Nội dung yêu cầu thanh toán (`amount_vnd`, `beneficiary_version`, `bank/account snapshot`, `purpose`, `source_excerpt`, `revision_number`) | **Toàn vẹn (Integrity)** & **Tính xác thực nguồn tham chiếu** | Sửa đổi số tiền hoặc tài khoản thụ hưởng sau khi gửi/duyệt biến yêu cầu hợp lệ thành chuyển tiền sai đích/sai số tiền (BEC / Invoice Fraud). | Đóng băng `PaymentRevision` khi submit; tính `content_digest` SHA-256 trên canonical JSON; mọi sửa đổi tạo revision mới và vô hiệu hóa phiếu cũ (`T-19`, `T-20`). |
| **AST-02** | Danh tính nhân viên (`EmployeeIdentity`, `person_id`), vai trò (`role`), trạng thái hoạt động và phiên làm việc (`session`, `security_epoch`) | **Tính xác thực (Authenticity)** & **Ủy quyền (Authorization)** | Kẻ giả danh hoặc người dùng vượt quyền tự duyệt yêu cầu, hoặc phiên bị đánh cắp tiếp tục thao tác sau khi phát hiện sự cố. | Bootstrap ngoại tuyến cố định; kiểm tra `person_id` và `role` trên mọi endpoint; tách phiên pre-auth và full MFA; thu hồi tức thì qua `security_epoch` (`T-05..T-11`, `T-25`). |
| **AST-03** | Bí mật xác thực (Mật khẩu băm, `TOTPDevice.bin_key` seed, session key, CSRF token, `ActionChallenge.nonce`) | **Tính bí mật (Confidentiality)** & **Chống phát lại (Anti-Replay)** | Lộ mật khẩu/phiên/seed làm tăng mức độ chiếm quyền tài khoản; lộ nonce/token cho phép giả mạo thao tác. | Password hasher chuẩn của Django; TOTP kiểm tra timestep `last_t` chống dùng lại; `ActionChallenge` TTL 120s dùng 1 lần; lọc tuyệt đối khỏi `AuditEvent` và log (`T-10`, `T-13`, `T-22`, `T-23`, `T-38`). |
| **AST-04** | Quyết định phê duyệt (`Approval`) và Biên nhận thực thi mô phỏng (`PaymentExecution`) | **Toàn vẹn (Integrity)**, **Tính duy nhất (Uniqueness)** & **Không thể chối bỏ trong phạm vi hệ thống** | Phát lại xác nhận cũ, dùng chéo xác nhận giữa các yêu cầu, hoặc chạy đua đồng thời tạo ra nhiều lệnh thực thi cho cùng 1 yêu cầu. | Ràng buộc DB `UniqueConstraint(revision, slot)`, `UniqueConstraint(revision, approver_person_id)`, `OneToOneField(request)` trên `PaymentExecution`; khóa tuần tự `SecurityMutex(id=1)` (`T-16`, `T-17`, `T-29..T-35`). |
| **AST-05** | Danh mục người thụ hưởng (`Beneficiary`, `BeneficiaryVersion`) | **Toàn vẹn nguồn tham chiếu (Reference Integrity)** | Kẻ tấn công lừa thay đổi số tài khoản nhà cung cấp hoặc chèn người nhận chưa xác minh vào yêu cầu thanh toán. | Chỉ cho phép chọn `BeneficiaryVersion` có trạng thái `VERIFIED`; cập nhật tài khoản luôn tạo version mới qua quy trình ngoại tuyến độc lập; kiểm tra lại ở Final Gate (`T-18`, `T-28`). |
| **AST-06** | Nhật ký kiểm toán (`AuditEvent`) và lịch sử phiên bản | **Tính truy vết (Accountability / Traceability)** & **Quyền riêng tư nội bộ** | Không giải thích được ai đã làm gì khi xảy ra sự cố, hoặc lộ lọt thông tin giao dịch nhạy cảm cho người không có thẩm quyền. | Ghi `AuditEvent` cùng transaction với thao tác chính; không có API sửa/xóa log; phân quyền đọc theo vai trò (`REQUESTER` chỉ xem của mình, `SECURITY_ADMIN` xem log an ninh đã ẩn chi tiết thừa) (`T-08`, `T-38`). |
| **AST-07** | Tính sẵn sàng và đúng đắn của quy trình phê duyệt | **Tính khả dụng có kiểm soát (Controlled Availability)** | Kẻ tấn công hoặc lỗi hệ thống làm treo giao dịch hoặc ép hệ thống rơi vào trạng thái mở khóa trái phép (fail-open). | Thiết kế **Fail-Closed** (từ chối an toàn khi thiếu khóa, hết hạn hoặc lỗi giữa chừng); không có đường "duyệt khẩn cấp bỏ qua người thứ hai" (`T-21`, `T-40`). |

---

## 2. Mô hình đối phương và các mức chiếm quyền (SEC-02, SEC-05, TC-02)

Hệ thống phân tích 5 mức đối phương tăng dần về năng lực tấn công (`A1..A5`):

| Mã đối phương | Mô tả năng lực và tài nguyên kẻ tấn công nắm giữ | Mục tiêu tấn công | Khả năng bị chặn và giới hạn bảo vệ của hệ thống | Test chứng minh |
|---|---|---|---|---|
| **A1 — Kẻ giả danh bên ngoài hoặc tài khoản trùng tên** | Có tin nhắn văn bản, ảnh chụp, giọng nói giả mạo Giám đốc Nam yêu cầu chuyển khoản gấp vào số tài khoản lạ; hoặc sở hữu một tài khoản nội bộ không có quyền duyệt nhưng đổi `display_name` trùng hệt Giám đốc Nam. | Lừa kế toán chuyển tiền vào tài khoản giả hoặc tự gọi API phê duyệt nhờ trùng tên hiển thị. | **Bị chặn hoàn toàn**: Tin nhắn chỉ là văn bản `"Nguồn ngoài — chưa xác minh"`; số tài khoản ngoài danh mục `VERIFIED` bị từ chối; phân quyền dựa trên `user.id`, `person_id` và `role` trong DB, không dựa vào `display_name`. | `T-05`, `T-06`, `T-18` |
| **A2 — Kẻ chiếm được mật khẩu (Password Compromise)** | Biết đúng `username` và `password` của Giám đốc Nam (`DIRECTOR`) hoặc Kế toán Lan (`REQUESTER`), nhưng **không** có thiết bị tạo mã TOTP của nạn nhân. | Đăng nhập để xem dữ liệu, tạo yêu cầu giả hoặc phê duyệt/thực thi yêu cầu thanh toán. | **Bị chặn ở bước Pre-Auth**: Chỉ tạo được phiên tạm `preauth` (hạn 5 phút), mọi API nghiệp vụ đều từ chối (`401 MFA_REQUIRED`). Thử đoán OTP quá ngưỡng sẽ bị khóa tạm thời (`429 RATE_LIMITED`). | `T-10`, `T-13` |
| **A3 — Kẻ đánh cắp phiên đăng nhập (Session Hijacking / CSRF)** | Đánh cắp được `sessionid` cookie của phiên đã qua MFA (nhờ XSS nơi khác, lộ cookie máy trạm) hoặc lừa trình duyệt nạn nhân gửi request giả (CSRF), nhưng **không** có mã TOTP mới tại thời điểm thao tác. | Gọi trực tiếp endpoint `approve`, `reject`, `execute-simulated`, `suspend` bằng phiên đang sống, hoặc gửi cờ `mfa_verified=true`. | **Giới hạn thiệt hại**: Kẻ có cookie có thể đọc các trang trong quyền xem của phiên đó khi phiên chưa hết hạn/chưa bị thu hồi, nhưng **không thể** `approve`/`reject`/`execute`/`suspend` vì thiếu `ActionChallenge` + mã TOTP ở timestep mới. CSRF bị chặn bởi token và Origin check. Khi nạn nhân `logout` hoặc admin `revoke-all`, phiên và challenge mở bị hủy ngay. | `T-11`, `T-23`, `T-25`, `T-36` |
| **A4 — Kẻ chiếm hoàn toàn 1 tài khoản duyệt (Full Single Approver Compromise)** | Kiểm soát **toàn bộ** mật khẩu, phiên làm việc và thiết bị/seed TOTP của Giám đốc Nam (`DIRECTOR`), hoặc chính tài khoản đó bị điều khiển. | Tự phê duyệt cả 2 bước hoặc sửa nội dung yêu cầu đã được người kia duyệt sang số tiền/tài khoản khác rồi thực thi. | **Chịu lỗi 1 danh tính (Single-Identity Fault Tolerance)**: Kẻ tấn công **có thể** tạo 1 phiếu hợp lệ ở slot `DIRECTOR` của Nam. Tuy nhiên: (1) Không thể ký thay slot `CONTROLLER` của Hương (`person_id` độc lập); (2) Không thể tự thực thi (`DIRECTOR` không có quyền `execute`); (3) Nếu sửa nội dung yêu cầu thì phiếu của Hương bị hủy hiệu lực ngay. *(Lưu ý: Nếu Hương cũng duyệt thật cùng nội dung đó thì giao dịch có đủ 2 phiếu).* | `T-02`, `T-07`, `T-12`, `T-19`, `T-20` |
| **A5 — Kẻ chiếm quyền tài khoản `SECURITY_ADMIN` ứng dụng** | Kiểm soát hoàn toàn tài khoản `SECURITY_ADMIN` (An) cùng MFA của An. | Tự tạo người duyệt mới, đổi `role` cho đồng bọn, reset MFA của Giám đốc, sửa danh mục `Beneficiary`, hoặc trực tiếp duyệt/thực thi thanh toán. | **Cô lập đặc quyền quản trị**: `SECURITY_ADMIN` chỉ có thể gây gián đoạn tạm thời bằng cách `suspend`/`revoke-all` (dẫn tới trạng thái an toàn `HOLD`), hoàn toàn **không** có chức năng tạo user, đổi `role`, reset MFA, sửa `Beneficiary` hay duyệt/thực thi thanh toán; `/admin/` của Django không được mở cho nghiệp vụ. | `T-09`, `T-14`, `T-15` |

---

## 3. Ma trận Rủi ro – Cơ chế bảo vệ – Giả định – Kiểm thử (SEC-03, SEC-04, YC-04)

| Mã rủi ro | Mô tả rủi ro & Kịch bản tấn công | Điểm kiểm soát bắt buộc phía Server / DB | Giả định tin cậy liên quan | Các Test Case kiểm chứng |
|---|---|---|---|---|
| **R-01: Giả mạo thông tin nguồn ngoài hoặc mạo danh hiển thị** | Kẻ gian gửi tin nhắn giả danh Giám đốc kèm STK mới; hoặc dùng tài khoản nội bộ đặt tên/ảnh giống Giám đốc để duyệt; hoặc gửi trường `role`/`verified` từ client. | 1. Gắn nhãn `"Nguồn ngoài — chưa xác minh"` và escape toàn bộ `source_excerpt`.<br>2. Chỉ nhận `BeneficiaryVersion` có trạng thái `VERIFIED` trong DB.<br>3. Kiểm tra quyền bằng `user.id`, `person_id`, `role` từ DB; từ chối/bỏ qua mọi trường authority do client gửi. | Danh mục `BeneficiaryVersion` `VERIFIED` và hồ sơ `person_id` ban đầu được thiết lập đúng qua quy trình ngoại tuyến. | `T-05`, `T-06`, `T-18`, `T-37` |
| **R-02: Chiếm mật khẩu, chiếm phiên hoặc chiếm hoàn toàn 1 tài khoản duyệt** | Lộ mật khẩu; đánh cắp cookie phiên sau đăng nhập; hoặc kẻ gian chiếm cả mật khẩu lẫn TOTP của 1 người duyệt; hoặc vét cạn (brute-force) mật khẩu/OTP. | 1. Tách phiên `preauth` (5 phút) và phiên đầy đủ sau MFA.<br>2. Bắt buộc Step-Up MFA mới gắn `ActionChallenge` cho mọi quyết định duyệt/thực thi/an ninh.<br>3. Yêu cầu 2 người duyệt độc lập (`DIRECTOR` + `CONTROLLER`) khác `REQUESTER`.<br>4. Throttle mật khẩu và OTP persist vào DB ngay cả khi từ chối.<br>5. Thu hồi tức thì qua `security_epoch`. | Ít nhất 1 trong 2 người duyệt độc lập (`DIRECTOR` hoặc `CONTROLLER`) chưa bị chiếm quyền và thực hiện kiểm tra độc lập. | `T-10`, `T-11`, `T-12`, `T-13`, `T-14`, `T-15`, `T-25`, `T-26`, `T-27` |
| **R-03: Vượt quyền ngang/dọc, tự duyệt, kiêm nhiệm hoặc bỏ qua bước (IDOR / Broken Access Control)** | `REQUESTER` tự duyệt hoặc thực thi khi mới có 1 phiếu; 1 người giữ 2 tài khoản để duyệt cả 2 slot; `REQUESTER` xem/hủy yêu cầu của người khác; gọi thẳng API thực thi bỏ qua UI. | 1. Kiểm tra `request.requester_id == actor.id` cho thao tác của người lập.<br>2. Kiểm tra `approver.person_id != requester.person_id` và `director.person_id != controller.person_id`.<br>3. Kiểm tra object-level scope trên mọi view/API (`GET` lẫn `POST`).<br>4. Final Gate kiểm tra lại toàn bộ điều kiện từ DB dưới khóa. | Mã nguồn máy chủ không bị sửa đổi trái phép. | `T-01`, `T-02`, `T-03`, `T-04`, `T-07`, `T-08`, `T-09`, `T-24` |
| **R-04: Sửa đổi nội dung sau khi gửi/duyệt hoặc đánh tráo ngữ cảnh xác nhận** | Sửa số tiền/tài khoản sau khi đã có 1 phiếu duyệt; lấy `ActionChallenge` của yêu cầu A hoặc của hành động `APPROVE` đem dùng cho yêu cầu B hoặc hành động `EXECUTE`; đổi tài khoản người nhận ngay trước lúc thực thi. | 1. Đóng băng snapshot và tính `content_digest` SHA-256 khi `submit`.<br>2. Chặn sửa trực tiếp revision đã nộp; thao tác `revise` tạo revision mới ở `DRAFT` và hủy hiệu lực mọi phiếu/challenge cũ.<br>3. Ràng buộc `ActionChallenge` với `actor`, `session`, `device`, `epoch`, `action`, `request`, `revision`, `content_digest`, `beneficiary_version`.<br>4. Final Gate kiểm tra lại `beneficiary.active_version` và `content_digest`. | Hàm băm SHA-256 và dữ liệu trong PostgreSQL không bị DBA sửa trực tiếp. | `T-16`, `T-17`, `T-18`, `T-19`, `T-20`, `T-28`, `T-32` |
| **R-05: Phát lại (Replay) xác nhận, dùng lại mã TOTP hoặc dùng xác nhận quá hạn** | Gửi lại `ActionChallenge` đã dùng; dùng lại cùng mã TOTP 6 số vừa đăng nhập để duyệt ngay trong cùng cửa sổ 30 giây; chỉnh đồng hồ máy khách để dùng challenge/request đã hết hạn. | 1. Đánh dấu `consumed_at` nguyên tử cho `ActionChallenge` dưới khóa.<br>2. Lưu và kiểm tra `last_t` (last accepted timestep) trên `TOTPDevice` cho cả đăng nhập và thao tác.<br>3. Kiểm tra `now >= expires_at` hoàn toàn bằng giờ UTC của máy chủ.<br>4. Chặn mọi thay đổi trên các trạng thái kết thúc (`REJECTED`, `CANCELLED`, `EXPIRED`, `EXECUTED_SIMULATED`). | Đồng hồ hệ thống của máy chủ (UTC) hoạt động chính xác. | `T-21`, `T-22`, `T-23`, `T-29`, `T-34` |
| **R-06: Điều kiện tranh chấp đồng thời (Race Conditions) và lỗi ghi một nửa (Partial Write)** | Gửi đồng thời 2 lệnh `execute` (cùng hoặc khác `Idempotency-Key`); duyệt đồng thời với sửa revision hoặc từ chối; thực thi đồng thời với thu hồi tài khoản; lỗi DB xảy ra sau khi tạo `PaymentExecution` nhưng trước khi ghi `AuditEvent`. | 1. Mọi mutation nhạy cảm lấy khóa `SecurityMutex.objects.select_for_update().get(pk=1)` trong `transaction.atomic()` trên PostgreSQL.<br>2. Ràng buộc DB `OneToOneField(request)` trên `PaymentExecution` và `UniqueConstraint` trên `Approval`.<br>3. Xử lý `Idempotency-Key` trả về đúng biên nhận cũ nếu cùng key/actor/payload.<br>4. Ghi `PaymentExecution`, trạng thái request và `AuditEvent` thành công trong cùng 1 transaction. | Cơ sở dữ liệu là PostgreSQL thật với cơ chế row-level locking (`SELECT ... FOR UPDATE`). | `T-30`, `T-31`, `T-32`, `T-33`, `T-34`, `T-35`, `T-40` |
| **R-07: Lạm dụng quyền quản trị hoặc quy trình khôi phục tài khoản làm lối đi vòng** | Dùng `SECURITY_ADMIN` hoặc đường tự khai báo để mở khóa tài khoản, đổi role, reset MFA hoặc làm sống lại các phiếu duyệt cũ sau sự cố. | 1. Không có UI/API tạo user, đổi role, reset MFA hay sửa `Beneficiary`.<br>2. Vô hiệu hóa `/admin/` cho các model nghiệp vụ.<br>3. Công cụ khôi phục ngoại tuyến (`recover_principal`) bắt buộc tăng `security_epoch` và giữ nguyên trạng thái vô hiệu của các phiếu duyệt cũ (buộc tạo revision mới và duyệt lại). | Quản trị viên hệ thống vận hành CLI ngoại tuyến tuân thủ quy trình đối chiếu nhân thân độc lập. | `T-09`, `T-14`, `T-15`, `T-26`, `T-27`, `T-28` |
| **R-08: Tấn công bề mặt Web, lộ bí mật trong nhật ký và cấu hình đường truyền** | Tấn công CSRF; chèn mã độc XSS vào `purpose`/`source_excerpt`; đọc trộm log của người khác hoặc khai thác OTP/seed/session key trong log; nghe lén đường truyền. | 1. Bật `CsrfViewMiddleware`, chỉ cho phép `POST` đối với mutation.<br>2. Escape toàn bộ dữ liệu hiển thị trong template, validate chặt miền dữ liệu VND.<br>3. Kiểm soát quyền đọc `AuditEvent` theo vai trò và không bao giờ ghi secret/OTP/cookie vào log.<br>4. Cung cấp cấu hình HTTPS với chứng chỉ CA riêng của lab và cờ cookie `Secure`, `HttpOnly`, `SameSite=Lax`. | Trình duyệt người dùng không bị cài mã độc đọc trực tiếp DOM. | `T-08`, `T-36`, `T-37`, `T-38`, `T-39` |



---

# Chương 4. Thiết kế kiến trúc hệ thống, Luồng dữ liệu, ERD và Máy trạng thái

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



---

# Chương 5. Thiết kế chi tiết các cơ chế bảo vệ

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



---

# Chương 6. Triển khai Prototype và Điểm thực thi phía máy chủ

- **Cấu trúc ứng dụng Django (`apps/`)**:
  - `apps/common/`: Mô hình khóa tuần tự hóa `SecurityMutex(id=1)` (`SELECT ... FOR UPDATE`), hàm băm chuẩn hóa SHA-256 `compute_revision_digest()`, ngoại lệ chuẩn hóa và kiểm tra cấm chèn trường trái quyền (`assert_no_forbidden_authority_fields`).
  - `apps/accounts/`: Mô hình `EmployeeIdentity` (lưu `person_id`, `role`, `security_epoch`, bộ đếm khóa tạm thời mật khẩu/OTP), xác thực 2 bước tách biệt phiên `pre_auth` với phiên hoàn tất MFA, middleware `SecurityEpochSessionMiddleware` kiểm tra `security_epoch` và thời gian nhàn rỗi trên mọi request, cùng các lệnh CLI ngoại tuyến `bootstrap_lab` và `recover_principal`.
  - `apps/beneficiaries/`: Mô hình `Beneficiary` và `BeneficiaryVersion` bất biến (`PENDING`, `VERIFIED`, `REVOKED`), chỉ quản lý qua lệnh CLI ngoại tuyến tin cậy `manage_beneficiary`.
  - `apps/payments/`: Mô hình `PaymentRequest`, `PaymentRevision` (đóng băng nội dung), `ActionChallenge` (ràng buộc ngữ cảnh 10 thuộc tính, TTL 120s, dùng 1 lần), `Approval` (kiểm tra 2 người duyệt độc lập `DIRECTOR` + `CONTROLLER` khác `person_id` của `REQUESTER`), và `PaymentExecution` (`OneToOneField` chống thực thi kép, Final Gate kiểm tra lại toàn bộ điều kiện sống trước khi commit).
  - `apps/audit/`: Mô hình `AuditEvent` kèm bộ lọc tự động loại bỏ mọi trường nhạy cảm (`password`, `otp_token`, `secret`, `cookie`, `csrf`) và phân quyền đọc theo vai trò.
- **Giới hạn quyền Quản trị viên an ninh (`SECURITY_ADMIN`) và vô hiệu hóa `/admin/`**:
  - Đường dẫn `/admin/` của Django bị gỡ bỏ hoàn toàn khỏi `config/urls.py` (`T-09` trả về HTTP 404).
  - `SECURITY_ADMIN` chỉ truy cập được `/security/users` và `/audit/` (chỉ đọc các sự kiện an ninh đã ẩn số tiền/số tài khoản) và chỉ thực hiện được `SUSPEND` hoặc `REVOKE_ALL` khi có `ADMIN_REVOKE` challenge + mã TOTP mới.

---

# Chương 7. Kiểm thử thực tế (`T-01` .. `T-40`) và Bằng chứng trên PostgreSQL 17

Toàn bộ **40 ca kiểm thử (`T-01` .. `T-40`)** đã được thực thi trên cơ sở dữ liệu **PostgreSQL 17.6 thật** (tuyệt đối không dùng SQLite), bao gồm cả nhóm kiểm thử tranh chấp đồng thời 2 kết nối (`T-30` .. `T-35`), kiểm thử biên thời gian máy chủ (`T-21`), chống dùng lại timestep TOTP (`T-23`), kiểm thử HTTPS TLS với Root CA nội bộ (`T-39`) và kiểm thử rollback nguyên tử khi xảy ra lỗi giữa transaction (`T-40`).

| Mã test | Yêu cầu | Rủi ro | Chế độ | Trạng thái | Kết quả thực tế (`actual`) | Bằng chứng |
|---|---|---|---|---|---|---|
| `T-01` | `GT-01;YC-01;YC-06;YC-07;TC-03;SP-03;SP-04` | `R-03;R-04;R-06` | `planned` | **PASS** | DRAFT -> PENDING_APPROVAL -> APPROVED -> EXECUTED_SIMULATED thanh cong; 2 Approval doc lap (nam, huong) cung revision 1; PaymentExecution count=1 (SIM-RCPT-20261024131111-960525CC). | `evidence/logs/T-01.json; evidence/logs/pytest_full_run.log` |
| `T-02` | `YC-07;SEC-04;TC-03` | `R-03` | `planned` | **PASS** | Khi moi co 1 phieu cua Nam, API xin EXECUTE challenge tra HTTP 409 (MISSING_APPROVAL) va goi thang execute-simulated tra HTTP 409 (MISSING_APPROVAL); Approval count=1, PaymentExecution count=0. | `evidence/logs/T-02.json; evidence/logs/pytest_full_run.log` |
| `T-03` | `YC-07;SEC-04;TC-03` | `R-03;R-04` | `planned` | **PASS** | Huong tu choi dua yeu cau ve REJECTED (HTTP 200); Nam thu xin challenge duyet bi HTTP 409 (TERMINAL_STATE), Lan thu execute bi HTTP 409 (TERMINAL_STATE); trang thai giu nguyen REJECTED, PaymentExecution=0. | `evidence/logs/T-03.json; evidence/logs/pytest_full_run.log` |
| `T-04` | `YC-07;SEC-02;SEC-04` | `R-03` | `planned` | **PASS** | Minh thu huy R1 cua Lan bi HTTP 403 (FORBIDDEN); Lan huy thanh cong HTTP 200 -> CANCELLED; Nam thu duyet tiep bi HTTP 409. | `evidence/logs/T-04.json; evidence/logs/pytest_full_run.log` |
| `T-05` | `GT-01;SEC-02;SEC-05;YC-05;YC-07;TC-01` | `R-01` | `planned` | **PASS** | Tai khoan nam_lookalike (display_name='Nguyễn Văn Nam (Giám đốc)', person_id='PER-FAKE-006') xin challenge APPROVE_DIRECTOR bi HTTP 403 (FORBIDDEN); Approval count=0; AuditEvent ghi nhan actor=nam_lookalike (PER-FAKE-006). | `evidence/logs/T-05.json; evidence/logs/pytest_full_run.log` |
| `T-06` | `SEC-02;YC-07;TC-01` | `R-01;R-03` | `planned` | **PASS** | Payload chua role/verified/status/approver_id bi tu choi voi HTTP 400 (FORBIDDEN); role cua Lan giu nguyen REQUESTER; khong tao request sai. | `evidence/logs/T-06.json; evidence/logs/pytest_full_run.log` |
| `T-07` | `SEC-02;SEC-04;YC-07` | `R-03` | `planned` | **PASS** | Lan thu tu duyet (ke ca khi fixture gan role DIRECTOR) bi HTTP 403 (SELF_APPROVAL); Nam thu duyet lan 2 chiem 2 slot bi HTTP 409 (DUPLICATE_APPROVER); Approval count=1. | `evidence/logs/T-07.json; evidence/logs/pytest_full_run.log` |
| `T-08` | `SEC-01;SEC-02;YC-07` | `R-03;R-08` | `planned` | **PASS** | Lan truy cap R2 cua Minh bi chan tren moi endpoint: detail=403, revise=403, cancel=403, receipt=403; khong ro ri noi dung R2. | `evidence/logs/T-08.json; evidence/logs/pytest_full_run.log` |
| `T-09` | `SEC-02;SEC-04;YC-07` | `R-03;R-07` | `planned` | **PASS** | SecurityAdmin An bi tu choi moi thao tac tai chinh: create=403, challenge_approve=403, execute=403; duong dan /admin/ bi chan HTTP 403 (PROHIBITED_ROUTE_ATTEMPT). | `evidence/logs/T-09.json; evidence/logs/pytest_full_run.log` |
| `T-10` | `SEC-02;SEC-05;YC-07;TC-02` | `R-02` | `planned` | **PASS** | Sau buoc mat khau (/auth/login -> MFA_REQUIRED), phien pre-auth goi /challenges bi chan HTTP 401 (MFA_REQUIRED); Approval count=0. | `evidence/logs/T-10.json; evidence/logs/pytest_full_run.log` |
| `T-11` | `SEC-02;SEC-05;YC-05;YC-07;TC-02` | `R-02` | `planned` | **PASS** | Phien bi danh cap gui mfa_verified=true nhung thieu OTP bi HTTP 400; sau logout, challenge co invalidated_at != None, security_epoch giu nguyen (1), goi lai bang phien cu bi HTTP 401. | `evidence/logs/T-11.json; evidence/logs/pytest_full_run.log` |
| `T-12` | `GT-01;SEC-02;SEC-05;YC-05;YC-07;TC-02` | `R-02` | `planned` | **PASS** | Tai khoan Nam bi chiem toan bo chi tao duoc 1 phieu DIRECTOR; thu xin challenge APPROVE_CONTROLLER bi HTTP 403; Lan thu xin EXECUTE challenge bi HTTP 409 (MISSING_APPROVAL); PaymentExecution=0. | `evidence/logs/T-12.json; evidence/logs/pytest_full_run.log` |
| `T-13` | `SEC-02;SEC-05;YC-07` | `R-02` | `planned` | **PASS** | 5 lan nhap OTP sai tren session 1 tang failed_otp_attempts=5 va dat otp_throttled_until; doi sang session 2 va challenge moi van bi chan HTTP 429 (RATE_LIMITED); sau khi het thoi gian cho, Nam xac thuc lai thanh cong (HTTP 200). | `evidence/logs/T-13.json; evidence/logs/pytest_full_run.log` |
| `T-14` | `SEC-02;SEC-05;YC-07` | `R-02;R-07` | `planned` | **PASS** | Moi duong dan tu doi MFA factor/role qua HTTP deu bi chan HTTP 403 ({'/auth/reset-mfa': 403, '/reset-mfa': 403, '/auth/change-factor': 403, '/auth/change-role': 403}); TOTPDevice va security_epoch (1) giu nguyen. | `evidence/logs/T-14.json; evidence/logs/pytest_full_run.log` |
| `T-15` | `SEC-02;SEC-05;YC-07` | `R-02;R-07` | `planned` | **PASS** | SecurityAdmin dinh chi Nam -> R1 chuyen sang HOLD, phieu cu bi INVALIDATED_BY_INCIDENT; thu mo lai quyen qua HTTP /unsuspend bi chan 403; chay CLI tin cay recover_principal tang security_epoch tu 1 -> 3, phien cu bi chan HTTP 401, phieu cu khong tu hoi sinh. | `evidence/logs/T-15.json; evidence/logs/pytest_full_run.log` |
| `T-16` | `SEC-04;YC-05;YC-07` | `R-04` | `planned` | **PASS** | Challenge C1 cap cho Nam khi bi Huong su dung (kem OTP hop le cua Huong) bi tu choi HTTP 403 (WRONG_SCOPE); Approval count=0. | `evidence/logs/T-16.json; evidence/logs/pytest_full_run.log` |
| `T-17` | `SEC-04;YC-05;YC-07` | `R-04` | `planned` | **PASS** | Challenge APPROVE_DIRECTOR R1 dung sang R2 bi HTTP 409 (WRONG_SCOPE); dung sang REJECT R1 bi HTTP 409 (WRONG_SCOPE). | `evidence/logs/T-17.json; evidence/logs/pytest_full_run.log` |
| `T-18` | `SEC-04;YC-05;YC-07;TC-02` | `R-01;R-04` | `planned` | **PASS** | Tao yeu cau voi BEN-003 (PENDING) bi HTTP 400 (BENEFICIARY_INVALID), BEN-004 (REVOKED) bi HTTP 400 (BENEFICIARY_INVALID), chen account_number_override tu khai bi HTTP 400 (FORBIDDEN); Request count=0. | `evidence/logs/T-18.json; evidence/logs/pytest_full_run.log` |
| `T-19` | `SEC-01;SEC-04;YC-05;YC-07;TC-02` | `R-04` | `planned` | **PASS** | Cap nhat truc tiep vao /requests/<id>/edit khi revision 1 da dong bang bi HTTP 409 (IMMUTABLE_REVISION); amount_vnd=20000000 va content_digest=adb29a326e057a8a... giu nguyen. | `evidence/logs/T-19.json; evidence/logs/pytest_full_run.log` |
| `T-20` | `GT-01;SEC-01;SEC-04;YC-05;YC-07` | `R-04` | `planned` | **PASS** | Lan tao revision 2 dua yeu cau ve DRAFT; phieu duyet rev 1 cua Nam chuyen sang status='SUPERSEDED_BY_REVISION', challenge cua Huong co invalidated_at != None; thu dung lai challenge cu cho rev 2 bi HTTP 409 (WRONG_SCOPE). | `evidence/logs/T-20.json; evidence/logs/pytest_full_run.log` |
| `T-21` | `SEC-04;YC-05;YC-07` | `R-05` | `planned` | **PASS** | Tai now = expires_at - 1s (2026-10-24T13:15:29.470568+00:00), C1 duoc chap nhan; tai now == expires_at (2026-10-24T13:15:30.470568+00:00) va now = expires_at + 5s (2026-10-24T13:15:35.470568+00:00), C2 bi tu choi voi CHALLENGE_EXPIRED; Approval count cho R2 = 0. | `evidence/logs/T-21.json; evidence/logs/pytest_full_run.log` |
| `T-22` | `SEC-04;YC-05;YC-07` | `R-05` | `planned` | **PASS** | Phat lai challenge da tieu thu bi HTTP 409, consumed_at giu nguyen; retry idempotent cung key IDEMP-T22-KEY tra cung bien nhan SIM-RCPT-20261024131158-20F26668 voi PaymentExecution count=1. | `evidence/logs/T-22.json; evidence/logs/pytest_full_run.log` |
| `T-23` | `SEC-04;YC-05;YC-07` | `R-05` | `planned` | **PASS** | Sau khi ma TOTP cua Nam duoc chap nhan cho R1 (device.last_t=59761587), dung lai cung ma/timestep cho challenge C2 tren R2 bi tu choi voi OTP_REPLAY; Approval count tren R2 = 0. | `evidence/logs/T-23.json; evidence/logs/pytest_full_run.log` |
| `T-24` | `SEC-02;SEC-04;YC-07` | `R-03` | `planned` | **PASS** | Goi thang execute-simulated kem approval_ids/status tu khai bi HTTP 400 (FORBIDDEN); nguoi duyet Nam goi xin challenge EXECUTE bi HTTP 403 (FORBIDDEN); PaymentExecution count=0. | `evidence/logs/T-24.json; evidence/logs/pytest_full_run.log` |
| `T-25` | `GT-01;SEC-02;SEC-05;YC-07` | `R-02` | `planned` | **PASS** | Sau khi SecurityAdmin dinh chi Nam, R1 chuyen sang trang thai HOLD; Lan thu execute bang challenge da cap truoc do bi chan HTTP 409 (PRINCIPAL_REVOKED); PaymentExecution count=0. | `evidence/logs/T-25.json; evidence/logs/pytest_full_run.log` |
| `T-26` | `SEC-05;YC-07` | `R-02;R-07` | `planned` | **PASS** | Khi role cua Nam bi doi tu DIRECTOR sang REQUESTER truoc khi execute, Final Gate phat hien role hien tai khong khop, chuyen R1 sang HOLD va tra HTTP 409 (PRINCIPAL_REVOKED); PaymentExecution count=0. | `evidence/logs/T-26.json; evidence/logs/pytest_full_run.log` |
| `T-27` | `SEC-05;YC-07` | `R-02;R-07` | `planned` | **PASS** | Reset/rotate TOTP factor cua Nam qua recover_principal tang security_epoch (1 -> 2), dua R1 sang HOLD, chan phien cu HTTP 401 va chan Lan execute HTTP 409. | `evidence/logs/T-27.json; evidence/logs/pytest_full_run.log` |
| `T-28` | `SEC-05;YC-07` | `R-04;R-07` | `planned` | **PASS** | Khi BEN-001 duoc cap nhat sang version 2 truoc luc execute, Final Gate phat hien revision 1 gan voi version 1 da cu, tra HTTP 409 (PRINCIPAL_REVOKED) va khong tu dong chuyen sang tai khoan moi (PaymentExecution=0). | `evidence/logs/T-28.json; evidence/logs/pytest_full_run.log` |
| `T-29` | `SEC-04;YC-07` | `R-05` | `planned` | **PASS** | Sau khi R1 dat EXECUTED_SIMULATED (SIM-RCPT-20261024131216-BBA22C18), revise=409, cancel=409, reject_challenge=409, execute voi key moi=409; PaymentExecution count=1 khong doi. | `evidence/logs/T-29.json; evidence/logs/pytest_full_run.log` |
| `T-30` | `SEC-04;YC-07;YC-08` | `R-06` | `planned` | **PASS** | Hai worker PostgreSQL doc lap cung gui idempotency_key='IDEMP-T30-SAME' qua Barrier(2): 1 worker tao moi (is_replay=False), 1 worker nhan ket qua idempotent (is_replay=True), cung receipt=SIM-RCPT-20261024131354-3FEAD71D, PaymentExecution COUNT=1. | `evidence/logs/T-30.json; evidence/logs/pytest_full_run.log` |
| `T-31` | `SEC-04;YC-07` | `R-06` | `planned` | **PASS** | Hai worker PostgreSQL doc lap voi 2 idempotency_key khac nhau (IDEMP-T31-KEY-A, IDEMP-T31-KEY-B) va 2 challenge/timestep hop le cung tranh chap R1: 1 worker EXECUTED, 1 worker REJECTED (IDEMPOTENCY_CONFLICT); PaymentExecution COUNT=1. | `evidence/logs/T-31.json; evidence/logs/pytest_full_run.log` |
| `T-32` | `SEC-04;YC-07` | `R-04;R-06` | `planned` | **PASS** | Ca 2 thu tu khoa tren PostgreSQL deu an toan: Order A (revise truoc -> approve cu bi tu choi WRONG_SCOPE); Order B (approve truoc -> revise sau vo hieu phieu cu va dua ve DRAFT); khong co phieu cu nao con ACTIVE cho revision 2. | `evidence/logs/T-32.json; evidence/logs/pytest_full_run.log` |
| `T-33` | `SEC-04;YC-07` | `R-06` | `planned` | **PASS** | Ca 2 thu tu tranh chap approve/reject deu ket thuc REJECTED va PaymentExecution=0: Case 1={'huong': 'REJECTED', 'nam': 'TERMINAL_STATE'}, Case 2={'nam': 'APPROVED_SLOT_1', 'huong': 'REJECTED'}. | `evidence/logs/T-33.json; evidence/logs/pytest_full_run.log` |
| `T-34` | `SEC-04;YC-07` | `R-05;R-06` | `planned` | **PASS** | Hai ket noi PostgreSQL cung gui 1 ma TOTP cua Nam cho 2 challenge (R1 va R2) qua Barrier(2): ket qua ['APPROVED', 'OTP_REPLAY']; tong Approval cua Nam tang dung 1. | `evidence/logs/T-34.json; evidence/logs/pytest_full_run.log` |
| `T-35` | `SEC-04;YC-07` | `R-06` | `planned` | **PASS** | Subcase 1 (revoke commit truoc execute): R1 chuyen HOLD, execute bi chan (PRINCIPAL_REVOKED), Execution=0; Subcase 2 (execute commit truoc revoke): R2 ghi nhan 1 bien nhan SIM-RCPT-20261024131602-D930F3F5, revoke sau do tang epoch nhung khong xoa lich su/bien nhan da commit. | `evidence/logs/T-35.json; evidence/logs/pytest_full_run.log` |
| `T-36` | `SEC-04;YC-07` | `R-08` | `planned` | **PASS** | Voi enforce_csrf_checks=True: POST thieu CSRF bi HTTP 403, Origin la bi HTTP 403, dung CSRF+Origin hop le tra HTTP 201; GET tren /submit, /approve, /execute-simulated deu tra HTTP 405. | `evidence/logs/T-36.json; evidence/logs/pytest_full_run.log` |
| `T-37` | `SEC-04;YC-07` | `R-08` | `planned` | **PASS** | Cac gia tri VND sai (0, am, so thap phan, vuot 1e12) deu bi chan HTTP 400 ([400, 400, 400, 400, 400]); noi dung <script> va <img onerror> trong purpose/source_excerpt duoc escape an toan (&lt;script&gt;...) va gan nhan 'Nguon ngoai — chua xac minh'. | `evidence/logs/T-37.json; evidence/logs/pytest_full_run.log` |
| `T-38` | `SEC-01;SEC-04;YC-07` | `R-08` | `planned` | **PASS** | Lan khong thay su kien cua Minh tren /audit; SecurityAdmin An chi thay metadata da loc (khong co amount_vnd/beneficiary_account); POST/DELETE /audit bi chan HTTP 403; quet toan bo AuditEvent khong chua secret_marker hay TOTP seed. | `evidence/logs/T-38.json; evidence/logs/pytest_full_run.log` |
| `T-39` | `YC-03;YC-07` | `R-08` | `planned` | **PASS** | Xac minh HTTPS profile voi Lab Root CA (ssl.CERT_REQUIRED, check_hostname=True): ket noi TLSv1.3 thanh cong tren https://127.0.0.1:34543/auth/login (HTTP 200), Set-Cookie co Secure va SameSite=Lax; trang loi 403 khong lo SECRET_KEY. | `evidence/logs/T-39.json; evidence/logs/pytest_full_run.log` |
| `T-40` | `SEC-04;YC-07` | `R-06` | `planned` | **PASS** | Khi chen loi RuntimeError giua transaction execute_payment_request_simulated, PostgreSQL rollback toan bo: PaymentExecution=0, status giu nguyen APPROVED, challenge chua consumed, AuditEvent SUCCESS=0; sau khi bo loi va thu lai, giao dich thanh cong voi 1 bien nhan SIM-RCPT-20261024131452-760F644B. | `evidence/logs/T-40.json; evidence/logs/pytest_full_run.log` |

---

# Chương 8. Phân tích Đánh đổi (Trade-off) Ngắn hạn và Dài hạn

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


---

# Chương 9. Giới hạn của hệ thống và Quy trình xử lý sự cố

1. **Một tài khoản bị chiếm so với nhiều chủ thể thông đồng hoặc bị chiếm đồng thời**:
   - Hệ thống ngăn chặn thành công kịch bản kẻ tấn công chiếm trọn 01 tài khoản người duyệt (`T-12`) hoặc chiếm phiên làm việc của người lập/người duyệt (`T-10`, `T-11`).
   - Tuy nhiên, nếu cả hai người duyệt (`DIRECTOR` và `CONTROLLER`) cùng thông đồng hoặc cùng bị chiếm thiết bị MFA và mật khẩu đồng thời với người lập, hệ thống phần mềm không thể tự phân biệt với thao tác hợp lệ.
2. **Nguy cơ người duyệt xác nhận nhầm nội dung sai ngay từ đầu**:
   - Mã băm `content_digest` đảm bảo nội dung không bị thay đổi sau khi duyệt (`T-19`, `T-20`), nhưng không thay thế được trách nhiệm kiểm tra chứng từ gốc của người duyệt trước khi nhập mã TOTP.
3. **Máy chủ hoặc Quản trị cơ sở dữ liệu (DBA/OS root) bị chiếm quyền**:
   - Trong phạm vi bài lab, máy chủ ứng dụng Django, tiến trình PostgreSQL 17 và môi trường thực thi CLI ngoại tuyến nằm trong ranh giới tin cậy (Trusted Computing Base). Nhật ký `AuditEvent` chống sửa/xóa từ giao diện web/API (`T-38`), nhưng không bất biến trước người nắm quyền quản trị trực tiếp trên PostgreSQL.
4. **Quy trình ứng phó và khôi phục sự cố**:
   - **Bước 1 (Cô lập tức thì trên giao diện an ninh)**: `SECURITY_ADMIN` đăng nhập MFA, tạo `ADMIN_REVOKE` challenge và thực hiện `SUSPEND` hoặc `REVOKE_ALL` đối với tài khoản nghi bị lộ -> Tăng `security_epoch`, hủy mọi phiên và challenge đang mở, đồng thời chuyển toàn bộ yêu cầu thanh toán liên quan chưa thực thi sang trạng thái `HOLD` (`T-25`, `D-04`).
   - **Bước 2 (Khôi phục ngoại tuyến có kiểm soát)**: Sau khi xác minh danh tính nhân sự ngoài đời thực, quản trị viên hệ thống chạy lệnh `python manage.py recover_principal --username <user> --rotate-totp --reason "..."` để cấp lại mật khẩu và hạt giống TOTP mới (`T-15`, `T-27`). Các yêu cầu đang ở `HOLD` bắt buộc phải được người lập rà soát, tạo revision mới và xin phê duyệt lại từ đầu.

---

# Chương 10. Kết luận và Hướng phát triển tiếp theo

- **Kết luận trong phạm vi đã chứng minh**: Đồ án đã xây dựng hoàn chỉnh prototype `securepay_lab` trên Django 5.2 và PostgreSQL 17, thực thi đầy đủ 10 quyết định thiết kế (`DES-01..DES-10`), vượt qua toàn bộ **40/40 ca kiểm thử (`T-01..T-40`)** và **04 kịch bản trình diễn (`D-01..D-04`)** với bằng chứng thực tế không chứa bí mật.
- **Hướng phát triển tiếp theo ngoài phạm vi prototype**:
  - Hỗ trợ khóa xác thực phần cứng chống phishing (FIDO2/WebAuthn với chữ ký gắn dữ liệu giao dịch).
  - Tách khóa tuần tự hóa theo từng bản ghi (`Principal -> Beneficiary -> PaymentRequest`) để nâng cao thông lượng đồng thời.
  - Đẩy nhật ký kiểm toán thời gian thực sang kho lưu trữ bất biến (WORM/SIEM độc lập) kèm chuỗi băm ký số ngoài máy chủ ứng dụng.

---

# Phụ lục A. Ma trận Truy vết Yêu cầu (`traceability.csv`)

| Mã | Nguồn đặc tả | Thành phần triển khai | Ca kiểm thử | Bằng chứng | Trạng thái | Giới hạn phạm vi |
|---|---|---|---|---|---|---|
| `GT-01` | Muc tieu do an (Phu luc 19); §1, §2.1 | `docs/01_scope.md; docs/04_security_design.md; apps/payments/services.py` | `T-01;T-05;T-12;T-20;T-25` | `docs/01_scope.md; docs/04_security_design.md` | **DONE** | Chi xac minh va phe duyet trong he thong noi bo mo phong; khong phat hien deepfake va khong ket noi ngan hang that. |
| `SEC-01` | Huong 1 - Cau hoi 1 (Phu luc 19); §2.1, §4.1 | `docs/02_threat_model.md; docs/03_architecture.md; apps/` | `T-08;T-19;T-20;T-38` | `docs/02_threat_model.md; docs/diagrams/03_erd.svg` | **DONE** | Bao ve toan ven va truy vet o tang ung dung/DB; khong chong duoc DBA doc hai sua truc tiep tren may chu DB. |
| `SEC-02` | Huong 1 - Cau hoi 2 (Phu luc 19); §2.1, §4.2, §6.1 | `docs/02_threat_model.md; docs/04_security_design.md` | `T-05;T-06;T-07;T-08;T-09;T-10;T-11;T-12;T-13;T-14;T-15` | `docs/02_threat_model.md; docs/04_security_design.md` | **DONE** | Mo hinh 4 vai tro co dinh va 5 muc doi phuong A1..A5; khong bao gom truong hop ca 2 nguoi duyet cung thong dong. |
| `SEC-03` | Huong 1 - Cau hoi 3 (Phu luc 19); §2.1, §4.2, §4.3 | `docs/02_threat_model.md; tests/` | `T-01..T-40` | `docs/02_threat_model.md` | **DONE** | Tap trung vao 8 nhom rui ro R-01..R-08 trong quy trinh xac minh thanh toan noi bo. |
| `SEC-04` | Huong 1 - Cau hoi 4 (Phu luc 19); §2.1, §5-§10 | `docs/04_security_design.md; apps/` | `T-01..T-40` | `docs/04_security_design.md; docs/decisions.md` | **DONE** | TOTP xac minh yeu to thiet bi kem ActionChallenge gan ngu canh, khong phai chu ky so phan cung. |
| `SEC-05` | Huong 1 - Cau hoi 5 (Phu luc 19); §2.1, §4.2, §10.1 | `docs/02_threat_model.md; docs/04_security_design.md; docs/diagrams/07_seq_compromise_revocation.mmd` | `T-05;T-10;T-11;T-12;T-13;T-14;T-15;T-25;T-26;T-27;T-28` | `docs/02_threat_model.md; docs/diagrams/07_seq_compromise_revocation.svg` | **DONE** | Mot tai khoan duyet bi chiem hoan toan van bi chan boi nguoi duyet doc lap thu hai; neu ca hai cung bi chiem hoac duyet nham thi nam ngoai bao dam. |
| `YC-01` | Yeu cau chung 1 (Phu luc 19); §1, §2.2, §3 | `docs/01_scope.md; README.md` | `T-01` | `docs/01_scope.md` | **DONE** | Doanh nghiep gia lap Minh Phat Lab voi du lieu va giao dich mo phong. |
| `YC-02` | Yeu cau chung 2 (Phu luc 19); §2.2, §4 | `docs/02_threat_model.md; docs/01_scope.md` | `T-05..T-40` | `docs/02_threat_model.md` | **DONE** | Phan tich tai san va rui ro trong pham vi ung dung web noi bo va PostgreSQL. |
| `YC-03` | Yeu cau chung 3 (Phu luc 19); §2.2, §5, §6, §7 | `docs/03_architecture.md; docs/diagrams/01_architecture.mmd; docs/diagrams/02_dfd_trust_boundaries.mmd` | `T-01;T-39` | `docs/03_architecture.md; docs/diagrams/01_architecture.svg; docs/diagrams/02_dfd_trust_boundaries.svg` | **DONE** | Kien truc monolith Django + PostgreSQL phu hop quy mo do an cuoi ky. |
| `YC-04` | Yeu cau chung 4 (Phu luc 19); §2.2, §4.3, §7 | `docs/04_security_design.md; apps/` | `T-01..T-40` | `docs/04_security_design.md; docs/decisions.md` | **DONE** | Moi co che deu gan voi rui ro R-01..R-08 va ca kiem thu cu the. |
| `YC-05` | Yeu cau chung 5 (Phu luc 19); §2.2, §12, §13 | `docs/04_security_design.md; docs/diagrams/06_seq_tamper_replay.mmd; tests/` | `T-05;T-11;T-12;T-16;T-17;T-18;T-19;T-20;T-21;T-22;T-23` | `docs/diagrams/06_seq_tamper_replay.svg` | **DONE** | Mo phong tin nhan gia, sua noi dung, danh cap phien/tai khoan va dung sai ngu canh challenge/OTP. |
| `YC-06` | Yeu cau chung 6 (Phu luc 19); §2.2, §5, §9 | `config/; apps/; templates/; static/; manage.py` | `T-01` | `docs/03_architecture.md` | **DONE** | Prototype thuc thi luong tao-duyet-thuc thi mo phong tren PostgreSQL, khong goi ngan hang that. |
| `YC-07` | Yeu cau chung 7 (Phu luc 19); §2.2, §12 | `tests/; evidence/test_results.csv` | `T-01..T-40` | `evidence/test_results.csv` | **DONE** | Trang thai khoi dau cua T-01..T-40 la NOT_RUN cho toi khi chay that tren PostgreSQL o M3-M7. |
| `YC-08` | Yeu cau chung 8 (Phu luc 19); §2.2, §14 | `docs/05_tradeoffs.md` | `T-01;T-12;T-21;T-30` | `docs/decisions.md` | **DONE** | So lieu do thuc nghiem tren moi truong lab; chi phi nhan su/van hanh dai han la uoc luong co gia dinh. |
| `TC-01` | Diem quan trong 1 (Phu luc 19); §1, §2.3, §4.4 | `docs/01_scope.md; docs/02_threat_model.md; templates/payments/; apps/payments/services.py` | `T-05;T-06` | `docs/01_scope.md; docs/02_threat_model.md` | **DONE** | He thong khong tin ten hien thi, anh dai dien hay truong tu khai tu client. |
| `TC-02` | Diem quan trong 2 (Phu luc 19); §2.3, §4.2, §4.4 | `docs/02_threat_model.md; apps/payments/models.py; apps/payments/services.py` | `T-10;T-11;T-12;T-18;T-19` | `docs/02_threat_model.md` | **DONE** | Tin nhan ben ngoai va ca tai khoan that bi chiem deu duoc xem la dau vao co the bi gia mao/thay doi. |
| `TC-03` | Diem quan trong 3 (Phu luc 19); §2.3, §7, §8, §10 | `docs/04_security_design.md; apps/audit/models.py; apps/payments/services.py` | `T-01..T-40` | `docs/04_security_design.md; docs/decisions.md` | **DONE** | Moi quyet dinh chap nhan hoac tu choi deu dua tren kiem tra server-side va luu reason_code trong AuditEvent. |
| `SP-01` | San pham nop 1 (Phu luc 19); §2.3, §15.1 | `deliverables/Bao_cao_De_tai_5.docx; scripts/generate_deliverables.py` | `` | `docs/01_scope.md; docs/02_threat_model.md; docs/03_architecture.md; docs/04_security_design.md` | **DONE** | Bao cao DOCX se duoc tao sau khi co ket qua chay test va demo that o M7-M9. |
| `SP-02` | San pham nop 2 (Phu luc 19); §2.3, §15 | `docs/diagrams/*.mmd; docs/diagrams/*.svg; docs/diagrams/*.png; scripts/render_diagrams.py` | `` | `docs/diagrams/01_architecture.svg; docs/diagrams/02_dfd_trust_boundaries.svg; docs/diagrams/03_erd.svg; docs/diagrams/04_state_machine.svg; docs/diagrams/05_seq_normal_flow.svg; docs/diagrams/06_seq_tamper_replay.svg; docs/diagrams/07_seq_compromise_revocation.svg` | **DONE** | Da xuat day du 7 so do .mmd kem ban xem duoc .svg va .png; se kiem tra dong bo lan cuoi o M9. |
| `SP-03` | San pham nop 3 (Phu luc 19); §2.3, §5.4, §15.3 | `securepay_lab/; compose.yaml; requirements.lock; README.md` | `T-01..T-40` | `docs/03_architecture.md` | **DONE** | Source code va prototype se duoc xay dung tu M2 den M6. |
| `SP-04` | San pham nop 4 (Phu luc 19); §2.3, §12, §15 | `tests/; evidence/test_results.csv; evidence/index.md` | `T-01..T-40` | `evidence/test_results.csv` | **DONE** | Toan bo 40 test case hien dang o trang thai NOT_RUN. |
| `SP-05` | San pham nop 5 (Phu luc 19); §2.3, §13, §15.2 | `deliverables/Slide_De_tai_5.pptx; deliverables/Kich_ban_demo.md; scripts/run_demos.py` | `T-01;T-05;T-12;T-20;T-25;T-30` | `docs/01_scope.md` | **DONE** | Slide PPTX va kich ban demo D-01..D-04 se duoc hoan thien o M8-M9. |

---

# Phụ lục B. Hướng dẫn Cài đặt, Vận hành và Kịch bản Demo (`D-01` .. `D-04`)

# Kịch bản Trình diễn (Demo Script) Có thể Tái lập — Đề tài 5 (`D-01` .. `D-04`)

Tài liệu này hướng dẫn từng bước trình diễn trực tiếp trên trình duyệt (hoặc chạy tự động qua `scripts/run_demos_and_capture.py`) trên cơ sở dữ liệu **PostgreSQL 17 thật**, kèm các câu lệnh kiểm chứng trạng thái DB và đáp án cho các câu hỏi phản biện trọng tâm.

---

## Chuẩn bị trước buổi trình diễn

1. Khởi động PostgreSQL 17 và làm mới dữ liệu chuẩn:
   ```powershell
   .\.venv\Scripts\python.exe manage.py bootstrap_lab --reset
   .\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
   ```
2. Mở tệp cục bộ `private/demo_credentials.json` trên máy trình chiếu (không chiếu tệp này lên màn hình chung) để lấy mật khẩu và cấu hình TOTP cho 4 cửa sổ trình duyệt ẩn danh độc lập (tách biệt cookie phiên):
   - **Cửa sổ 1**: `lan` (`REQUESTER` — Người lập yêu cầu)
   - **Cửa sổ 2**: `nam` (`DIRECTOR` — Người duyệt 1)
   - **Cửa sổ 3**: `huong` (`CONTROLLER` — Người duyệt 2)
   - **Cửa sổ 4**: `an` (`SECURITY_ADMIN` — Quản trị an ninh) / `nam_fake` (Tài khoản trùng tên sếp)
3. Để tái lập tự động toàn bộ 4 kịch bản và xuất lại ảnh chụp bằng chứng vào `evidence/demos/`:
   ```powershell
   .\.venv\Scripts\python.exe .\scripts\run_demos_and_capture.py
   ```

---

## Kịch bản `D-01` — Yêu cầu thật được xác nhận bởi 2 người duyệt độc lập và thực hiện đúng 1 lần

- **Mục tiêu chứng minh**: Luồng chuẩn `DRAFT -> PENDING_APPROVAL -> APPROVED -> EXECUTED_SIMULATED`; 1 phiếu chưa thể thực thi; chỉ `REQUESTER` gốc mới thực thi được bằng `EXECUTE` challenge + TOTP mới; gửi lại cùng `idempotency_key` trả về đúng biên nhận cũ mà không nhân đôi giao dịch.
- **Các bước thực hiện & Kết quả thực tế đã ghi nhận**:
  1. `lan` tạo yêu cầu `REQ-20261024-0001-21F3` số tiền `20,000,000 VND` tới `BEN-001` và bấm **Nộp yêu cầu**. Chỉ ra mã băm đóng băng `content_digest = 6d5b90f0c7b286a7c9e0ab2c...`.
  2. `nam` (`DIRECTOR`) đăng nhập MFA, xin `APPROVE` challenge và nhập mã TOTP mới để duyệt phiếu thứ nhất.
  3. `lan` thử yêu cầu `EXECUTE` challenge khi mới có 1 phiếu -> Máy chủ chặn với **HTTP `409` (`MISSING_APPROVAL`)**.
  4. `huong` (`CONTROLLER`) đăng nhập MFA, xin `APPROVE` challenge và nhập TOTP mới để duyệt phiếu thứ hai -> Trạng thái chuyển sang `APPROVED`.
  5. `lan` xin `EXECUTE` challenge mới, nhập TOTP mới và thực thi mô phỏng với `idempotency_key = "DEMO-D01-KEY-001"` -> Sinh biên nhận **`SIM-RCPT-20261024131246-08BBBE5F`**.
  6. Gửi lại yêu cầu thực thi cùng `idempotency_key = "DEMO-D01-KEY-001"` -> Trả về biên nhận cũ `SIM-RCPT-20261024131246-08BBBE5F` (`idempotent_retry = True`), tổng số bản ghi `PaymentExecution` trong PostgreSQL vẫn bằng **`1`**.
- **Bằng chứng lưu trữ**: [`evidence/demos/D-01_valid_flow.png`](../evidence/demos/D-01_valid_flow.png), [`evidence/demos/D-01_summary.json`](../evidence/demos/D-01_summary.json).

---

## Kịch bản `D-02` — Giả danh tên/ảnh sếp và một tài khoản duyệt bị chiếm hoàn toàn vẫn không thể rút tiền

- **Mục tiêu chứng minh**: Quyền hạn dựa trên `user.id`, `role`, `person_id` đã bootstrap chứ không dựa trên `display_name` hay avatar; phiên đăng nhập bị đánh cắp không thay thế được xác thực thao tác mới; kẻ tấn công chiếm trọn 1 tài khoản người duyệt (cả mật khẩu + TOTP của `nam`) vẫn bị chặn bởi nguyên tắc 2 người duyệt độc lập.
- **Các bước thực hiện & Kết quả thực tế đã ghi nhận**:
  1. `lan` tạo yêu cầu `REQ-20261024-0001-90B5` (`85,000,000 VND`) kèm trích dẫn tin nhắn nguồn ngoài. Giao diện hiển thị rõ nhãn cảnh báo **`Nguồn ngoài — chưa xác minh`**.
  2. Đăng nhập tài khoản `nam_fake` (có tên hiển thị `Trần Văn Nam` và avatar `TN` giống hệt Giám đốc Nam) rồi gọi API xin challenge duyệt -> Bị chặn **HTTP `403` (`FORBIDDEN`)**.
  3. Dùng phiên đã đăng nhập của `nam` nhưng gửi yêu cầu duyệt thiếu mã OTP thao tác mới -> Bị chặn **HTTP `400`**.
  4. Giả định kẻ tấn công chiếm hoàn toàn cả mật khẩu và thiết bị MFA của `nam`: kẻ tấn công ký duyệt hợp lệ được 1 phiếu (`DIRECTOR`), nhưng không thể ký phiếu thứ hai.
  5. Kiểm soát viên `huong` độc lập kiểm tra chứng từ, phát hiện yêu cầu bất thường từ nguồn chat ngoài và thực hiện **Từ chối (`REJECT`)** với OTP mới -> Yêu cầu chuyển sang trạng thái kết thúc **`REJECTED`**. `lan` thử thực thi bị chặn **HTTP `409`**, `PaymentExecution` = **`0`**.
- **Bằng chứng lưu trữ**: [`evidence/demos/D-02_impersonation_and_compromise.png`](../evidence/demos/D-02_impersonation_and_compromise.png), [`evidence/demos/D-02_summary.json`](../evidence/demos/D-02_summary.json).

---

## Kịch bản `D-03` — Sửa số tiền hoặc người nhận làm xác nhận cũ mất hiệu lực ngay lập tức

- **Mục tiêu chứng minh**: Không thể sửa âm thầm bản ghi `PaymentRevision` đã đóng băng; tạo revision mới bắt buộc quay về `DRAFT` và hủy hiệu lực mọi phiếu duyệt/challenge của revision cũ.
- **Các bước thực hiện & Kết quả thực tế đã ghi nhận**:
  1. `lan` tạo và nộp yêu cầu `REQ-20261024-0001-1025` (`20,000,000 VND`, `BEN-001`), `nam` duyệt phiếu thứ nhất trên `revision 1`, `huong` đã mở sẵn một challenge trên `revision 1`.
  2. Thử gửi POST cập nhật trực tiếp vào `/requests/<id>` để sửa số tiền -> Bị chặn **HTTP `409`**.
  3. `lan` sử dụng chức năng hợp lệ **Tạo Revision mới (`/revise`)** đổi người nhận sang `BEN-002` và số tiền thành `32,000,000 VND` -> Tạo `revision 2`, trạng thái quay về **`DRAFT`**, phiếu duyệt `revision 1` của `nam` bị đánh dấu `SUPERSEDED_BY_REVISION_2`.
  4. Sau khi nộp `revision 2`, `huong` thử dùng lại challenge cũ đã cấp ở `revision 1` -> Bị chặn **HTTP `409` (`WRONG_SCOPE`)**.
  5. `nam` và `huong` cấp xác nhận mới cho `revision 2`, sau đó `lan` thực thi mô phỏng thành công với biên nhận **`SIM-RCPT-20261024131253-56B9B208`**.
- **Bằng chứng lưu trữ**: [`evidence/demos/D-03_revision_invalidation.png`](../evidence/demos/D-03_revision_invalidation.png), [`evidence/demos/D-03_summary.json`](../evidence/demos/D-03_summary.json).

---

## Kịch bản `D-04` — Thu hồi quyền trước bước thực hiện (`HOLD`) và chống tranh chấp đồng thời trên PostgreSQL

- **Mục tiêu chứng minh**: Đình chỉ tài khoản người duyệt sau khi yêu cầu đã `APPROVED` vẫn chặn đứng bước thực thi tại Final Gate (`HOLD`); 2 kết nối PostgreSQL chạy đua đồng thời chỉ tạo đúng 01 biên nhận.
- **Các bước thực hiện & Kết quả thực tế đã ghi nhận**:
  1. Yêu cầu 1 đã được cả `nam` và `huong` duyệt (`APPROVED`) và `lan` đã lấy sẵn `EXECUTE` challenge.
  2. Trước khi `lan` bấm thực thi, Quản trị viên an ninh `an` thực hiện **Đình chỉ (`SUSPEND`)** tài khoản `nam` -> `security_epoch` của `nam` tăng lên, yêu cầu tự động chuyển sang **`HOLD`**.
  3. `lan` gửi lệnh thực thi với challenge đã cấp -> Bị chặn **HTTP `409` (`PRINCIPAL_REVOKED`)**, không có biên nhận nào được tạo.
  4. Trên yêu cầu thứ hai đủ điều kiện, kích hoạt 2 luồng worker trên 2 kết nối PostgreSQL độc lập cùng vượt rào `threading.Barrier(2)` gọi `execute_simulated`: kết quả `[{"worker": 2, "receipt": "SIM-RCPT-20261024131504-BE4B5929", "is_replay": false}, {"worker": 1, "receipt": "SIM-RCPT-20261024131504-BE4B5929", "is_replay": true}]`, tổng số bản ghi `PaymentExecution` trong DB là **`1`**.
- **Bằng chứng lưu trữ**: [`evidence/demos/D-04_revocation_and_concurrency.png`](../evidence/demos/D-04_revocation_and_concurrency.png), [`evidence/demos/D-04_summary.json`](../evidence/demos/D-04_summary.json).

---

## Đáp án ngắn gọn cho bộ câu hỏi phản biện (Mục 16)

1. **Làm sao biết người yêu cầu/duyệt là đúng người?**
   - Hệ thống không dựa vào tên hiển thị, ảnh đại diện hay trích dẫn email/chat (`T-05`, `DES-06`). Quyền hạn được gắn với bản ghi danh tính `EmployeeIdentity` (`id`, `person_id`, `role`, `security_epoch`) đã được khởi tạo qua quy trình bootstrap ngoại tuyến tin cậy (`DES-01`) và phải chứng minh qua mật khẩu + thiết bị TOTP đã đăng ký.
2. **Nếu tài khoản người duyệt bị chiếm hoàn toàn thì điều gì xảy ra?**
   - Kẻ tấn công chiếm trọn 1 tài khoản người duyệt (cả mật khẩu lẫn thiết bị MFA của `nam`) chỉ ký được tối đa 01 phiếu cho vai trò `DIRECTOR` (`T-12`). Hệ thống bắt buộc phiếu thứ hai từ một con người độc lập (`person_id` khác) giữ vai trò `CONTROLLER` (`huong`), và bước thực thi cuối cùng lại thuộc về `REQUESTER` (`lan`) với `EXECUTE` challenge mới. Ngoài ra, khi phát hiện sự cố, `SECURITY_ADMIN` thu hồi quyền (`SUSPEND`/`REVOKE_ALL`) làm tăng `security_epoch`, vô hiệu hóa ngay lập tức các phiếu duyệt của tài khoản bị chiếm trên những yêu cầu chưa thực thi (`T-25`).
3. **Làm sao ngăn sửa số tiền/người nhận hoặc dùng lại xác nhận cũ?**
   - Nội dung yêu cầu khi nộp được đóng băng thành `PaymentRevision` bất biến kèm mã băm SHA-256 `content_digest` (`T-19`). Mỗi `ActionChallenge` và `Approval` lưu cứng `revision_id`, `content_digest` và `beneficiary_version_id`. Nếu sửa nội dung, hệ thống tạo revision mới ở trạng thái `DRAFT` và hủy hiệu lực toàn bộ phiếu/challenge cũ (`T-20`). Mỗi challenge có TTL 120 giây theo giờ máy chủ (`T-21`), chỉ tiêu thụ một lần (`T-22`), và thiết bị TOTP chặn tái sử dụng cùng một timestep 30 giây (`T-23`).
4. **Đánh đổi lớn nhất và rủi ro còn lại là gì?**
   - **Ngắn hạn**: Tăng số thao tác xác thực (6 lần TOTP và 14 HTTP request cho mỗi yêu cầu hoàn tất, độ trễ xử lý hệ thống trung bình ~`2126.8` ms nhưng người dùng phải nhập mã nhiều lần và chờ timestep mới nếu thao tác liền kề trong 30 giây).
   - **Dài hạn**: Khôi phục MFA và cập nhật danh mục người nhận phải thực hiện qua CLI ngoại tuyến tin cậy; khóa `SecurityMutex` toàn cục ưu tiên tính đúng đắn tuyệt đối hơn thông lượng cao.
   - **Rủi ro còn lại (Residual Risks)**: Nếu cả hai người duyệt và người lập cùng bị chiếm quyền đồng thời, hoặc thông đồng ngoài đời thực, hoặc hai người duyệt không kiểm tra kỹ chứng từ mà bấm duyệt nhầm trên nội dung sai ngay từ đầu, hoặc máy chủ PostgreSQL/OS bị kẻ tấn công chiếm quyền root, thì các cơ chế ở tầng ứng dụng không thể tự ngăn chặn.

