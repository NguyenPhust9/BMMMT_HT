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

