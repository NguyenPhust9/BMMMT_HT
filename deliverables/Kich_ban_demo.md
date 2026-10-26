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
