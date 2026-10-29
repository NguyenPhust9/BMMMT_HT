# Bộ 40 test case — Bản tiếng Việt dễ đọc

Tài liệu này là bản tóm tắt dành cho thuyết trình và rà soát. Kết quả máy chạy chi tiết vẫn được lưu tại `test_results.csv` và `logs/T-01.json` đến `logs/T-40.json`.

## Nhóm 1 — Luồng nghiệp vụ và phân quyền (`T-01` đến `T-09`)

| ID | Tình huống kiểm thử | Kết quả mong đợi |
|---|---|---|
| **T-01** | Người lập tạo yêu cầu; Giám đốc và Kiểm soát viên duyệt; người lập thực thi. | Đi đúng luồng `DRAFT → PENDING_APPROVAL → APPROVED → EXECUTED_SIMULATED`; chỉ có một biên nhận. |
| **T-02** | Thực thi khi mới có một phiếu duyệt. | Bị chặn `409 MISSING_APPROVAL`; không tạo biên nhận. |
| **T-03** | Kiểm soát viên từ chối, sau đó thử duyệt hoặc thực thi lại. | Yêu cầu giữ trạng thái `REJECTED`; mọi thao tác tiếp theo bị chặn. |
| **T-04** | Người lập khác thử hủy yêu cầu không thuộc sở hữu. | Bị chặn `403`; chỉ chủ sở hữu mới hủy được. |
| **T-05** | Tài khoản giả danh có tên hiển thị giống Giám đốc thử duyệt. | Bị chặn `403 FORBIDDEN`; không tạo phiếu duyệt. |
| **T-06** | Client tự khai vai trò, trạng thái hoặc người duyệt trong payload. | Máy chủ từ chối dữ liệu vượt quyền; không tạo yêu cầu sai. |
| **T-07** | Người lập tự duyệt hoặc một người cố chiếm cả hai vị trí duyệt. | Bị chặn bởi `SELF_APPROVAL` hoặc `DUPLICATE_APPROVER`. |
| **T-08** | Người lập truy cập yêu cầu của người lập khác. | Mọi thao tác xem, sửa, hủy và xem biên nhận đều bị chặn. |
| **T-09** | Quản trị an ninh thử tạo, duyệt hoặc thực thi thanh toán. | Bị chặn; vai trò an ninh không có quyền tài chính. |

## Nhóm 2 — Xác thực, chiếm quyền và challenge (`T-10` đến `T-17`)

| ID | Tình huống kiểm thử | Kết quả mong đợi |
|---|---|---|
| **T-10** | Chỉ đăng nhập mật khẩu nhưng chưa hoàn thành MFA rồi gọi API nghiệp vụ. | Bị chặn `401 MFA_REQUIRED`. |
| **T-11** | Kẻ tấn công có cookie phiên nhưng thiếu challenge và OTP mới. | Không thể duyệt; đăng xuất làm challenge đang mở mất hiệu lực. |
| **T-12** | Một tài khoản người duyệt bị chiếm cả mật khẩu và TOTP. | Chỉ tạo được một phiếu; không thể tự tạo phiếu thứ hai hoặc thực thi. |
| **T-13** | Nhập OTP sai nhiều lần rồi đổi sang phiên khác. | Tài khoản/thiết bị vẫn bị giới hạn `429 RATE_LIMITED`. |
| **T-14** | Thử tự đổi MFA hoặc tự nâng vai trò qua HTTP. | Tất cả đường dẫn đều bị chặn `403`. |
| **T-15** | Đình chỉ người duyệt rồi thử tự mở lại quyền. | Yêu cầu chuyển `HOLD`; chỉ quy trình khôi phục ngoại tuyến mới khôi phục được tài khoản. |
| **T-16** | Challenge của Giám đốc bị Kiểm soát viên lấy để sử dụng. | Bị chặn do sai người dùng hoặc sai phiên (`WRONG_SCOPE`). |
| **T-17** | Challenge của yêu cầu/revision này được dùng cho yêu cầu, revision hoặc hành động khác. | Bị chặn `409 WRONG_SCOPE`. |

## Nhóm 3 — Nội dung, revision và chống phát lại (`T-18` đến `T-29`)

| ID | Tình huống kiểm thử | Kết quả mong đợi |
|---|---|---|
| **T-18** | Tạo yêu cầu tới người nhận chưa xác minh/đã thu hồi hoặc tự chèn số tài khoản. | Bị chặn; chỉ người nhận `VERIFIED` được sử dụng. |
| **T-19** | Sửa trực tiếp revision đã nộp duyệt. | Bị chặn `409 IMMUTABLE_REVISION`; số tiền và mã băm không đổi. |
| **T-20** | Tạo revision mới sau khi đã có phiếu duyệt/challenge. | Phiếu và challenge cũ bị vô hiệu hóa; tiến độ duyệt trở về ban đầu. |
| **T-21** | Dùng challenge trước, đúng lúc và sau thời điểm hết hạn. | Chỉ challenge còn hạn được chấp nhận; challenge hết hạn bị từ chối. |
| **T-22** | Phát lại challenge đã dùng hoặc gửi lại cùng khóa idempotency. | Challenge bị chặn; retry idempotent trả cùng biên nhận, không tạo bản ghi thứ hai. |
| **T-23** | Dùng lại cùng một mã TOTP trong cùng chu kỳ 30 giây. | Bị chặn `OTP_REPLAY`. |
| **T-24** | Client tự gửi danh sách phiếu duyệt/trạng thái hoặc người duyệt thử thực thi. | Máy chủ bỏ qua dữ liệu tự khai và từ chối thao tác. |
| **T-25** | Đình chỉ người duyệt sau khi yêu cầu đã đủ phiếu nhưng trước khi thực thi. | Final Gate chuyển yêu cầu sang `HOLD`; không tạo biên nhận. |
| **T-26** | Vai trò người duyệt bị thay đổi trước khi thực thi. | Final Gate phát hiện quyền không còn hợp lệ và chặn giao dịch. |
| **T-27** | Thiết bị TOTP của người duyệt được reset/rotate. | Phiên, challenge và phiếu cũ mất hiệu lực; yêu cầu chuyển `HOLD`. |
| **T-28** | Phiên bản người thụ hưởng thay đổi trước lúc thực thi. | Không tự chuyển sang tài khoản mới; giao dịch bị chặn. |
| **T-29** | Thử sửa, hủy, từ chối hoặc thực thi lại yêu cầu đã hoàn tất. | Mọi thao tác bị chặn; vẫn chỉ có một biên nhận. |

## Nhóm 4 — Tranh chấp đồng thời và tính nguyên tử (`T-30` đến `T-35`)

| ID | Tình huống kiểm thử | Kết quả mong đợi |
|---|---|---|
| **T-30** | Hai kết nối đồng thời thực thi với cùng khóa idempotency. | Một kết nối tạo biên nhận, kết nối còn lại nhận đúng biên nhận đó; tổng cộng một bản ghi. |
| **T-31** | Hai kết nối đồng thời thực thi với hai khóa idempotency khác nhau. | Chỉ một giao dịch thắng; giao dịch còn lại bị xung đột. |
| **T-32** | Thao tác sửa revision và duyệt cũ xảy ra đồng thời. | Dù thứ tự nào xảy ra, không phiếu cũ nào còn hiệu lực trên revision mới. |
| **T-33** | Phê duyệt và từ chối xảy ra đồng thời. | Trạng thái cuối là `REJECTED`; không tạo biên nhận. |
| **T-34** | Hai kết nối cùng dùng một mã TOTP cho hai challenge. | Chỉ một thao tác thành công; thao tác còn lại bị `OTP_REPLAY`. |
| **T-35** | Thu hồi quyền và thực thi xảy ra đồng thời. | Kết quả nhất quán theo transaction; không có trạng thái hoặc biên nhận dở dang. |

## Nhóm 5 — Bảo vệ web, dữ liệu và phục hồi lỗi (`T-36` đến `T-40`)

| ID | Tình huống kiểm thử | Kết quả mong đợi |
|---|---|---|
| **T-36** | Gửi POST thiếu CSRF, Origin sai hoặc dùng GET cho endpoint thay đổi dữ liệu. | Thiếu/sai CSRF bị `403`; sai phương thức bị `405`. |
| **T-37** | Nhập số tiền không hợp lệ và nội dung chứa mã XSS. | Giá trị tiền sai bị `400`; HTML/script được escape an toàn. |
| **T-38** | Người dùng đọc audit của người khác hoặc tìm bí mật trong audit. | Audit được phân quyền, lọc dữ liệu tài chính và không chứa seed TOTP. |
| **T-39** | Kiểm tra cấu hình HTTPS, cookie và trang lỗi. | TLS hoạt động; cookie có `Secure`, `SameSite`; trang lỗi không lộ bí mật. |
| **T-40** | Cố tình gây lỗi giữa transaction thực thi. | PostgreSQL rollback toàn bộ; thử lại hợp lệ tạo đúng một biên nhận. |

## Các test nên trình bày trực tiếp

- **D-01:** `T-01`, `T-02` — luồng hợp lệ và bắt buộc hai người duyệt.
- **D-02:** `T-05`, `T-11`, `T-12` — giả danh và chiếm quyền tài khoản.
- **D-03:** `T-19`, `T-20` — đóng băng nội dung và vô hiệu hóa phê duyệt cũ.
- **D-04:** `T-25`, `T-35` — thu hồi khẩn cấp và kiểm soát tranh chấp.

**Kết quả tổng hợp:** `40/40 PASS` trên PostgreSQL 17; tất cả hoạt động thanh toán chỉ là mô phỏng nội bộ.
