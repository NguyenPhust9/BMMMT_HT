# Trạng thái Dự án (PROJECT_STATUS.md)

- **Đề tài**: Đề tài 5 — Hệ thống xác minh và phê duyệt yêu cầu thanh toán nội bộ trước nguy cơ giả mạo và chiếm quyền tài khoản
- **Thư mục dự án**: `g:\BMMMT_HT\securepay_lab`
- **Cập nhật lần cuối (UTC)**: `2026-10-24 13:15:06 UTC`
- **Mốc hiện tại**: Hoàn tất toàn bộ **M0 → M9** (`DONE`)

---

## 1. Bảng tiến độ các mốc (M0 – M9)

| Mốc | Nội dung chính | Trạng thái | Đầu ra chính |
|---|---|---|---|
| **M0** | Khảo sát môi trường, chốt phạm vi, lập bảng truy vết và mẫu kết quả test | **DONE** | `docs/01_scope.md`, `docs/decisions.md`, `docs/traceability.csv`, `evidence/test_results.csv`, `PROJECT_STATUS.md` |
| **M1** | Kiến trúc, mô hình đe dọa, mô hình dữ liệu, máy trạng thái & bộ 7 sơ đồ | **DONE** | `docs/02_threat_model.md`, `docs/03_architecture.md`, `docs/04_security_design.md`, `docs/diagrams/01..07.{mmd,svg,png}` |
| **M2** | Khung dự án Django 5.2 + PostgreSQL 17, xác thực 2 bước MFA, bootstrap offline | **DONE** | `manage.py`, `config/`, `apps/common/`, `apps/accounts/`, `bootstrap_lab`, `recover_principal` |
| **M3** | Danh mục người nhận tin cậy, luồng yêu cầu thanh toán, đóng băng revision & kiểm thử `T-01..T-09`, `T-18..T-20` | **DONE** | `apps/beneficiaries/`, `apps/payments/`, `manage_beneficiary`, `tests/test_suite_t01_t20.py` |
| **M4** | Challenge một lần gắn nội dung, TOTP mới cho `APPROVE`/`REJECT`/`EXECUTE`, chống replay & kiểm thử `T-10..T-17`, `T-21..T-24` | **DONE** | `ActionChallenge`, `Approval`, `PaymentExecution`, `tests/test_suite_t01_t20.py`, `tests/test_suite_t21_t40.py` |
| **M5** | Khóa tuần tự hóa `SecurityMutex` trên PostgreSQL, thu hồi quyền (`SUSPEND`/`REVOKE_ALL`), Final Gate & kiểm thử `T-25..T-35`, `T-40` | **DONE** | `apps/common/mutex.py`, `apps/accounts/services.py`, `tests/test_suite_t21_t40.py` |
| **M6** | Bề mặt web an toàn (CSRF, XSS escaping, nhãn nguồn ngoài), nhật ký kiểm toán ẩn bí mật & HTTPS profile (`T-36..T-39`) | **DONE** | `apps/audit/`, `templates/`, `static/css/securepay.css`, `Caddyfile`, `tests/test_suite_t21_t40.py` |
| **M7** | Chạy đầy đủ bộ kiểm thử 40 ca (`T-01..T-40`) trên PostgreSQL 17 thật và ghi nhận bằng chứng | **DONE** | `evidence/test_results.csv` (**40/40 PASS**), `evidence/index.md`, `evidence/logs/T-01..T-40.json` |
| **M8** | Thực thi 4 kịch bản demo (`D-01..D-04`), chụp minh chứng và phân tích đánh đổi ngắn/dài hạn (kèm số liệu đo N=5) | **DONE** | `evidence/demos/D-01..D-04_*.{png,json}`, `evidence/demos/metrics_n5.json`, `docs/05_tradeoffs.md` |
| **M9** | Đóng gói 5 sản phẩm bàn giao (`SP-01..SP-05`), kiểm tra vệ sinh bí mật và nghiệm thu cuối | **DONE** | `deliverables/Bao_cao_De_tai_5.docx`, `deliverables/Slide_De_tai_5.pptx`, `deliverables/Kich_ban_demo.md`, `README.md` |

---

## 2. Tóm tắt kết quả kiểm thử và bằng chứng thực tế

- **Tổng số ca kiểm thử (`T-01` .. `T-40`)**: `40` ca — **40 PASS**, `0 FAIL`, `0 BLOCKED`, `0 NOT_RUN`.
- **Tổng số mục truy vết (`traceability.csv`)**: `22/22 DONE` (`GT-01`, `SEC-01..05`, `YC-01..08`, `TC-01..03`, `SP-01..05`).
- **Kiểm tra rò rỉ bí mật (Secret Hygiene Scan)**: Đã quét toàn bộ `docs/`, `evidence/`, `deliverables/` và `README.md` — **0 rò rỉ** hạt giống TOTP, mật khẩu, mã OTP hay session cookie.
- **Lỗi tồn đọng**: Không còn lỗi chặn nghiệm thu.
