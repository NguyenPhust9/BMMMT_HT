"""
Render editable Mermaid (.mmd) diagrams in docs/diagrams/ into readable SVG and PNG files
so that SP-02 has both editable source (.mmd) and standalone viewable graphics (.svg, .png)
without requiring internet access.
"""
from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape
from PIL import Image, ImageDraw, ImageFont

DIAGRAMS_DIR = Path(__file__).resolve().parent.parent / "docs" / "diagrams"


def _load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = (
        [
            r"C:\Windows\Fonts\arialbd.ttf",
            r"C:\Windows\Fonts\segoeuib.ttf",
            r"C:\Windows\Fonts\tahomabd.ttf",
        ]
        if bold
        else [
            r"C:\Windows\Fonts\arial.ttf",
            r"C:\Windows\Fonts\segoeui.ttf",
            r"C:\Windows\Fonts\tahoma.ttf",
        ]
    )
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size=size)
    return ImageFont.load_default()


DIAGRAM_SPECS = {
    "01_architecture": {
        "title": "SƠ ĐỒ 01: KIẾN TRÚC TỔNG THỂ HỆ THỐNG SECUREPAY LAB & RANH GIỚI BẢO MẬT",
        "subtitle": "Monolith Django 5.2 + PostgreSQL 17 + SecurityMutex(id=1) + Step-Up MFA Challenge",
        "boxes": [
            (40, 100, 380, 210, "#fff4e6", "#d9480f", "TB-01: Kênh Bên Ngoài (Không Tin Cậy)", [
                "- Tin nhắn Zalo / Email / Cuộc gọi giả danh",
                "- Chỉ lưu vào source_kind / source_excerpt",
                "- Luôn escape HTML & gắn nhãn 'Chưa xác minh'",
            ]),
            (450, 100, 950, 210, "#e7f5ff", "#1971c2", "TB-02: Trình Duyệt & Thiết Bị TOTP", [
                "- 4 vai trò: REQUESTER, DIRECTOR, CONTROLLER, SECURITY_ADMIN",
                "- Thiết bị TOTP độc lập (6 số, 30s timestep)",
                "- Không quyết định quyền hay trạng thái ở client",
            ]),
            (980, 100, 1360, 210, "#f3f0ff", "#6741d9", "Reverse Proxy / HTTPS Profile", [
                "- Loopback 127.0.0.1 / TLS CA nội bộ Lab",
                "- Cookie HttpOnly, SameSite=Lax, Secure (HTTPS)",
                "- Kiểm tra CSRF & Trusted Origins",
            ]),
            (40, 250, 950, 460, "#ebfbee", "#2f9e44", "TB-03: Máy Chủ Ứng Dụng Django 5.2 Monolith (Trusted Core)", [
                "1. Middleware: CSRF + Session Idle/Max Timeout + SecurityEpoch Verification",
                "2. apps.accounts: Pre-Auth (5m) -> Full MFA Session, Throttle, Suspend / Revoke_all",
                "3. apps.beneficiaries: Danh mục BeneficiaryVersion (VERIFIED) bất biến, không sửa tại chỗ",
                "4. apps.payments: Đóng băng PaymentRevision (SHA-256 Digest), ActionChallenge (120s),",
                "   2 Approval độc lập (DIRECTOR + CONTROLLER != REQUESTER), Final Gate & PaymentExecution",
                "5. apps.audit: Ghi AuditEvent cùng transaction, lọc sạch secret/OTP/cookie, phân quyền đọc",
            ]),
            (980, 250, 1360, 460, "#fff9db", "#f08c00", "TB-04: Vận Hành Ngoại Tuyến (CLI)", [
                "- manage.py bootstrap_lab (Seed cố định)",
                "- manage.py manage_beneficiary (Đối chiếu 2 người)",
                "- manage.py recover_principal (Khôi phục MFA,",
                "  tăng security_epoch, chuyển request sang HOLD)",
                "- Không mở /admin/ hay API reset MFA công khai",
            ]),
            (40, 500, 1360, 680, "#f8f9fa", "#343a40", "Cơ Sở Dữ Liệu Quan Hệ PostgreSQL 17 (Mạng Nội Bộ)", [
                "- SecurityMutex(id=1): SELECT ... FOR UPDATE tuần tự hóa mọi mutation nhạy cảm",
                "- Ràng buộc DB: amount_vnd > 0, Unique(revision, slot), Unique(revision, approver_person_id), OneToOne(PaymentExecution.payment_request)",
                "- Lưu trữ: EmployeeIdentity, TOTPDevice, Beneficiary/Version, PaymentRequest/Revision, ActionChallenge, Approval, PaymentExecution, AuditEvent",
            ]),
        ],
        "arrows": [
            (380, 155, 450, 155, "Trích dẫn thô"),
            (950, 155, 980, 155, "HTTPS / HTTP"),
            (1170, 210, 600, 250, "Forward tới Django"),
            (495, 460, 495, 500, "Transaction + Lock Mutex(1)"),
            (1170, 460, 1170, 500, "CLI Lock Mutex(1) + Audit"),
        ],
    },
    "02_dfd_trust_boundaries": {
        "title": "SƠ ĐỒ 02: LUỒNG DỮ LIỆU (DFD) & 4 RANH GIỚI TIN CẬY (TB-01 .. TB-04)",
        "subtitle": "Kiểm soát toàn bộ dữ liệu đi qua từng ranh giới và từ chối mặc định (Fail-Closed)",
        "boxes": [
            (40, 110, 360, 360, "#fff5f5", "#c92a2a", "TB-01: Nguồn Tin Bên Ngoài", [
                "- Tin nhắn giả danh Giám đốc Nam",
                "- Yêu cầu đổi gấp số tài khoản nhận",
                "- Không có thẩm quyền hệ thống",
                "- Dữ liệu đi qua: source_excerpt",
            ]),
            (400, 110, 760, 360, "#e7f5ff", "#1864ab", "TB-02: Trình Duyệt / Client", [
                "- Gửi POST form + CSRF + Session Cookie",
                "- Nhập mã TOTP 6 số từ thiết bị riêng",
                "- Có thể bị sửa DOM / gửi trường thừa",
                "  (role, verified, status, approver_id)",
            ]),
            (800, 110, 1360, 360, "#ebfbee", "#2b8a3e", "TB-03: Các Trạm Kiểm Soát Server (Django)", [
                "Gate 1: Escape HTML, bác bỏ trường authority tự khai",
                "Gate 2: Kiểm tra Full MFA Session & security_epoch",
                "Gate 3: Khóa SecurityMutex(id=1) trong PostgreSQL",
                "Gate 4: Kiểm tra ActionChallenge (120s, 1 lần, đúng scope)",
                "        + TOTP timestep mới (chống replay last_t)",
                "Gate 5: Kiểm tra 2 person_id độc lập & SHA-256 Digest",
            ]),
            (40, 420, 660, 670, "#fff9db", "#e67700", "TB-04: Kênh Vận Hành Ngoại Tuyến Tin Cậy", [
                "- Bootstrap danh tính nhân viên (person_id đã xác minh)",
                "- Xác minh độc lập danh mục BeneficiaryVersion (VERIFIED)",
                "- Khôi phục tài khoản sau sự cố (tăng epoch + buộc duyệt lại)",
            ]),
            (700, 420, 1360, 670, "#f1f3f5", "#212529", "Kho Dữ Liệu PostgreSQL 17 (Trusted Storage)", [
                "- Bản chụp bất biến PaymentRevision + content_digest",
                "- Phiếu duyệt Approval (lưu epoch lúc ký)",
                "- Biên nhận mô phỏng PaymentExecution (duy nhất / request)",
                "- Nhật ký AuditEvent (đã lọc secret, kèm reason_code)",
            ]),
        ],
        "arrows": [
            (360, 220, 400, 220, "Text chưa xác minh"),
            (760, 220, 800, 220, "HTTP POST + OTP"),
            (1080, 360, 1080, 420, "Ghi nguyên tử dưới khóa"),
            (660, 540, 700, 540, "Cập nhật có kiểm toán"),
        ],
    },
    "03_erd": {
        "title": "SƠ ĐỒ 03: MÔ HÌNH DỮ LIỆU QUAN HỆ (ERD) TRÊN POSTGRESQL",
        "subtitle": "Các thực thể cốt lõi, khóa ngoại bảo vệ (PROTECT) và ràng buộc toàn vẹn dữ liệu",
        "boxes": [
            (40, 100, 460, 350, "#e7f5ff", "#1971c2", "EmployeeIdentity & TOTPDevice", [
                "PK id (UUID) | UK username | UK person_id",
                "role (REQUESTER/DIRECTOR/CONTROLLER/SECURITY_ADMIN)",
                "is_active, is_suspended, security_epoch (int >= 1)",
                "failed_password_attempts, failed_otp_attempts",
                "1..* -> TOTPDevice (confirmed, last_t anti-replay)",
            ]),
            (490, 100, 910, 350, "#fff9db", "#f08c00", "Beneficiary & BeneficiaryVersion", [
                "Beneficiary: PK id | UK code | status | active_version_id",
                "BeneficiaryVersion (Bất biến sau khi tạo):",
                "  PK id | FK beneficiary_id | version_number",
                "  vendor_name, bank_name, account_number",
                "  status (PENDING / VERIFIED / REVOKED)",
            ]),
            (940, 100, 1360, 350, "#f3f0ff", "#6741d9", "ActionChallenge (120s TTL, One-Time)", [
                "PK id | UK nonce | FK actor_id | actor_epoch",
                "session_key_hash | device_id | action",
                "FK payment_request_id | FK payment_revision_id",
                "content_digest | FK beneficiary_version_id",
                "expires_at | consumed_at | invalidated_at",
            ]),
            (40, 400, 460, 680, "#ebfbee", "#2f9e44", "PaymentRequest & PaymentRevision", [
                "PaymentRequest: PK id | UK request_code",
                "  FK requester_id | requester_person_id",
                "  FK current_revision_id | status | expires_at",
                "PaymentRevision (Đóng băng khi Submit):",
                "  PK id | FK payment_request_id | revision_number",
                "  amount_vnd (>0) | snapshot bank/account/name",
                "  source_kind, source_excerpt | content_digest",
            ]),
            (490, 400, 910, 680, "#fff0f6", "#c2255c", "Approval (2 Slot Độc Lập)", [
                "PK id | FK payment_revision_id | FK approver_id",
                "approver_person_id | slot (DIRECTOR / CONTROLLER)",
                "content_digest | FK challenge_id (OneToOne)",
                "approver_epoch_at_signing | requester_epoch_at_signing",
                "status (ACTIVE / SUPERSEDED / INVALIDATED / EXPIRED)",
                "UK(revision, slot) & UK(revision, approver_person_id)",
            ]),
            (940, 400, 1360, 680, "#f8f9fa", "#343a40", "PaymentExecution, AuditEvent & Mutex", [
                "PaymentExecution: PK id | UK payment_request_id (1:1)",
                "  FK payment_revision_id | FK executor_id",
                "  idempotency_key | UK receipt_id | SIMULATED label",
                "AuditEvent: PK id | actor | action | result | reason_code",
                "  before_state | after_state | sanitized metadata",
                "SecurityMutex: PK id=1 (Row lock cho mọi mutation)",
            ]),
        ],
        "arrows": [
            (250, 350, 250, 400, "1..* tạo Request"),
            (680, 350, 350, 400, "Tham chiếu Version"),
            (460, 520, 490, 520, "1..* Revision -> Approval"),
            (940, 250, 750, 400, "1:1 tiêu thụ Challenge"),
            (460, 600, 940, 600, "1:1 tạo Execution"),
        ],
    },
    "04_state_machine": {
        "title": "SƠ ĐỒ 04: MÁY TRẠNG THÁI YÊU CẦU THANH TOÁN (PAYMENT REQUEST STATE MACHINE)",
        "subtitle": "Kiểm soát chặt điều kiện chuyển trạng thái và các trạng thái kết thúc bất biến",
        "boxes": [
            (50, 120, 400, 250, "#e7f5ff", "#1971c2", "1. DRAFT (Bản Nháp)", [
                "- REQUESTER tạo mới hoặc tạo Revision N+1",
                "- Chưa có hiệu lực duyệt",
                "- Gửi duyệt (Submit) -> Đóng băng Snapshot",
            ]),
            (460, 120, 900, 250, "#fff9db", "#f08c00", "2. PENDING_APPROVAL (Chờ Duyệt)", [
                "- 0/2 hoặc 1/2 phiếu duyệt hợp lệ",
                "- Hạn 24h tính từ submitted_at (Server UTC)",
                "- Cần đủ DIRECTOR + CONTROLLER độc lập",
            ]),
            (960, 120, 1350, 250, "#ebfbee", "#2f9e44", "3. APPROVED (Đủ 2 Phiếu Hợp Lệ)", [
                "- Đủ 2 phiếu ACTIVE cùng Revision & Digest",
                "- Chỉ là nhãn hiển thị; trước khi thực thi",
                "  vẫn phải kiểm tra lại toàn bộ ở Final Gate",
            ]),
            (50, 320, 470, 470, "#fff0f6", "#c2255c", "4. HOLD (Tạm Giữ Do Sự Cố An Ninh)", [
                "- Kích hoạt khi Requester/Approver bị Suspend,",
                "  Revoke_all, đổi Role/MFA, hoặc Beneficiary bị thu hồi",
                "- Chặn thực thi; muốn tiếp tục phải khắc phục",
                "  nguyên nhân và tạo Revision mới để duyệt lại",
            ]),
            (520, 320, 1350, 470, "#d3f9d8", "#2b8a3e", "5. EXECUTED_SIMULATED (Trạng Thái Cuối - Thành Công Mô Phỏng)", [
                "- Chỉ chính REQUESTER thực thi với Challenge EXECUTE + mã TOTP mới + Idempotency-Key",
                "- Tạo đúng 1 bản ghi PaymentExecution (SIMULATED) dưới khóa SecurityMutex(id=1)",
                "- Không thể sửa, hủy, từ chối hay thực thi tạo giao dịch lần hai",
            ]),
            (50, 520, 1350, 670, "#ffe3e3", "#c92a2a", "Các Trạng Thái Kết Thúc Khác (Terminal States: REJECTED / CANCELLED / EXPIRED)", [
                "- REJECTED: Một người duyệt (DIRECTOR hoặc CONTROLLER) từ chối với Challenge REJECT + OTP mới + Lý do",
                "- CANCELLED: Chủ yêu cầu (REQUESTER) hủy trước khi thực thi",
                "- EXPIRED: Quá thời hạn 24h theo đồng hồ UTC của máy chủ -> Mọi thao tác duyệt/thực thi tiếp theo đều bị từ chối",
            ]),
        ],
        "arrows": [
            (350, 185, 460, 185, "Submit (Freeze)"),
            (900, 185, 960, 185, "Đủ 2/2 phiếu"),
            (680, 250, 260, 320, "Sự cố / Revoke"),
            (1150, 250, 1050, 320, "Final Gate + OTP"),
            (260, 320, 200, 250, "Revise (N+1)"),
        ],
    },
    "05_seq_normal_flow": {
        "title": "SƠ ĐỒ 05: TRÌNH TỰ LUỒNG HỢP LỆ — 2 NGƯỜI DUYỆT ĐỘC LẬP & THỰC THI MÔ PHỎNG (D-01, T-01)",
        "subtitle": "Lan (REQUESTER) lập -> Nam (DIRECTOR) duyệt -> Hương (CONTROLLER) duyệt -> Lan thực thi mô phỏng",
        "boxes": [
            (50, 100, 1310, 200, "#e7f5ff", "#1971c2", "Bước 1: Kế toán Lan (REQUESTER) tạo và gửi yêu cầu thanh toán R1", [
                "1.1 Lan chọn Beneficiary B1 (VERIFIED), nhập 20.000.000 VND và trích dẫn tin nhắn ('Nguồn ngoài — chưa xác minh').",
                "1.2 Lan bấm Gửi duyệt (POST /requests/{id}/submit) -> Server khóa Mutex(1), chụp snapshot tài khoản nhận, tính SHA-256 content_digest, chuyển sang PENDING_APPROVAL.",
            ]),
            (50, 220, 1310, 330, "#fff9db", "#f08c00", "Bước 2: Giám đốc Nam (DIRECTOR) đối chiếu và phê duyệt độc lập (Phiếu 1/2)", [
                "2.1 Nam mở trang chi tiết đã đóng băng, kiểm tra số tiền/STK, yêu cầu cấp ActionChallenge loại APPROVE_DIRECTOR (TTL 120s).",
                "2.2 Nam nhập mã TOTP mới -> Server khóa Mutex(1), kiểm tra TOTP (last_t), tạo Approval(slot=DIRECTOR). Nếu Lan thử thực thi lúc này sẽ bị chặn 409 MISSING_APPROVAL (T-02).",
            ]),
            (50, 350, 1310, 460, "#f3f0ff", "#6741d9", "Bước 3: Kiểm soát viên Hương (CONTROLLER) đối chiếu và phê duyệt độc lập (Phiếu 2/2)", [
                "3.1 Hương yêu cầu cấp ActionChallenge loại APPROVE_CONTROLLER gắn đúng Revision 1 và content_digest.",
                "3.2 Hương nhập mã TOTP mới -> Server khóa Mutex(1), kiểm tra person_id khác Lan và khác Nam, tạo Approval(slot=CONTROLLER), chuyển trạng thái sang APPROVED.",
            ]),
            (50, 480, 1310, 670, "#ebfbee", "#2f9e44", "Bước 4: Kế toán Lan (REQUESTER) xác thực Step-Up MFA mới và Thực thi mô phỏng", [
                "4.1 Lan yêu cầu ActionChallenge loại EXECUTE cho yêu cầu R1 của chính mình.",
                "4.2 Lan gửi POST /requests/{id}/execute-simulated kèm Challenge EXECUTE + mã TOTP mới của Lan + Idempotency-Key.",
                "4.3 Server khóa Mutex(1), chạy Final Gate (kiểm tra lại cả 3 tài khoản, 2 phiếu, epoch, digest, beneficiary), tạo đúng 1 PaymentExecution (SIMULATED) + AuditEvent.",
                "4.4 Nếu Lan gửi lại cùng Idempotency-Key, hệ thống trả về đúng biên nhận cũ mà không tạo bản ghi thực thi thứ hai (T-30).",
            ]),
        ],
        "arrows": [
            (680, 200, 680, 220, "PENDING (0/2)"),
            (680, 330, 680, 350, "PENDING (1/2)"),
            (680, 460, 680, 480, "APPROVED (2/2)"),
        ],
    },
    "06_seq_tamper_replay": {
        "title": "SƠ ĐỒ 06: CHỐNG SỬA NỘI DUNG, TẠO REVISION MỚI & CHẶN PHÁT LẠI (D-03, T-17..T-23)",
        "subtitle": "Bảo vệ toàn vẹn nội dung đã đóng băng và chống tái sử dụng xác nhận cũ",
        "boxes": [
            (50, 100, 1310, 220, "#ffe3e3", "#c92a2a", "Tình huống A: Thử sửa âm thầm nội dung sau khi đã gửi duyệt (T-19)", [
                "- Yêu cầu R1 (Revision 1: 20.000.000 VND) đã được đóng băng (is_frozen=True) và đã có phiếu duyệt của Giám đốc Nam.",
                "- Kẻ tấn công hoặc client gửi request sửa trực tiếp amount_vnd=50.000.000 hoặc đổi số tài khoản trên Revision 1.",
                "- Server từ chối ngay lập tức (409 SNAPSHOT_MISMATCH / IMMUTABLE_REVISION) và ghi AuditEvent DENIED; dữ liệu Revision 1 giữ nguyên.",
            ]),
            (50, 250, 1310, 390, "#fff9db", "#f08c00", "Tình huống B: Sửa đổi đúng quy trình tạo Revision 2 làm vô hiệu hóa toàn bộ xác nhận cũ (T-20)", [
                "- Kế toán Lan gọi chức năng Revise hợp lệ để đổi số tiền sang 25.000.000 VND.",
                "- Dưới khóa Mutex(1), Server tạo PaymentRevision(revision_number=2) mới ở trạng thái DRAFT.",
                "- Toàn bộ Approval của Revision 1 bị chuyển sang SUPERSEDED_BY_REVISION và các ActionChallenge cũ bị vô hiệu hóa.",
                "- Yêu cầu buộc phải Submit lại Revision 2 (sinh content_digest mới D2) và xin lại từ đầu đủ 2 phiếu duyệt mới.",
            ]),
            (50, 420, 1310, 670, "#e7f5ff", "#1971c2", "Tình huống C: Chặn dùng chéo ngữ cảnh, hết hạn và phát lại Challenge / TOTP (T-16, T-17, T-21..T-23)", [
                "- Thử lấy Challenge của người khác (T-16) hoặc lấy Challenge APPROVE đem gọi EXECUTE / đổi sang Request khác (T-17) -> Bị chặn 403/409 WRONG_SCOPE.",
                "- Thử gửi Challenge sau 120 giây theo giờ UTC của Server dù chỉnh lùi đồng hồ trình duyệt (T-21) -> Bị chặn 409 CHALLENGE_EXPIRED.",
                "- Thử gửi lại Challenge đã consumed (T-22) -> Bị chặn 409 CHALLENGE_USED.",
                "- Thử dùng lại cùng mã TOTP 6 số vừa dùng đăng nhập/duyệt trong cùng timestep 30 giây (T-23, T-34) -> Bị chặn 400/409 OTP_REPLAY.",
            ]),
        ],
        "arrows": [
            (680, 220, 680, 250, "Bắt buộc tạo Revision mới"),
            (680, 390, 680, 420, "Kiểm tra Scope & Replay"),
        ],
    },
    "07_seq_compromise_revocation": {
        "title": "SƠ ĐỒ 07: XỬ LÝ TÀI KHOẢN BỊ CHIẾM QUYỀN HOÀN TOÀN & THU HỒI KHẨN CẤP (D-02, D-04, T-12, T-25)",
        "subtitle": "Chịu lỗi khi 1 người duyệt bị chiếm hoàn toàn và chặn thực thi tức thì tại Final Gate",
        "boxes": [
            (50, 100, 1310, 270, "#fff0f6", "#c2255c", "Kịch bản 1: Tài khoản Giám đốc Nam (DIRECTOR) bị chiếm hoàn toàn cả Mật khẩu + Thiết bị TOTP (T-12, D-02)", [
                "1. Kẻ gian đăng nhập hợp lệ qua cả 2 bước (Password + TOTP của Nam) và ký duyệt thành công slot DIRECTOR cho yêu cầu R1.",
                "2. Kẻ gian thử ký tiếp slot CONTROLLER -> Bị chặn vì role là DIRECTOR và trùng person_id (UniqueConstraint & Service check).",
                "3. Kẻ gian thử gọi thẳng API execute-simulated -> Bị chặn vì DIRECTOR không có quyền thực thi và R1 mới chỉ có 1/2 phiếu.",
                "4. Kiểm soát viên Hương (độc lập) phát hiện bất thường và Reject R1 -> R1 chuyển sang REJECTED vĩnh viễn, không có tiền giả lập nào được thực thi.",
            ]),
            (50, 300, 1310, 480, "#fff9db", "#f08c00", "Kịch bản 2: Đình chỉ / Thu hồi tài khoản ngay trước bước Thực thi (T-25, D-04)", [
                "1. Giả sử yêu cầu R2 đã có đủ 2 phiếu (APPROVED), nhưng trước khi Lan kịp thực thi thì phát hiện tài khoản của Nam có dấu hiệu lộ lọt.",
                "2. Quản trị viên An (SECURITY_ADMIN) xin Challenge SUSPEND + nhập mã TOTP mới + lý do để đình chỉ tài khoản Nam.",
                "3. Dưới khóa Mutex(1): Nam bị đặt is_suspended=True, security_epoch tăng từ 1 lên 2; phiếu duyệt của Nam trên R2 chuyển sang INVALIDATED_BY_INCIDENT; R2 chuyển sang HOLD.",
                "4. Khi Lan gọi execute-simulated cho R2: Final Gate kiểm tra thấy R2 đang HOLD và security_epoch của Nam không còn khớp -> Từ chối 409 PRINCIPAL_REVOKED.",
            ]),
            (50, 510, 1310, 670, "#ebfbee", "#2f9e44", "Kịch bản 3: Khôi phục ngoại tuyến tin cậy và Tranh chấp đồng thời Execute vs Revoke (T-15, T-35)", [
                "- SECURITY_ADMIN không thể tự mở khóa hay reset MFA qua Web UI. Việc khôi phục chỉ chạy qua CLI ngoại tuyến (recover_principal), tăng tiếp security_epoch và buộc R2 phải tạo Revision mới để duyệt lại từ đầu.",
                "- Khi Execute và Revoke chạy đồng thời trên PostgreSQL (T-35): Nhờ khóa SecurityMutex(id=1), nếu Revoke giữ khóa trước thì Execute thất bại; nếu Execute hợp lệ commit trước thì biên nhận lịch sử được bảo toàn.",
            ]),
        ],
        "arrows": [
            (680, 270, 680, 300, "Phát hiện sự cố"),
            (680, 480, 680, 510, "Khôi phục có kiểm soát"),
        ],
    },
}


def render_svg(name: str, spec: dict) -> str:
    width, height = 1400, 720
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<defs>',
        '  <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">',
        '    <path d="M 0 0 L 10 5 L 0 10 z" fill="#495057" />',
        '  </marker>',
        '</defs>',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff" />',
        f'<rect x="15" y="15" width="{width - 30}" height="{height - 30}" rx="12" fill="#fcfcfc" stroke="#dee2e6" stroke-width="2" />',
        f'<text x="40" y="52" font-family="Segoe UI, Arial, sans-serif" font-size="22" font-weight="bold" fill="#1864ab">{escape(spec["title"])}</text>',
        f'<text x="40" y="78" font-family="Segoe UI, Arial, sans-serif" font-size="15" fill="#495057">{escape(spec["subtitle"])}</text>',
    ]

    for x1, y1, x2, y2, bg, border, title, bullets in spec["boxes"]:
        w = x2 - x1
        h = y2 - y1
        lines.append(
            f'<rect x="{x1}" y="{y1}" width="{w}" height="{h}" rx="10" fill="{bg}" stroke="{border}" stroke-width="2.5" />'
        )
        lines.append(
            f'<text x="{x1 + 16}" y="{y1 + 30}" font-family="Segoe UI, Arial, sans-serif" font-size="16" font-weight="bold" fill="{border}">{escape(title)}</text>'
        )
        ty = y1 + 58
        for b in bullets:
            lines.append(
                f'<text x="{x1 + 18}" y="{ty}" font-family="Segoe UI, Arial, sans-serif" font-size="14" fill="#212529">{escape(b)}</text>'
            )
            ty += 24

    for ax1, ay1, ax2, ay2, label in spec["arrows"]:
        lines.append(
            f'<line x1="{ax1}" y1="{ay1}" x2="{ax2}" y2="{ay2}" stroke="#495057" stroke-width="2.5" marker-end="url(#arrow)" />'
        )
        mx = (ax1 + ax2) // 2
        my = (ay1 + ay2) // 2 - 6
        lines.append(
            f'<text x="{mx}" y="{my}" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="12" font-weight="bold" fill="#343a40">{escape(label)}</text>'
        )

    lines.append("</svg>")
    return "\n".join(lines)


def render_png(name: str, spec: dict, out_path: Path) -> None:
    width, height = 1400, 720
    img = Image.new("RGB", (width, height), "#ffffff")
    draw = ImageDraw.Draw(img)

    font_title = _load_font(22, bold=True)
    font_sub = _load_font(15, bold=False)
    font_box_title = _load_font(16, bold=True)
    font_bullet = _load_font(14, bold=False)
    font_label = _load_font(12, bold=True)

    draw.rounded_rectangle((15, 15, width - 15, height - 15), radius=12, fill="#fcfcfc", outline="#dee2e6", width=2)
    draw.text((40, 32), spec["title"], fill="#1864ab", font=font_title)
    draw.text((40, 62), spec["subtitle"], fill="#495057", font=font_sub)

    for x1, y1, x2, y2, bg, border, title, bullets in spec["boxes"]:
        draw.rounded_rectangle((x1, y1, x2, y2), radius=10, fill=bg, outline=border, width=3)
        draw.text((x1 + 16, y1 + 12), title, fill=border, font=font_box_title)
        ty = y1 + 42
        for b in bullets:
            draw.text((x1 + 18, ty), b, fill="#212529", font=font_bullet)
            ty += 24

    for ax1, ay1, ax2, ay2, label in spec["arrows"]:
        draw.line((ax1, ay1, ax2, ay2), fill="#495057", width=3)
        draw.ellipse((ax2 - 5, ay2 - 5, ax2 + 5, ay2 + 5), fill="#495057")
        mx = (ax1 + ax2) // 2
        my = (ay1 + ay2) // 2 - 16
        draw.text((mx - 45, my), label, fill="#212529", font=font_label)

    img.save(out_path, format="PNG")


def main() -> None:
    DIAGRAMS_DIR.mkdir(parents=True, exist_ok=True)
    for name, spec in DIAGRAM_SPECS.items():
        svg_path = DIAGRAMS_DIR / f"{name}.svg"
        png_path = DIAGRAMS_DIR / f"{name}.png"
        svg_path.write_text(render_svg(name, spec), encoding="utf-8")
        render_png(name, spec, png_path)
        print(f"Rendered {svg_path.name} and {png_path.name}")


if __name__ == "__main__":
    main()
