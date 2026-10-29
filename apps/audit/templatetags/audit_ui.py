from django import template

register = template.Library()

ACTION_LABELS = {
    "AUTH_LOGIN_PASSWORD": "Đăng nhập",
    "AUTH_LOGIN_PREAUTH": "Kiểm tra thông tin đăng nhập",
    "AUTH_LOGIN_PASSWORD_ONLY": "Đăng nhập thành công",
    "AUTH_LOGIN_MFA": "Xác thực MFA thành công",
    "AUTH_LOGOUT": "Đăng xuất",
    "BENEFICIARY_PROPOSED": "Đề nghị người thụ hưởng",
    "BENEFICIARY_VERIFIED": "Xác minh người thụ hưởng",
    "BENEFICIARY_REJECTED": "Từ chối người thụ hưởng",
    "BENEFICIARY_CHANGE_HOLD_REQUEST": "Tạm giữ yêu cầu do người thụ hưởng thay đổi",
    "OFFLINE_BENEFICIARY_REVOKED": "Thu hồi người thụ hưởng ngoại tuyến",
    "OFFLINE_BENEFICIARY_VERSION_CREATED": "Tạo phiên bản người thụ hưởng ngoại tuyến",
    "CREATE_PAYMENT_REQUEST": "Tạo yêu cầu thanh toán",
    "EDIT_DRAFT_REQUEST": "Chỉnh sửa bản nháp",
    "EDIT_PAYMENT_REQUEST": "Chỉnh sửa yêu cầu thanh toán",
    "REVISE_PAYMENT_REQUEST": "Chỉnh sửa yêu cầu — tạo phiên bản mới",
    "SUBMIT_PAYMENT_REQUEST": "Gửi yêu cầu phê duyệt",
    "CANCEL_PAYMENT_REQUEST": "Hủy yêu cầu thanh toán",
    "APPROVE_PAYMENT_REQUEST": "Phê duyệt yêu cầu",
    "REJECT_PAYMENT_REQUEST": "Từ chối yêu cầu",
    "EXECUTE_PAYMENT_REQUEST": "Thực hiện thanh toán",
    "EXECUTE_PAYMENT_SIMULATED": "Thực hiện thanh toán mô phỏng",
    "ISSUE_PAYMENT_CHALLENGE": "Tạo mã xác nhận",
    "ISSUE_SECURITY_CHALLENGE": "Tạo mã xác nhận an ninh",
    "REQUEST_MOVED_TO_HOLD": "Chuyển yêu cầu sang trạng thái tạm giữ",
    "OFFLINE_PRINCIPAL_RECOVERY": "Khôi phục tài khoản ngoại tuyến",
    "VIEW_PAYMENT_REQUEST": "Xem yêu cầu thanh toán",
    "ACCESS_PROTECTED_ENDPOINT": "Truy cập chức năng bảo vệ",
}

REASON_LABELS = {
    "INVALID_CREDENTIALS": "Thông tin đăng nhập không đúng",
    "FORBIDDEN": "Không có quyền thực hiện",
    "AUTH_REQUIRED": "Cần đăng nhập",
    "MFA_REQUIRED": "Cần xác thực bổ sung",
    "OTP_INVALID": "Mã OTP không đúng",
    "OTP_REPLAY": "Mã OTP đã được sử dụng",
    "CHALLENGE_EXPIRED": "Yêu cầu xác nhận đã hết hạn",
    "PRINCIPAL_REVOKED": "Tài khoản hoặc quyền đã bị thu hồi",
    "VALIDATION_ERROR": "Dữ liệu không hợp lệ",
}

STATE_LABELS = {
    "ANONYMOUS": "Chưa đăng nhập", "PREAUTH_PENDING_MFA": "Đang xác thực",
    "AUTHENTICATED_PASSWORD_ONLY": "Đã đăng nhập", "AUTHENTICATED_FULL_MFA": "Đã đăng nhập",
    "DRAFT": "Bản nháp", "PENDING_APPROVAL": "Chờ duyệt", "APPROVED": "Đã phê duyệt",
    "REJECTED": "Đã từ chối", "HOLD": "Tạm giữ", "EXECUTED_SIMULATED": "Đã thực hiện",
    "CANCELLED": "Đã hủy", "EXPIRED": "Đã hết hạn",
}

ROLE_LABELS = {
    "REQUESTER": "Kế toán", "DIRECTOR": "Giám đốc", "CONTROLLER": "Kiểm soát viên",
    "SECURITY_ADMIN": "Quản trị an ninh", "UNPRIVILEGED": "Không có quyền nghiệp vụ",
}

@register.filter
def audit_action(value):
    return ACTION_LABELS.get(value, str(value).replace("_", " ").title())

@register.filter
def reason_label(value):
    return REASON_LABELS.get(value, str(value).replace("_", " ").capitalize())

@register.filter
def state_label(value):
    if not value:
        return "—"
    if ":Rev#" in str(value):
        state, revision = str(value).split(":Rev#", 1)
        return f"{STATE_LABELS.get(state, state)} · Phiên bản {revision}"
    return STATE_LABELS.get(value, str(value).replace("_", " ").capitalize())

@register.filter
def role_label(value):
    return ROLE_LABELS.get(value, value or "")

@register.filter
def vnd(value):
    """Format an integer using Vietnamese thousands separators."""
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return value
