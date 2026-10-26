from __future__ import annotations

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from apps.beneficiaries.models import Beneficiary, BeneficiaryStatus
from apps.common.http import require_full_mfa
from apps.payments.models import PaymentRequest, RequestStatus


@require_full_mfa
def dashboard_view(request: HttpRequest) -> HttpResponse:
    if request.user.role == "SECURITY_ADMIN":
        return redirect("/security/users")
    qs = PaymentRequest.objects.all()
    if request.user.role == "REQUESTER":
        qs = qs.filter(requester=request.user)
    context = {
        "total_requests": qs.count(),
        "pending_requests": qs.filter(status=RequestStatus.PENDING_APPROVAL).count(),
        "approved_requests": qs.filter(status=RequestStatus.APPROVED).count(),
        "completed_requests": qs.filter(status=RequestStatus.EXECUTED_SIMULATED).count(),
        "verified_beneficiaries": Beneficiary.objects.filter(status=BeneficiaryStatus.VERIFIED).count(),
        "recent_requests": qs.select_related("requester", "current_revision").order_by("-updated_at")[:5],
    }
    return render(request, "common/dashboard.html", context)


MODULES = {
    "invoices": {
        "eyebrow": "QUẢN LÝ CHỨNG TỪ", "title": "Hóa đơn", "icon": "fa-file-invoice-dollar",
        "description": "Tập trung hóa đơn đầu vào và theo dõi trạng thái đối chiếu.",
        "cards": [("Hóa đơn mới", "0"), ("Chờ đối chiếu", "0"), ("Đã khớp", "0"), ("Có sai lệch", "0")],
        "columns": ["Số hóa đơn", "Nhà cung cấp", "Ngày phát hành", "Giá trị", "Trạng thái"],
    },
    "budgets": {
        "eyebrow": "KIỂM SOÁT CHI TIÊU", "title": "Ngân sách", "icon": "fa-chart-pie",
        "description": "Theo dõi hạn mức theo phòng ban, dự án và kỳ kế toán.",
        "cards": [("Ngân sách năm", "—"), ("Đã sử dụng", "—"), ("Đang cam kết", "—"), ("Còn khả dụng", "—")],
        "columns": ["Mã ngân sách", "Phòng ban", "Hạn mức", "Đã sử dụng", "Còn lại"],
    },
    "reports": {
        "eyebrow": "PHÂN TÍCH TÀI CHÍNH", "title": "Báo cáo", "icon": "fa-chart-column",
        "description": "Tổng hợp số liệu thanh toán và hiệu quả xử lý theo thời gian.",
        "cards": [("Tổng chi kỳ này", "—"), ("Thời gian duyệt TB", "—"), ("Tỷ lệ hoàn tất", "—"), ("Yêu cầu bị từ chối", "—")],
        "columns": ["Tên báo cáo", "Chu kỳ", "Người tạo", "Cập nhật", "Thao tác"],
    },
    "notifications": {
        "eyebrow": "TRUNG TÂM THÔNG BÁO", "title": "Thông báo", "icon": "fa-bell",
        "description": "Theo dõi yêu cầu cần xử lý và các thay đổi quan trọng.",
        "cards": [("Chưa đọc", "0"), ("Cần xử lý", "0"), ("Cảnh báo", "0"), ("Tất cả", "0")],
        "columns": ["Thông báo", "Loại", "Liên quan", "Thời gian", "Trạng thái"],
    },
    "settings": {
        "eyebrow": "CẤU HÌNH CÁ NHÂN", "title": "Cài đặt", "icon": "fa-gear",
        "description": "Quản lý tùy chọn hiển thị và thông báo của tài khoản.",
        "cards": [("Hồ sơ", ""), ("Thông báo", ""), ("Giao diện", ""), ("Bảo mật", "")],
        "columns": ["Tùy chọn", "Mô tả", "Giá trị hiện tại", "Trạng thái", "Thao tác"],
    },
    "help": {
        "eyebrow": "TRUNG TÂM HỖ TRỢ", "title": "Trợ giúp", "icon": "fa-circle-question",
        "description": "Hướng dẫn sử dụng các quy trình chính trong SecurePay.",
        "cards": [("Tạo yêu cầu", ""), ("Phê duyệt", ""), ("Người thụ hưởng", ""), ("Tài khoản", "")],
        "columns": ["Chủ đề", "Nhóm nội dung", "Cập nhật", "Mức độ", "Thao tác"],
    },
}


@require_full_mfa
def module_placeholder_view(request: HttpRequest, module: str) -> HttpResponse:
    config = MODULES.get(module)
    if config is None:
        return render(request, "common/error.html", {"error_message": "Không tìm thấy phân hệ."}, status=404)
    return render(request, "common/module_placeholder.html", {"module": module, **config})
