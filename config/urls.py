"""
URL configuration for SecurePay Lab (Section 8).
Explicitly omits / blocks Django admin, public signup, MFA reset, and role self-service.
"""
from django.urls import path, re_path

from apps.accounts import views as account_views
from apps.audit import views as audit_views
from apps.beneficiaries import views as beneficiary_views
from apps.payments import views as payment_views
from apps.common import views as common_views

urlpatterns = [
    path("", payment_views.home_redirect_view, name="home"),
    path("dashboard", common_views.dashboard_view, name="dashboard"),
    path("workspace/invoices", common_views.invoices_view, name="invoices"),
    path("workspace/<slug:module>", common_views.module_placeholder_view, name="module_placeholder"),
    # Authentication & MFA
    path("auth/login", account_views.login_view, name="login"),
    path("auth/mfa", account_views.mfa_verify_view, name="mfa_verify"),
    path("auth/logout", account_views.logout_view, name="logout"),
    # Payment Requests & Approvals & Simulated Execution
    path("requests", payment_views.requests_list_or_create_view, name="requests_list"),
    path("requests/new", payment_views.request_create_form_view, name="request_create_form"),
    path("requests/<uuid:request_id>", payment_views.request_detail_view, name="request_detail"),
    path("requests/<uuid:request_id>/edit", payment_views.edit_draft_view, name="request_edit_draft"),
    path("requests/<uuid:request_id>/submit", payment_views.submit_request_view, name="request_submit"),
    path("requests/<uuid:request_id>/revise", payment_views.revise_request_view, name="request_revise"),
    path("requests/<uuid:request_id>/cancel", payment_views.cancel_request_view, name="request_cancel"),
    path("requests/<uuid:request_id>/challenges", payment_views.issue_challenge_view, name="request_challenges"),
    path("requests/<uuid:request_id>/approve", payment_views.approve_request_view, name="request_approve"),
    path("requests/<uuid:request_id>/reject", payment_views.reject_request_view, name="request_reject"),
    path(
        "requests/<uuid:request_id>/execute-simulated",
        payment_views.execute_simulated_view,
        name="request_execute_simulated",
    ),
    path("requests/<uuid:request_id>/receipt", payment_views.receipt_view, name="request_receipt"),
    # Trusted Beneficiaries Registry (Read-only via HTTP)
    path("beneficiaries", beneficiary_views.beneficiaries_list_view, name="beneficiaries_list"),
    path("beneficiaries/new", beneficiary_views.beneficiary_create_view, name="beneficiary_create"),
    path("beneficiaries/<uuid:beneficiary_id>/review", beneficiary_views.beneficiary_review_view, name="beneficiary_review"),
    # Security-Admin Panel (Suspend & Revoke-All only)
    path("security/users", account_views.security_users_view, name="security_users"),
    path(
        "security/users/<uuid:user_id>/challenges",
        account_views.issue_security_challenge_view,
        name="security_user_challenges",
    ),
    path("security/users/<uuid:user_id>/suspend", account_views.suspend_user_view, name="security_user_suspend"),
    path(
        "security/users/<uuid:user_id>/revoke-all",
        account_views.revoke_all_user_view,
        name="security_user_revoke_all",
    ),
    # Role-scoped Audit Log (Read-only)
    path("audit", audit_views.audit_list_view, name="audit_list"),
    # Explicitly prohibited self-service / admin routes (DES-01, DES-09, T-09, T-14, T-15)
    re_path(r"^admin(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_admin"),
    re_path(r"^signup(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_signup"),
    re_path(r"^auth/signup(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_auth_signup"),
    re_path(r"^reset-mfa(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_reset_mfa"),
    re_path(r"^auth/reset-mfa(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_auth_reset_mfa"),
    re_path(r"^auth/change-role(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_change_role"),
    re_path(r"^auth/change-factor(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_change_factor"),
    re_path(r"^security/users/[^/]+/unsuspend(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_unsuspend"),
    re_path(r"^security/users/[^/]+/reset-mfa(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_sec_reset_mfa"),
    re_path(r"^security/users/[^/]+/change-role(?:/.*)?$", account_views.prohibited_route_view, name="prohibited_sec_change_role"),
]

