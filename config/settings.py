"""
Django 5.2 LTS settings for SecurePay Lab (Topic 5).
Implements strict baseline security controls (DES-01..DES-10).
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

env_path = BASE_DIR / ".env"
if env_path.exists():
    from dotenv import load_dotenv

    load_dotenv(env_path)

SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "securepay-lab-local-dev-secret-key-not-for-public-production-use-2026",
)

HTTPS_PROFILE = os.environ.get("SECUREPAY_HTTPS_PROFILE", "False").lower() in ("1", "true", "yes")
DEBUG = False if HTTPS_PROFILE else (os.environ.get("DJANGO_DEBUG", "True").lower() in ("1", "true", "yes"))

ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver").split(",")
    if h.strip()
]

CSRF_TRUSTED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "DJANGO_CSRF_TRUSTED_ORIGINS",
        "http://127.0.0.1:8000,http://localhost:8000,https://127.0.0.1:8443,https://localhost:8443",
    ).split(",")
    if o.strip()
]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "django_otp",
    "django_otp.plugins.otp_totp",
    "apps.common",
    "apps.accounts",
    "apps.beneficiaries",
    "apps.payments",
    "apps.audit",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "apps.accounts.middleware.SecurityEpochSessionMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.accounts.context_processors.security_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# PostgreSQL 16/17 Database Configuration (Never SQLite for acceptance)
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "securepay_lab"),
        "USER": os.environ.get("POSTGRES_USER", "securepay_user"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "securepay_local_dev_pw"),
        "HOST": os.environ.get("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.environ.get("POSTGRES_PORT", "55432"),
        "CONN_MAX_AGE": 0,
    }
}

AUTH_USER_MODEL = "accounts.EmployeeIdentity"

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "vi"
TIME_ZONE = "Asia/Ho_Chi_Minh"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Session & Cookie Security Settings (Section 3.1 & 5.3)
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = HTTPS_PROFILE
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = int(os.environ.get("SESSION_MAX_LIFETIME_SECONDS", "28800"))  # 8 hours max

CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = HTTPS_PROFILE

if HTTPS_PROFILE:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = os.environ.get("SECURE_SSL_REDIRECT", "True").lower() in ("1", "true", "yes")
    SECURE_HSTS_SECONDS = 3600
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_CONTENT_TYPE_NOSNIFF = True

# Baseline Security Policy Settings (Section 3.1)
CHALLENGE_TTL_SECONDS = int(os.environ.get("CHALLENGE_TTL_SECONDS", "120"))
REQUEST_TTL_HOURS = int(os.environ.get("REQUEST_TTL_HOURS", "24"))
PREAUTH_TTL_SECONDS = int(os.environ.get("PREAUTH_TTL_SECONDS", "300"))
SESSION_IDLE_TIMEOUT_SECONDS = int(os.environ.get("SESSION_IDLE_TIMEOUT_SECONDS", "1800"))
SESSION_MAX_LIFETIME_SECONDS = int(os.environ.get("SESSION_MAX_LIFETIME_SECONDS", "28800"))

MAX_PASSWORD_ATTEMPTS = int(os.environ.get("MAX_PASSWORD_ATTEMPTS", "5"))
PASSWORD_COOLDOWN_SECONDS = int(os.environ.get("PASSWORD_COOLDOWN_SECONDS", "300"))
MAX_OTP_ATTEMPTS = int(os.environ.get("MAX_OTP_ATTEMPTS", "5"))
OTP_COOLDOWN_SECONDS = int(os.environ.get("OTP_COOLDOWN_SECONDS", "300"))

MAX_AMOUNT_VND = 1_000_000_000_000
MAX_PURPOSE_LENGTH = 500
MAX_SOURCE_EXCERPT_LENGTH = 2000

LOGIN_URL = "/auth/login"

