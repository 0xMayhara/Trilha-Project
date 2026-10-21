"""Settings shared by every environment. Values come from environment variables (CLAUDE.md §7)."""

from pathlib import Path
from urllib.parse import quote

from django.core.exceptions import ImproperlyConfigured

from config.env import env_int, env_origin, env_str

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = env_str("DJANGO_SECRET_KEY")
DEBUG = False
ALLOWED_HOSTS: list[str] = []

INSTALLED_APPS = [
    # Before django.contrib.auth: its createsuperuser/changepassword overrides must win (SPEC-0003).
    "apps.accounts",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "apps.core",
    "apps.audit",
]

MIDDLEWARE = [
    "apps.core.middleware.RequestIdMiddleware",
    "apps.audit.middleware.AuditContextMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "apps.core.middleware.SecurityHeadersMiddleware",
    "apps.core.middleware.AccessLogMiddleware",
    "apps.core.middleware.MaxBodySizeMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env_str("POSTGRES_DB"),
        "USER": env_str("POSTGRES_USER"),
        "PASSWORD": env_str("POSTGRES_PASSWORD"),
        "HOST": env_str("POSTGRES_HOST"),
        "PORT": env_int("POSTGRES_PORT", 5432),
        "CONN_MAX_AGE": env_int("POSTGRES_CONN_MAX_AGE", 60),
        # Reconnect instead of failing the first request after a PostgreSQL restart.
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {
            "connect_timeout": 5,
            "sslmode": env_str("POSTGRES_SSLMODE", "prefer"),
        },
    }
}

REDIS_HOST = env_str("REDIS_HOST")
REDIS_PORT = env_int("REDIS_PORT", 6379)
REDIS_PASSWORD = env_str("REDIS_PASSWORD")
REDIS_BASE_URL = f"redis://:{quote(REDIS_PASSWORD, safe='')}@{REDIS_HOST}:{REDIS_PORT}"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": f"{REDIS_BASE_URL}/1",
        "OPTIONS": {"socket_connect_timeout": 2, "socket_timeout": 2},
    }
}

# Celery (SPEC-0001 SEC-15): JSON only, bounded run time, no result storage by default.
CELERY_BROKER_URL = f"{REDIS_BASE_URL}/0"
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_RESULT_ACCEPT_CONTENT = ["json"]
CELERY_TASK_TIME_LIMIT = 300
CELERY_TASK_SOFT_TIME_LIMIT = 270
CELERY_TASK_IGNORE_RESULT = True
CELERY_RESULT_BACKEND = None
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_WORKER_HIJACK_ROOT_LOGGER = False

AUTH_USER_MODEL = "accounts.User"

# Argon2 first, PBKDF2 as fallback (SPEC-0001 SEC-12).
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Cookies (SPEC-0001 SEC-04). The CSRF cookie stays readable by the frontend, which sends it
# back in the X-CSRFToken header; HttpOnly on it would add no protection.
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_MAX_AGE_LIMIT = 24 * 60 * 60
SESSION_COOKIE_AGE = env_int("DJANGO_SESSION_COOKIE_AGE", 8 * 60 * 60)
if not 0 < SESSION_COOKIE_AGE <= SESSION_COOKIE_MAX_AGE_LIMIT:
    raise ImproperlyConfigured("DJANGO_SESSION_COOKIE_AGE must be between 1 and 86400 seconds.")
# The cookie ends with the browser; the server still enforces SESSION_COOKIE_AGE (SPEC-0003 BR-08).
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Set-password links (SPEC-0003 BR-07, SEC-23): one hour by default, five minutes to one day.
PASSWORD_RESET_TIMEOUT = env_int("DJANGO_PASSWORD_RESET_TIMEOUT", 60 * 60)
if not 5 * 60 <= PASSWORD_RESET_TIMEOUT <= 24 * 60 * 60:
    raise ImproperlyConfigured(
        "DJANGO_PASSWORD_RESET_TIMEOUT must be between 300 and 86400 seconds."
    )
# Where users open Trilha. Used to print set-password links, never taken from the Host header.
TRILHA_BASE_URL = env_origin("TRILHA_BASE_URL", "http://localhost:8080")
# The proxy forwards Host without the published port, so Django's own guess of the origin
# (http://localhost) misses the port the browser sends (http://localhost:8080). Trust exactly the
# configured address; any other Origin is still rejected (SPEC-0003 SEC-03).
CSRF_TRUSTED_ORIGINS = [TRILHA_BASE_URL]

# Security headers (SPEC-0001 SEC-05).
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

# Request body limit (SPEC-0001 SEC-11).
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
CSRF_FAILURE_VIEW = "apps.core.views.csrf_failure"

# API baseline (SPEC-0001): deny by default, session auth, JSON only, bounded pages, throttling.
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["apps.core.api.permissions.DenyAll"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_PAGINATION_CLASS": "apps.core.api.pagination.DefaultPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": env_str("DJANGO_THROTTLE_ANON_RATE", "60/min"),
        "user": env_str("DJANGO_THROTTLE_USER_RATE", "600/min"),
        # Authentication endpoints (SPEC-0003 BR-09). DRF periods are one unit: s, min, hour, day.
        "login_ip": env_str("DJANGO_THROTTLE_LOGIN_IP_RATE", "10/min"),
        "login_username": env_str("DJANGO_THROTTLE_LOGIN_USERNAME_RATE", "10/hour"),
        "password_set": env_str("DJANGO_THROTTLE_PASSWORD_SET_RATE", "10/hour"),
        "password_change": env_str("DJANGO_THROTTLE_PASSWORD_CHANGE_RATE", "10/hour"),
    },
    # Exactly one trusted proxy, which overwrites X-Forwarded-For (SEC-18).
    "NUM_PROXIES": 1,
    "EXCEPTION_HANDLER": "apps.core.api.exceptions.exception_handler",
}

# Structured JSON logs on stdout (SPEC-0001 SEC-13).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"json": {"()": "apps.core.logging.JsonFormatter"}},
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "json",
        }
    },
    "root": {"handlers": ["stdout"], "level": env_str("DJANGO_LOG_LEVEL", "INFO")},
    "loggers": {
        # Replace Django's default console/mail handlers; records propagate to root.
        "django": {"handlers": [], "level": "INFO", "propagate": True},
        # 4xx responses are already covered by the access log.
        "django.request": {"level": "ERROR"},
        "django.security": {"level": "WARNING"},
        # Never log SQL statements with their parameters.
        "django.db.backends": {"level": "WARNING"},
    },
}
