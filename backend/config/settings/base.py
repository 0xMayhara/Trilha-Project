"""Settings shared by every environment. Values come from environment variables (CLAUDE.md §7)."""

from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from config.env import env_int, env_str

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = env_str("DJANGO_SECRET_KEY")
DEBUG = False
ALLOWED_HOSTS: list[str] = []

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "apps.accounts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
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
        "OPTIONS": {
            "connect_timeout": 5,
            "sslmode": env_str("POSTGRES_SSLMODE", "prefer"),
        },
    }
}

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

# Security headers (SPEC-0001 SEC-05).
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

# Request body limit (SPEC-0001 SEC-11).
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
