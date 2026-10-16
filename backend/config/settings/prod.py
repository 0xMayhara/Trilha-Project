"""Production settings. Startup fails closed on missing or placeholder secrets (SPEC-0001)."""

from django.core.exceptions import ImproperlyConfigured

from config.env import env_bool, env_int, env_list
from config.settings.base import *

# Never configurable through the environment (SEC-01).
DEBUG = False

_PLACEHOLDER_MARKER = "change-me"


def _require_strong_secret(name: str, value: str, min_length: int) -> None:
    if len(value) < min_length or _PLACEHOLDER_MARKER in value.lower():
        raise ImproperlyConfigured(f"{name} is too short or still a placeholder.")


_require_strong_secret("DJANGO_SECRET_KEY", SECRET_KEY, 50)
_require_strong_secret("POSTGRES_PASSWORD", DATABASES["default"]["PASSWORD"], 16)
_require_strong_secret("REDIS_PASSWORD", REDIS_PASSWORD, 16)

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS")

# TLS terminates at the reverse proxy, which always overwrites X-Forwarded-Proto (SEC-18).
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", True)
SECURE_HSTS_SECONDS = env_int("DJANGO_SECURE_HSTS_SECONDS", 31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS", True)
SECURE_HSTS_PRELOAD = env_bool("DJANGO_SECURE_HSTS_PRELOAD", True)

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
