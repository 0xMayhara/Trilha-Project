"""Typed access to environment variables.

Errors name the variable but never echo its value.
"""

import os
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def env_str(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise ImproperlyConfigured(f"Environment variable {name} is required.")
    return value


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    raise ImproperlyConfigured(f"Environment variable {name} must be a boolean.")


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ImproperlyConfigured(f"Environment variable {name} must be an integer.") from None


def env_list(name: str, default: str | None = None) -> list[str]:
    raw = env_str(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def env_origin(name: str, default: str) -> str:
    """An http(s) origin such as https://trilha.example.com:8443: no credentials, path, query or
    fragment."""
    parts = urlsplit(env_str(name, default))
    try:
        # .port raises ValueError for a non-numeric or out-of-range port.
        valid_port = parts.port != 0
    except ValueError:
        valid_port = False
    if (
        not valid_port
        or parts.scheme not in {"http", "https"}
        or not parts.hostname
        or "@" in parts.netloc
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ImproperlyConfigured(
            f"Environment variable {name} must be an http(s) origin such as https://trilha.example.com."
        )
    return f"{parts.scheme}://{parts.netloc}"
