"""Typed access to environment variables.

Errors name the variable but never echo its value.
"""

import os

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
