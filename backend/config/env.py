"""Typed access to environment variables.

Errors name the variable but never echo its value.
"""

import base64
import os
import re
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

MIN_DIGEST_KEY_BYTES = 32
_KEY_ID = re.compile(r"[a-z0-9]{1,16}")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+={0,2}")

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


def env_key_ring(keys_name: str, active_name: str) -> tuple[dict[str, bytes], str]:
    """A key ring of comma-separated `id:base64url` keys and the ID of the one that signs
    (SPEC-0007 SEC-53). Both unset means no ring. Anything else must be complete: unique IDs, keys
    of at least 32 bytes, no placeholder, and an active ID present in the ring."""
    raw = os.environ.get(keys_name, "")
    active = os.environ.get(active_name, "")
    if not raw and not active:
        return {}, ""
    if "change-me" in raw.lower():
        raise ImproperlyConfigured(f"{keys_name} is still a placeholder.")
    ring: dict[str, bytes] = {}
    for part in raw.split(","):
        key_id, separator, encoded = part.strip().partition(":")
        if not separator or not _KEY_ID.fullmatch(key_id) or key_id in ring:
            raise ImproperlyConfigured(f"{keys_name} must list unique id:base64url keys.")
        encoded = encoded.rstrip("=") if _BASE64URL.fullmatch(encoded) else ""
        if not encoded or len(encoded) % 4 == 1:
            raise ImproperlyConfigured(f"{keys_name} keys must be base64url text.")
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if len(key) < MIN_DIGEST_KEY_BYTES:
            raise ImproperlyConfigured(
                f"{keys_name} keys must hold at least {MIN_DIGEST_KEY_BYTES} bytes."
            )
        ring[key_id] = key
    if active not in ring:
        raise ImproperlyConfigured(f"{active_name} must name a key of {keys_name}.")
    return ring, active
