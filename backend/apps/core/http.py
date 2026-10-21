import ipaddress
import logging

from django.http import HttpRequest

logger = logging.getLogger(__name__)


def client_ip(request: HttpRequest) -> str | None:
    """Client address as seen by the single trusted proxy, which appends it as the last
    X-Forwarded-For entry (SPEC-0001 SEC-18). Matches DRF's NUM_PROXIES=1 behavior.

    The proxy always sends a valid address. Anything else means the proxy was bypassed or
    misconfigured: the access log and audit events get no IP rather than the raw value, and the
    audit `inet` column never fails every audited operation (SPEC-0002 SEC-09)."""
    # Cached so the access log and the audit context agree and the warning is logged once.
    if not hasattr(request, "_client_ip"):
        request._client_ip = _valid_ip(_forwarded_ip(request))
    return request._client_ip


def _forwarded_ip(request: HttpRequest) -> str | None:
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[-1].strip()
    return request.META.get("REMOTE_ADDR")


def _valid_ip(address: str | None) -> str | None:
    if not address:
        return None
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        # The raw value is attacker-controlled and is not logged.
        logger.warning("invalid_client_address", extra={"event": "invalid_client_address"})
        return None
