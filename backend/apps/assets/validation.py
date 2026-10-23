"""Canonical forms for asset input (SPEC-0005 Validation Rules). Every caller goes through these:
HTTP serializers, services and the `ip` filter."""

import ipaddress
import re

from django.core.exceptions import ValidationError

HOSTNAME_MAX_LENGTH = 253
HOSTNAME_PATTERN = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
MAX_IP_ADDRESSES = 16
# ASCII only (SPEC-0011 D-4); starts and ends alphanumeric. Ranges here never match non-ASCII.
OS_VERSION_MAX_LENGTH = 32
OS_VERSION_PATTERN = r"^[A-Za-z0-9]([A-Za-z0-9 ._+-]{0,30}[A-Za-z0-9])?$"
_IP_TEXT_MAX_LENGTH = 45
_LIMITED_BROADCAST = ipaddress.IPv4Address("255.255.255.255")


def canonical_hostname(value):
    """Empty, or a lowercase ASCII DNS name that is not an IP literal (M-4)."""
    if not isinstance(value, str) or not value.isascii():
        raise ValidationError("Use an ASCII DNS name; non-DNS labels belong in the name.")
    value = value.lower()
    if not value:
        return value
    if len(value) > HOSTNAME_MAX_LENGTH or not re.fullmatch(HOSTNAME_PATTERN, value):
        raise ValidationError(
            "Use a DNS name: dot-separated labels of letters, digits and hyphens."
        )
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValidationError("IP addresses belong in ip_addresses, not hostname.")


def canonical_os_version(value):
    """Empty, or a short ASCII version such as "24.04" or "22H2" (SPEC-0011 SEC-06)."""
    if not isinstance(value, str):
        raise ValidationError("Expected text.")
    value = value.strip()
    if value and not re.fullmatch(OS_VERSION_PATTERN, value):
        raise ValidationError(
            "Use 1 to 32 ASCII letters, digits, spaces, dots, hyphens, underscores or plus signs, "
            "starting and ending with a letter or digit."
        )
    return value


def canonical_ip(value):
    """One host address in canonical form, or ValidationError (SPEC-0005 IP canonicalization)."""
    if not isinstance(value, str) or not value.isascii() or len(value) > _IP_TEXT_MAX_LENGTH:
        raise ValidationError("Enter a valid IPv4 or IPv6 address.")
    if "%" in value:
        raise ValidationError("Zone identifiers are not allowed.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValidationError("Enter a valid IPv4 or IPv6 address.") from None
    if address.version == 6:
        if address.scope_id is not None:
            raise ValidationError("Zone identifiers are not allowed.")
        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped
    # Explicit predicates only: never is_reserved/is_global/is_private (F-20). Subnet-directed
    # broadcasts cannot be recognized without a prefix, so they are not claimed to be rejected.
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address == _LIMITED_BROADCAST
    ):
        raise ValidationError(
            "Unspecified, loopback, multicast and broadcast addresses are not host addresses."
        )
    return address


def canonical_ip_list(values):
    """Deduplicated, ordered canonical text: IPv4 before IPv6, then numeric order."""
    if not isinstance(values, list) or len(values) > MAX_IP_ADDRESSES:
        raise ValidationError(f"Provide a list of at most {MAX_IP_ADDRESSES} addresses.")
    addresses = {canonical_ip(value) for value in values}
    return [str(address) for address in sorted(addresses, key=lambda a: (a.version, int(a)))]


def display_ips(values):
    """Stored values rendered with the same canonical text (PostgreSQL's inet text may differ)."""
    return [str(ipaddress.ip_address(value)) for value in values]
