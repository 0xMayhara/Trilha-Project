"""Canonical forms for asset input (SPEC-0005 Validation Rules). Every caller goes through these:
HTTP serializers, services and the `ip` filter."""

import ipaddress
import re
import unicodedata

from django.core.exceptions import ValidationError

TEXT_MAX_LENGTH = 150
QUERY_MAX_LENGTH = 100
HOSTNAME_MAX_LENGTH = 253
HOSTNAME_PATTERN = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
MAX_IP_ADDRESSES = 16
_IP_TEXT_MAX_LENGTH = 45
# Controls, surrogates and format characters (bidi overrides, zero-width) are never display text.
_REJECTED_CATEGORIES = frozenset({"Cc", "Cs", "Cf"})
_LIMITED_BROADCAST = ipaddress.IPv4Address("255.255.255.255")


def normalize_text(value, *, required, max_length=TEXT_MAX_LENGTH):
    """NFC first, then trim, then length and character-category checks (M-3, F-19)."""
    if not isinstance(value, str):
        raise ValidationError("Expected text.")
    value = unicodedata.normalize("NFC", value).strip()
    if required and not value:
        raise ValidationError("This field may not be blank.")
    if len(value) > max_length:
        raise ValidationError(f"Use at most {max_length} characters.")
    if any(unicodedata.category(char) in _REJECTED_CATEGORIES for char in value):
        raise ValidationError("Control, surrogate and format characters are not allowed.")
    return value


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
