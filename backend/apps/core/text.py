"""Canonical display text shared by the domain modules (SPEC-0005 M-3, F-19)."""

import unicodedata

from django.core.exceptions import ValidationError

TEXT_MAX_LENGTH = 150
QUERY_MAX_LENGTH = 100
# Controls, surrogates and format characters (bidi overrides, zero-width) are never display text.
_REJECTED_CATEGORIES = frozenset({"Cc", "Cs", "Cf"})


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


_MULTILINE_ALLOWED = frozenset("\n\t")
# Line and paragraph separators would break lines invisibly, like bidi and zero-width characters.
_MULTILINE_REJECTED = _REJECTED_CATEGORIES | {"Zl", "Zp"}


def normalize_multiline_text(value, *, required, max_length):
    """Plain multi-line text (SPEC-0007 BR-22): NFC, CR LF and CR become LF, then trim. Only LF and
    tab survive among controls; the check runs before trimming, so nothing rejected is ever
    silently dropped from the edges (CWE-451)."""
    if not isinstance(value, str):
        raise ValidationError("Expected text.")
    value = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
    if any(
        char not in _MULTILINE_ALLOWED and unicodedata.category(char) in _MULTILINE_REJECTED
        for char in value
    ):
        raise ValidationError(
            "Control, format and separator characters other than line breaks and tabs are not "
            "allowed."
        )
    value = value.strip()
    if required and not value:
        raise ValidationError("This field may not be blank.")
    if len(value) > max_length:
        raise ValidationError(f"Use at most {max_length} characters.")
    return value
