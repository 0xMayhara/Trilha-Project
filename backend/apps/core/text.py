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
