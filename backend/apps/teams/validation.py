import re
import unicodedata

from django.core.exceptions import ValidationError

CODE_PATTERN = r"^[a-z][a-z0-9_-]{0,62}$"


def validate_code(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(CODE_PATTERN, value):
        raise ValidationError("Codes require 1-63 lowercase ASCII letters, digits, _ or -.")


def validate_name(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 150
        or any(unicodedata.category(char) in {"Cc", "Cs"} for char in value)
    ):
        raise ValidationError(
            "Names require 1-150 trimmed characters without controls or surrogates."
        )
