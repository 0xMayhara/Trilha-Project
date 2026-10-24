"""SPEC-0007 BR-22 / SEC-25: plain multi-line text shared by descriptions, comments and reasons."""

import pytest
from django.core.exceptions import ValidationError

from apps.core.text import normalize_multiline_text


def clean(value, *, required=False, max_length=50):
    return normalize_multiline_text(value, required=required, max_length=max_length)


def test_multiline_text_rejects_control_and_bidi_characters_cwe_451():
    rejected = [
        *(chr(code) for code in range(0x202A, 0x202F)),  # bidi embeddings and overrides
        *(chr(code) for code in range(0x2066, 0x206A)),  # bidi isolates
        *(chr(code) for code in range(0x200B, 0x2010)),  # zero-width and direction marks
        chr(0x2028),  # line separator (Zl)
        chr(0x2029),  # paragraph separator (Zp)
        "\x00",
        "\x0b",
        "\x0c",
        "\x1b",
        "\x7f",
        "\x85",
        chr(0xFEFF),
        "\ud800",  # lone surrogate
    ]
    for character in rejected:
        for value in (f"a{character}b", character, f"text{character}"):
            with pytest.raises(ValidationError):
                clean(value)
    # Line breaks and tabs are text; CR LF and lone CR become LF; edges are trimmed.
    assert clean("  line 1\r\n\tline 2\rline 3\n  ") == "line 1\n\tline 2\nline 3"
    assert clean("Cafe" + chr(0x301)) == "Caf" + chr(0xE9)  # NFC
    assert clean("") == ""
    with pytest.raises(ValidationError):
        clean(" \n\t ", required=True)
    assert len(clean("x" * 50)) == 50
    with pytest.raises(ValidationError):
        clean("x" * 51)
    with pytest.raises(ValidationError):
        clean(("e" + chr(0x301)) * 26, max_length=25)  # counted after NFC: 26 characters
    for wrong in (None, 1, ["a"], b"a"):
        with pytest.raises(ValidationError):
            clean(wrong)
