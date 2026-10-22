"""Strict JSON request handling shared by the domain APIs (CLAUDE.md §11, CWE-915)."""

from rest_framework.exceptions import ValidationError


def parse_body(data, schema, *, required):
    """Accepts only the schema's keys, each with one of its JSON types; no coercion."""
    if not isinstance(data, dict):
        raise ValidationError({"non_field_errors": ["Expected a JSON object."]})
    errors = {key: ["This field is not accepted."] for key in data if key not in schema}
    for key, types in schema.items():
        if key not in data:
            if key in required:
                errors[key] = ["This field is required."]
        # bool is an int subclass: true must not pass as a version.
        elif isinstance(data[key], bool) or not isinstance(data[key], types):
            errors[key] = ["Invalid type."]
    if errors:
        raise ValidationError(errors)
    return dict(data)
