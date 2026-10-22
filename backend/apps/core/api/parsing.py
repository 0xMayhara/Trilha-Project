"""Strict JSON request handling shared by the domain APIs (CLAUDE.md §11, CWE-915)."""

import json

from django.conf import settings
from rest_framework.exceptions import ParseError, ValidationError
from rest_framework.parsers import JSONParser


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


def _unique_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ParseError("Repeated JSON keys are not accepted.")
    return dict(pairs)


class StrictJSONParser(JSONParser):
    """JSONParser that rejects repeated object keys instead of keeping the last one."""

    def parse(self, stream, media_type=None, parser_context=None):
        encoding = (parser_context or {}).get("encoding", settings.DEFAULT_CHARSET)
        try:
            return json.loads(stream.read().decode(encoding), object_pairs_hook=_unique_keys)
        except ParseError:
            raise
        except ValueError as exc:
            raise ParseError("Malformed request body.") from exc
