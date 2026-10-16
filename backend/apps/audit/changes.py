"""Builds `changes` from explicit field lists only, so an event never captures a whole model
(password hashes, tokens, internal fields) by accident (SPEC-0002 BR-07, SEC-11)."""

from collections.abc import Mapping, Sequence
from typing import Any

from django.core.exceptions import FieldDoesNotExist
from django.db import models

from apps.audit.exceptions import AuditValidationError


def _check_fields(fields: Sequence[str]) -> None:
    # A bare string is a sequence of characters, which would silently audit the wrong fields.
    if isinstance(fields, str) or not all(isinstance(field, str) for field in fields):
        raise AuditValidationError("Fields must be a sequence of field names.")
    if "__all__" in fields:
        raise AuditValidationError("Audited fields must be listed explicitly.")


def snapshot(instance: models.Model, fields: Sequence[str]) -> dict[str, Any]:
    """Current values of the listed concrete fields (foreign keys as their primary key)."""
    _check_fields(fields)
    values: dict[str, Any] = {}
    for name in fields:
        try:
            field = instance._meta.get_field(name)
        except FieldDoesNotExist as exc:
            raise AuditValidationError(f"Unknown field: {name}") from exc
        if not field.concrete or field.many_to_many:
            raise AuditValidationError(f"Only concrete single-valued fields are audited: {name}")
        values[name] = field.value_from_object(instance)
    return values


def field_changes(
    before: Mapping[str, Any], after: Mapping[str, Any], fields: Sequence[str]
) -> dict[str, dict[str, Any]]:
    """`{"field": {"before": old, "after": new}}` for listed fields whose value changed.
    A field absent from `before` (creation) is recorded with `before` set to None."""
    _check_fields(fields)
    return {
        name: {"before": before.get(name), "after": after.get(name)}
        for name in fields
        if before.get(name) != after.get(name)
    }
