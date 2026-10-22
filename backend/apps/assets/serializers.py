"""Explicit asset I/O shapes (SPEC-0005 API Contract). Inputs accept only listed keys with strict
JSON types (no coercion, CWE-915); services then canonicalize every value. Outputs are read-only."""

import uuid

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from apps.assets.models import Asset, Criticality, Environment, Kind, Status
from apps.assets.validation import QUERY_MAX_LENGTH, canonical_ip, display_ips, normalize_text
from apps.teams.serializers import TeamSummarySerializer

_TEXT = (str,)
_NULLABLE_TEXT = (str, type(None))
CREATE_FIELDS = {
    "team_id": _TEXT,
    "name": _TEXT,
    "kind": _TEXT,
    "hostname": _TEXT,
    "ip_addresses": (list,),
    "operating_system": _TEXT,
    "environment": _NULLABLE_TEXT,
    "criticality": _NULLABLE_TEXT,
}
UPDATE_FIELDS = {
    **{key: types for key, types in CREATE_FIELDS.items() if key != "team_id"},
    "version": (int,),
}
TRANSITION_FIELDS = {"version": (int,)}
TRANSFER_FIELDS = {"version": (int,), "team_id": _TEXT}
LIST_FILTERS = ("status", "team", "kind", "environment", "criticality", "ip", "q")


def parse_body(data, schema, *, required):
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


def parse_list_query(params):
    """Allowlisted filters; keys and repetition are already checked by validate_query."""
    filters = {"status": params.get("status", Status.ACTIVE)}
    errors = {}
    if filters["status"] not in Status.values:
        errors["status"] = ["Choose active or retired."]
    if "team" in params:
        try:
            filters["team_id"] = uuid.UUID(params["team"])
        except ValueError:
            errors["team"] = ["Expected a UUID."]
    for key, choices in (
        ("kind", Kind),
        ("environment", Environment),
        ("criticality", Criticality),
    ):
        if key in params:
            if params[key] in choices.values:
                filters[key] = params[key]
            else:
                errors[key] = [f"Choose one of: {', '.join(choices.values)}."]
    for key, parse in (
        ("ip", lambda value: str(canonical_ip(value))),
        ("q", lambda value: normalize_text(value, required=True, max_length=QUERY_MAX_LENGTH)),
    ):
        if key in params:
            try:
                filters[key] = parse(params[key])
            except DjangoValidationError as exc:
                errors[key] = exc.messages
    if errors:
        raise ValidationError(errors)
    return filters


class AssetSerializer(serializers.ModelSerializer):
    team = TeamSummarySerializer(read_only=True)
    ip_addresses = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = (
            "id",
            "team",
            "name",
            "kind",
            "hostname",
            "ip_addresses",
            "operating_system",
            "environment",
            "criticality",
            "status",
            "version",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    def get_ip_addresses(self, asset):
        return display_ips(asset.ip_addresses)
