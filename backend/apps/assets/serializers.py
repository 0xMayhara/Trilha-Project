"""Explicit asset I/O shapes (SPEC-0005 API Contract). Inputs accept only listed keys with strict
JSON types (no coercion, CWE-915); services then canonicalize every value. Outputs are read-only."""

import uuid

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from apps.assets.models import Asset, Criticality, Environment, Kind, Status
from apps.assets.validation import canonical_ip, display_ips
from apps.core.text import QUERY_MAX_LENGTH, normalize_text
from apps.teams.serializers import TeamSummarySerializer

_TEXT = (str,)
_NULLABLE_TEXT = (str, type(None))
CREATE_FIELDS = {
    "team_id": _TEXT,
    "name": _TEXT,
    "kind": _TEXT,
    "hostname": _TEXT,
    "ip_addresses": (list,),
    "os_product": _NULLABLE_TEXT,
    "os_version": _TEXT,
    "environment": _NULLABLE_TEXT,
    "criticality": _NULLABLE_TEXT,
    "hardening_status": _NULLABLE_TEXT,
    "internet_exposure": _NULLABLE_TEXT,
}
UPDATE_FIELDS = {
    **{key: types for key, types in CREATE_FIELDS.items() if key != "team_id"},
    "version": (int,),
}
TRANSITION_FIELDS = {"version": (int,)}
# finding_count is optional and ignored for assets without findings (SPEC-0007 BR-16).
TRANSFER_FIELDS = {"version": (int,), "team_id": _TEXT, "finding_count": (int,)}
LIST_FILTERS = ("status", "team", "kind", "environment", "criticality", "ip", "q")


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
    os_label = serializers.SerializerMethodField()

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
            "os_product",
            "os_version",
            "os_label",
            "environment",
            "criticality",
            "hardening_status",
            "internet_exposure",
            "status",
            "version",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    def get_ip_addresses(self, asset):
        return display_ips(asset.ip_addresses)

    def get_os_label(self, asset):
        # Server-derived, so asset pages never depend on the catalog endpoint (NFR-03).
        return asset.get_os_product_display()
