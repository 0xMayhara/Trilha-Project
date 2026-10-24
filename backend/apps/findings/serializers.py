"""Explicit finding I/O shapes (SPEC-0007 API Contract). Inputs accept only listed keys with strict
JSON types; services canonicalize every value. Every output field is read-only."""

import uuid

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from apps.core.text import QUERY_MAX_LENGTH, normalize_text
from apps.findings.models import Category, Finding, FindingLogEntry, Severity, Status
from apps.findings.selectors import capabilities
from apps.teams.serializers import TeamSummarySerializer

_TEXT = (str,)
CREATE_FIELDS = {
    "asset_id": _TEXT,
    "title": _TEXT,
    "description": _TEXT,
    "category": _TEXT,
    "severity": _TEXT,
    "cve_ids": (list,),
}
UPDATE_FIELDS = {
    **{key: types for key, types in CREATE_FIELDS.items() if key != "asset_id"},
    "version": (int,),
}
LIST_FILTERS = ("status", "severity", "category", "team", "asset", "assignee", "q")
LOGBOOK_QUERY = ("after", "before", "limit")
CURSOR_MAX = 2_147_483_647
LIMIT_MAX = 100


def _uuid_param(params, key, errors):
    try:
        return uuid.UUID(params[key])
    except ValueError:
        errors[key] = ["Expected a UUID."]
        return None


def parse_list_query(params, user_id):
    """Allowlisted filters; keys and repetition are already checked by validate_query."""
    filters, errors = {}, {}
    for key, choices in (("status", Status), ("severity", Severity), ("category", Category)):
        if key in params:
            if params[key] in choices.values:
                filters[key] = params[key]
            else:
                errors[key] = [f"Choose one of: {', '.join(choices.values)}."]
    for key, field in (("team", "team_id"), ("asset", "asset_id")):
        if key in params:
            filters[field] = _uuid_param(params, key, errors)
    if "assignee" in params:
        if params["assignee"] == "me":
            filters["assignee_id"] = user_id
        elif params["assignee"] == "none":
            filters["unassigned"] = True
        else:
            filters["assignee_id"] = _uuid_param(params, "assignee", errors)
    if "q" in params:
        try:
            filters["q"] = normalize_text(params["q"], required=True, max_length=QUERY_MAX_LENGTH)
        except DjangoValidationError as exc:
            errors["q"] = exc.messages
    if errors:
        raise ValidationError(errors)
    return filters


def _integer(value, low, high):
    # Decimal ASCII digits only: no sign, space, exponent or other scripts' digits.
    if value.isascii() and value.isdecimal() and len(value) <= 10 and low <= int(value) <= high:
        return int(value)
    return None


def parse_logbook_query(params):
    """`after` or `before` (0 to 2^31-1, not both) and `limit` (1-100, default 50) (SEC-31)."""
    cursor, errors = {}, {}
    for key in ("after", "before"):
        if key in params:
            cursor[key] = _integer(params[key], 0, CURSOR_MAX)
            if cursor[key] is None:
                errors[key] = [f"Expected an integer from 0 to {CURSOR_MAX}."]
    if "after" in params and "before" in params:
        errors["query"] = ["Use either after or before, not both."]
    cursor["limit"] = _integer(params.get("limit", "50"), 1, LIMIT_MAX)
    if cursor["limit"] is None:
        errors["limit"] = [f"Expected an integer from 1 to {LIMIT_MAX}."]
    if errors:
        raise ValidationError(errors)
    return cursor


def user_ref(user):
    if user is None:
        return None
    return {"id": user.pk, "username": user.username, "display_name": user.get_full_name()}


class FindingSummarySerializer(serializers.ModelSerializer):
    asset = serializers.SerializerMethodField()
    team = serializers.SerializerMethodField()
    assignee = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = (
            "id",
            "title",
            "severity",
            "category",
            "status",
            "created_at",
            "asset",
            "team",
            "assignee",
        )
        read_only_fields = fields

    def get_asset(self, finding):
        asset = finding.asset
        return {"id": asset.pk, "name": asset.name, "status": asset.status}

    def get_team(self, finding):
        # Always the asset's current team (BR-01): the finding stores none.
        return TeamSummarySerializer(finding.asset.team).data

    def get_assignee(self, finding):
        return user_ref(finding.assignee)


class FindingSerializer(FindingSummarySerializer):
    reported_by = serializers.SerializerMethodField()
    capabilities = serializers.SerializerMethodField()

    class Meta(FindingSummarySerializer.Meta):
        fields = (
            *FindingSummarySerializer.Meta.fields,
            "version",
            "description",
            "cve_ids",
            "updated_at",
            "reported_by",
            "capabilities",
        )
        read_only_fields = fields

    def get_asset(self, finding):
        asset = finding.asset
        return {
            "id": asset.pk,
            "name": asset.name,
            "status": asset.status,
            "kind": asset.kind,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "hardening_status": asset.hardening_status,
            "internet_exposure": asset.internet_exposure,
            "os_label": asset.get_os_product_display(),
            "os_version": asset.os_version,
        }

    def get_reported_by(self, finding):
        return user_ref(finding.reported_by)

    def get_capabilities(self, finding):
        return capabilities(self.context["principal"], finding)


class EntrySerializer(serializers.ModelSerializer):
    event = serializers.SerializerMethodField()
    actor = serializers.SerializerMethodField()
    body = serializers.SerializerMethodField()
    redacted = serializers.SerializerMethodField()

    class Meta:
        model = FindingLogEntry
        fields = (
            "id",
            "sequence",
            "kind",
            "event",
            "actor",
            "body",
            "metadata",
            "created_at",
            "redacted",
            "redacted_at",
            "redaction_reason",
        )
        read_only_fields = fields

    def get_event(self, entry):
        return entry.event or None

    def get_actor(self, entry):
        return user_ref(entry.actor)

    def get_body(self, entry):
        # System entries have no body; a redacted comment's content is gone (BR-51).
        if entry.kind != "comment" or entry.redacted_at is not None:
            return None
        return entry.body

    def get_redacted(self, entry):
        return entry.redacted_at is not None
