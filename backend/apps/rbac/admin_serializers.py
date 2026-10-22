"""Explicit I/O of the administration API (SPEC-0010 Schemas). Outputs are read-only and minimal:
no password hash, native flags, groups, permissions or session data (SEC-14, CWE-200). Inputs are
parsed by allowlist before any query runs (SEC-21, CWE-943)."""

import re
import uuid
from datetime import datetime, timedelta

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from apps.audit.models import ACTION_PATTERN, RESOURCE_TYPE_PATTERN, Outcome, Source
from apps.core.text import QUERY_MAX_LENGTH, normalize_text
from apps.rbac.catalog import PERMISSION_CODES
from apps.rbac.models import Position
from apps.rbac.serializers import RoleSummarySerializer

TEXT = (str,)
NULLABLE_TEXT = (str, type(None))
USER_FILTERS = ("q", "is_active", "is_admin", "position")
TEAM_FILTERS = ("q", "is_active")
ROLE_FILTERS = ("q",)
AUDIT_FILTERS = (
    "action",
    "actor_id",
    "resource_type",
    "resource_id",
    "outcome",
    "source",
    "occurred_after",
    "occurred_before",
)
AUDIT_DEFAULT_SPAN = timedelta(days=30)
AUDIT_MAX_SPAN = timedelta(days=366)
_REVISION = re.compile(r"^[0-9a-f]{64}\Z")
_RESOURCE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}\Z")
_ACTION = re.compile(ACTION_PATTERN)
_RESOURCE_TYPE = re.compile(RESOURCE_TYPE_PATTERN)


# Inputs


def uuid_value(data, key):
    try:
        return uuid.UUID(data[key])
    except ValueError:
        raise ValidationError({key: ["Expected a UUID."]}) from None


def revision_value(data):
    if not _REVISION.match(data["revision"]):
        raise ValidationError({"revision": ["Expected the preview's revision."]})
    return data["revision"]


def position_value(data):
    position = data["position"]
    if position is not None and position not in Position.values:
        raise ValidationError({"position": ["Choose analyst, engineer or null."]})
    return position


def _boolean(params, key, errors):
    if key in params:
        if params[key] in {"true", "false"}:
            return params[key] == "true"
        errors[key] = ["Choose true or false."]
    return None


def _text(params, key, errors):
    if key in params:
        try:
            return normalize_text(params[key], required=True, max_length=QUERY_MAX_LENGTH)
        except DjangoValidationError as exc:
            errors[key] = exc.messages
    return None


def _raise(errors):
    if errors:
        raise ValidationError(errors)


def user_filters(params):
    errors = {}
    filters = {
        "q": _text(params, "q", errors),
        "is_active": _boolean(params, "is_active", errors),
        "is_admin": _boolean(params, "is_admin", errors),
        "position": params.get("position"),
    }
    if filters["position"] not in {None, "none", *Position.values}:
        errors["position"] = ["Choose analyst, engineer or none."]
    _raise(errors)
    return filters


def team_filters(params):
    errors = {}
    filters = {"q": _text(params, "q", errors), "is_active": _boolean(params, "is_active", errors)}
    _raise(errors)
    return filters


def role_filters(params):
    errors = {}
    filters = {"q": _text(params, "q", errors)}
    _raise(errors)
    return filters


def _matching(params, key, pattern, max_length, errors):
    value = params.get(key)
    if value is not None and (len(value) > max_length or not pattern.match(value)):
        errors[key] = ["Invalid value."]
    return value


def _choice(params, key, choices, errors):
    value = params.get(key)
    if value is not None and value not in choices.values:
        errors[key] = [f"Choose one of: {', '.join(choices.values)}."]
    return value


def _moment(params, key, errors):
    value = params.get(key)
    if value is None:
        return None
    try:
        moment = datetime.fromisoformat(value) if len(value) <= 40 else None
    except ValueError:
        moment = None
    if moment is None or moment.tzinfo is None:
        errors[key] = ["Use an ISO 8601 date and time with an offset."]
    return moment


def audit_filters(params):
    """Exact-match filters and a bounded time range (default: the last 30 days, at most 366)."""
    errors = {}
    filters = {
        "action": _matching(params, "action", _ACTION, 100, errors),
        "resource_type": _matching(params, "resource_type", _RESOURCE_TYPE, 100, errors),
        "resource_id": _matching(params, "resource_id", _RESOURCE_ID, 64, errors),
        "outcome": _choice(params, "outcome", Outcome, errors),
        "source": _choice(params, "source", Source, errors),
        "actor_id": None,
    }
    if "actor_id" in params:
        try:
            filters["actor_id"] = uuid.UUID(params["actor_id"])
        except ValueError:
            errors["actor_id"] = ["Expected a UUID."]
    after, before = (
        _moment(params, "occurred_after", errors),
        _moment(params, "occurred_before", errors),
    )
    _raise(errors)
    if before is None:
        before = timezone.now()
    if after is None:
        after = before - AUDIT_DEFAULT_SPAN
    if not after < before or before - after > AUDIT_MAX_SPAN:
        raise ValidationError(
            {"occurred_after": ["The range must be increasing and at most 366 days long."]}
        )
    return {**filters, "occurred_after": after, "occurred_before": before}


# Outputs


class UserAdminSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    username = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    email = serializers.CharField()
    is_active = serializers.BooleanField()
    password_set = serializers.SerializerMethodField()
    is_admin = serializers.BooleanField()
    position = serializers.CharField(allow_null=True)
    date_joined = serializers.DateTimeField()
    last_login = serializers.DateTimeField(allow_null=True)

    def get_password_set(self, user):
        return user.has_usable_password()


class TeamAdminSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    code = serializers.CharField()
    name = serializers.CharField()
    is_active = serializers.BooleanField()
    member_count = serializers.IntegerField()


class _MemberUserSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    username = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    is_active = serializers.BooleanField()


def _roles(membership):
    return RoleSummarySerializer([item.role for item in membership.display_roles], many=True).data


class MemberSerializer(serializers.Serializer):
    membership_id = serializers.UUIDField(source="pk")
    user = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()

    def get_user(self, membership):
        return {
            **_MemberUserSerializer(membership.user).data,
            "position": membership.user_position,
        }

    def get_roles(self, membership):
        return _roles(membership)


class UserMembershipSerializer(serializers.Serializer):
    membership_id = serializers.UUIDField(source="pk")
    team = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()

    def get_team(self, membership):
        team = membership.team
        team.member_count = membership.team_member_count
        return TeamAdminSerializer(team).data

    def get_roles(self, membership):
        return _roles(membership)


class UserAdminDetailSerializer(UserAdminSerializer):
    memberships = serializers.SerializerMethodField()

    def get_memberships(self, user):
        return UserMembershipSerializer(user.display_memberships, many=True).data


class RoleAdminSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    code = serializers.CharField()
    name = serializers.CharField()
    permissions = serializers.SerializerMethodField()

    def get_permissions(self, role):
        return sorted(PERMISSION_CODES[p.natural_key()] for p in role.display_permissions)


def activation_preview(preview, team):
    return {
        "team": TeamAdminSerializer(team).data,
        "membership_count": preview.membership_count,
        "role_assignment_count": preview.role_assignment_count,
        "revision": preview.revision,
    }


def password_link(url):
    return {"url": url, "expires_in_seconds": settings.PASSWORD_RESET_TIMEOUT}


class AuditTrailEntrySerializer(serializers.Serializer):
    """One audit record (SPEC-0010 audit search schema). Payloads were redacted when recorded
    and are returned as stored data; clients render them as text (SEC-26)."""

    event_id = serializers.UUIDField()
    occurred_at = serializers.DateTimeField()
    actor = serializers.SerializerMethodField()
    action = serializers.CharField()
    outcome = serializers.CharField()
    resource = serializers.SerializerMethodField()
    source = serializers.CharField()
    request_id = serializers.UUIDField(allow_null=True)
    client_ip = serializers.IPAddressField(allow_null=True)
    changes = serializers.JSONField()
    metadata = serializers.JSONField()

    def get_actor(self, entry):
        actor_id = str(entry.actor_id) if entry.actor_id else None
        return {"type": entry.actor_type, "id": actor_id, "label": entry.actor_label}

    def get_resource(self, entry):
        return {"type": entry.resource_type, "id": entry.resource_id}
