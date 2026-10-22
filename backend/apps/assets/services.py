"""Asset use cases (SPEC-0005). Transport-independent: each one validates, locks, rechecks
authorization, compares the version, writes and audits inside one transaction.

Lock protocol (SPEC-0005 Concurrency / Idempotency): Role* -> Team* (UUID order) -> User, the
SPEC-0004 global order, then the Asset row last. Every RBAC or account writer that can reduce the
actor's authority holds FOR UPDATE on one of those rows, so it either commits before the recheck
or waits for this transaction to commit."""

import logging
import uuid
from contextlib import contextmanager

from django.core.exceptions import ValidationError
from django.db import IntegrityError, OperationalError, transaction

from apps.accounts.selectors import users
from apps.assets.exceptions import (
    AssetForbidden,
    AssetIntegrityFailure,
    AssetNotFound,
    InvalidState,
    NameTaken,
    StaleAsset,
    TeamUnavailable,
)
from apps.assets.models import ACTIVE_NAME_CONSTRAINT, Asset, Criticality, Environment, Kind, Status
from apps.assets.selectors import scoped_assets
from apps.assets.validation import (
    canonical_hostname,
    canonical_ip_list,
    display_ips,
    normalize_text,
)
from apps.audit.changes import snapshot
from apps.rbac import events
from apps.rbac.catalog import catalog_action
from apps.rbac.locking import bound_lock_waits, lock_failure
from apps.rbac.principals import UserPrincipal
from apps.rbac.selectors import assignments, can_access, roles, scoped_teams
from apps.teams.selectors import teams

logger = logging.getLogger("apps.assets")

ASSET_LOCK_TIMEOUT = "5s"
VIEW, ADD, CHANGE, RETIRE, TRANSFER = (
    "assets.view_asset",
    "assets.add_asset",
    "assets.change_asset",
    "assets.retire_asset",
    "assets.transfer_asset",
)
MUTABLE_FIELDS = (
    "name",
    "kind",
    "hostname",
    "ip_addresses",
    "operating_system",
    "environment",
    "criticality",
)
CREATED_FIELDS = ("team_id", *MUTABLE_FIELDS, "status")


def _choice(choices, *, nullable=False):
    def clean(value):
        if value is None and nullable:
            return None
        if not isinstance(value, str) or value not in choices.values:
            raise ValidationError(f"Choose one of: {', '.join(choices.values)}.")
        return value

    return clean


_CLEANERS = {
    "name": lambda value: normalize_text(value, required=True),
    "kind": _choice(Kind),
    "hostname": canonical_hostname,
    "ip_addresses": canonical_ip_list,
    "operating_system": lambda value: normalize_text(value, required=False),
    "environment": _choice(Environment, nullable=True),
    "criticality": _choice(Criticality, nullable=True),
}


def _clean(values):
    """Canonical values for the listed attributes; any other key is refused (CWE-915)."""
    errors = {field: ["This field cannot be set."] for field in values if field not in _CLEANERS}
    cleaned = {}
    for field, value in values.items():
        if field in _CLEANERS:
            try:
                cleaned[field] = _CLEANERS[field](value)
            except ValidationError as exc:
                errors[field] = exc.messages
    if errors:
        raise ValidationError(errors)
    return cleaned


def _version(value):
    # bool is an int subclass; a JSON true must not pass as version 1.
    if type(value) is not int or value < 1:
        raise ValidationError({"version": ["Expected a positive integer."]})
    return value


def _uuid(value, field=None):
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (TypeError, ValueError):
        if field:
            raise ValidationError({field: ["Expected a UUID."]}) from None
        raise AssetNotFound from None


def _require_user(principal):
    # Operator, system and provider principals have no asset authority in this release (SEC-08).
    if not isinstance(principal, UserPrincipal):
        raise AssetForbidden


def _constraint(cause):
    return getattr(getattr(cause, "diag", None), "constraint_name", None)


def _lock_unavailable(operation, principal, reason):
    logger.warning(
        "asset_lock_unavailable",
        extra={"operation": operation, "actor_id": str(principal.user_id), "reason": reason},
    )


@contextmanager
def _mutation(operation, principal):
    """One transaction with bounded lock waits; database failures are reported without details."""
    try:
        with transaction.atomic():
            bound_lock_waits(ASSET_LOCK_TIMEOUT)
            yield
    except IntegrityError as exc:
        cause = exc.__cause__
        # Identified by SQLSTATE and constraint name, never by message text (SEC-31).
        if getattr(cause, "sqlstate", None) == "23505" and _constraint(cause) == (
            ACTIVE_NAME_CONSTRAINT
        ):
            raise NameTaken from None
        logger.error(
            "asset_integrity_error",
            extra={"operation": operation, "constraint": _constraint(cause)},
        )
        raise AssetIntegrityFailure from None
    except OperationalError as exc:
        reason = lock_failure(exc)
        if reason is None:
            raise
        _lock_unavailable(operation, principal, reason)
        # A fresh error without the database cause: the 503 handler logs no SQL or row data.
        raise OperationalError("Asset lock unavailable.") from None


def _eligible(principal, team_id):
    return scoped_teams(principal).filter(pk=team_id).exists()


def _require(principal, team_id, codes, asset=None):
    for code in codes:
        if not can_access(principal, code, team_id=team_id, action=catalog_action(code)):
            raise AssetForbidden(asset.pk if asset is not None else None)


def _lock(principal, operation, team_ids):
    team_ids = sorted(set(team_ids))

    def role_ids():
        return set(
            assignments()
            .filter(membership__user_id=principal.user_id, membership__team_id__in=team_ids)
            .values_list("role_id", flat=True)
        )

    candidates = role_ids()
    # Lock by primary key only: no row data (such as the password hash) is read into memory.
    for rows in (
        roles().filter(pk__in=candidates),
        teams().filter(pk__in=team_ids),
        users().filter(pk=principal.user_id),
    ):
        list(rows.select_for_update(no_key=True).order_by("pk").values_list("pk", flat=True))
    # A role assigned before the Team locks is not locked; never acquire a Role after a Team.
    if not role_ids() <= candidates:
        _lock_unavailable(operation, principal, "role_drift")
        raise StaleAsset


def _source_team(principal, asset_id):
    try:
        return scoped_assets(principal).values_list("team_id", flat=True).get(pk=asset_id)
    except Asset.DoesNotExist:
        raise AssetNotFound from None


def _relock(principal, asset_id, source):
    try:
        asset = scoped_assets(principal).select_for_update().get(pk=asset_id)
    except Asset.DoesNotExist:
        raise AssetNotFound from None
    if asset.team_id != source:
        raise StaleAsset
    asset.ip_addresses = display_ips(asset.ip_addresses)
    return asset


def _check_version(asset, version):
    if asset.version != version:
        raise StaleAsset


def create_asset(principal, *, team_id, **fields):
    _require_user(principal)
    team_id = _uuid(team_id, "team_id")
    missing = {
        field: ["This field is required."] for field in ("name", "kind") if field not in fields
    }
    if missing:
        raise ValidationError(missing)
    values = _clean(fields)
    with _mutation("create", principal):
        if not _eligible(principal, team_id):
            raise TeamUnavailable
        _lock(principal, "create", {team_id})
        if not _eligible(principal, team_id):
            raise TeamUnavailable
        _require(principal, team_id, (VIEW, ADD))
        asset = Asset.objects.create(team_id=team_id, **values)
        events.emit(principal, "assets.asset_created", asset, fields=CREATED_FIELDS)
    return asset


def update_asset(principal, asset_id, *, version, changes):
    _require_user(principal)
    version = _version(version)
    asset_id = _uuid(asset_id)
    if not isinstance(changes, dict) or not changes:
        raise ValidationError({"non_field_errors": ["Provide at least one field to change."]})
    values = _clean(changes)
    with _mutation("update", principal):
        source = _source_team(principal, asset_id)
        _lock(principal, "update", {source})
        asset = _relock(principal, asset_id, source)
        _require(principal, source, (VIEW, CHANGE), asset)
        _check_version(asset, version)  # before no-op detection (SEC-11)
        if asset.status != Status.ACTIVE:
            raise InvalidState
        changed = tuple(field for field, value in values.items() if getattr(asset, field) != value)
        if not changed:
            return asset
        before = snapshot(asset, changed)
        for field in changed:
            setattr(asset, field, values[field])
        asset.version += 1
        asset.save(update_fields=[*changed, "version", "updated_at"])
        events.emit(principal, "assets.asset_updated", asset, before=before, fields=changed)
    return asset


def _transition(principal, asset_id, version, *, operation, source_status, target_status, action):
    _require_user(principal)
    version = _version(version)
    asset_id = _uuid(asset_id)
    with _mutation(operation, principal):
        source = _source_team(principal, asset_id)
        _lock(principal, operation, {source})
        asset = _relock(principal, asset_id, source)
        _require(principal, source, (VIEW, RETIRE), asset)
        _check_version(asset, version)
        if asset.status != source_status:
            raise InvalidState
        before = snapshot(asset, ("status",))
        asset.status = target_status
        asset.version += 1
        asset.save(update_fields=["status", "version", "updated_at"])
        events.emit(principal, action, asset, before=before, fields=("status",))
    return asset


def retire_asset(principal, asset_id, *, version):
    return _transition(
        principal,
        asset_id,
        version,
        operation="retire",
        source_status=Status.ACTIVE,
        target_status=Status.RETIRED,
        action="assets.asset_retired",
    )


def restore_asset(principal, asset_id, *, version):
    # A name taken meanwhile by another active asset fails on the partial unique index: 409.
    return _transition(
        principal,
        asset_id,
        version,
        operation="restore",
        source_status=Status.RETIRED,
        target_status=Status.ACTIVE,
        action="assets.asset_restored",
    )


def transfer_asset(principal, asset_id, *, version, team_id):
    _require_user(principal)
    version = _version(version)
    asset_id = _uuid(asset_id)
    destination = _uuid(team_id, "team_id")
    with _mutation("transfer", principal):
        source = _source_team(principal, asset_id)
        if not _eligible(principal, destination):
            raise TeamUnavailable
        _lock(principal, "transfer", {source, destination})
        asset = _relock(principal, asset_id, source)
        if not _eligible(principal, destination):
            raise TeamUnavailable
        _require(principal, source, (VIEW, TRANSFER), asset)
        _require(principal, destination, (VIEW, TRANSFER), asset)
        _check_version(asset, version)
        if destination == source:
            raise ValidationError({"team_id": ["Choose a different team."]})
        if asset.status != Status.ACTIVE:
            raise InvalidState
        before = snapshot(asset, ("team_id",))
        asset.team_id = destination
        asset.version += 1
        asset.save(update_fields=["team", "version", "updated_at"])
        events.emit(
            principal, "assets.asset_transferred", asset, before=before, fields=("team_id",)
        )
    return asset
