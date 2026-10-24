"""Finding use cases (SPEC-0007 slice B). Each validates, locks, rechecks authorization against the
asset's current team, compares the version, writes, appends its logbook entry and audits, all in
one transaction.

Lock order (BR-50): the actor's Role -> Team -> User rows (rbac.locking.lock_authority), then the
asset row, then the finding row. The owning team is read again under the asset lock, so a transfer
that commits first is noticed (409) and one that waits applies afterwards."""

import logging
import re
import uuid
from contextlib import contextmanager

from django.core.exceptions import ValidationError
from django.db import IntegrityError, OperationalError, transaction

from apps.assets.models import Asset
from apps.assets.models import Status as AssetStatus
from apps.assets.selectors import scoped_assets
from apps.audit.changes import field_changes, snapshot
from apps.audit.digests import content_digest
from apps.audit.services import record_event
from apps.audit.types import Resource
from apps.core.text import normalize_multiline_text, normalize_text
from apps.findings.exceptions import (
    AssetRetired,
    AssetUnavailable,
    FindingForbidden,
    FindingIntegrityFailure,
    FindingNotFound,
    StaleFinding,
)
from apps.findings.models import (
    CVE_PATTERN,
    DESCRIPTION_MAX_LENGTH,
    MAX_CVE_IDS,
    TITLE_MAX_LENGTH,
    Category,
    Finding,
    FindingLogEntry,
    LogKind,
    Severity,
)
from apps.findings.selectors import scoped_findings
from apps.rbac.catalog import catalog_action
from apps.rbac.locking import bound_lock_waits, lock_authority, lock_failure
from apps.rbac.policy import audit_actor
from apps.rbac.principals import UserPrincipal
from apps.rbac.selectors import can_access

logger = logging.getLogger("apps.findings")

LOCK_TIMEOUT = "5s"
VIEW, ADD, CHANGE = "findings.view_finding", "findings.add_finding", "findings.change_finding"
VIEW_ASSET = "assets.view_asset"
# Domain separation of the audit content digests (SPEC-0007 SEC-49).
DIGEST_CONTEXT = "trilha.findings.content-digest"
# Audited with before/after values; the description only as a keyed digest and a length.
AUDITED_FIELDS = ("title", "category", "severity", "cve_ids")
CREATED_FIELDS = ("asset_id", *AUDITED_FIELDS, "status")
# Logbook entries show before/after for these only; other changes list the field names (BR-27).
LOGGED_VALUES = ("severity", "category")


def _choice(choices):
    def clean(value):
        if not isinstance(value, str) or value not in choices.values:
            raise ValidationError(f"Choose one of: {', '.join(choices.values)}.")
        return value

    return clean


def _cve_ids(values):
    """Trimmed, upper-cased, canonical, unique and sorted. An attribute, never an identity."""
    if not isinstance(values, list) or len(values) > MAX_CVE_IDS:
        raise ValidationError(f"Provide a list of at most {MAX_CVE_IDS} CVE IDs.")
    cleaned = set()
    for value in values:
        if not isinstance(value, str):
            raise ValidationError("Each CVE ID must be text.")
        value = value.strip().upper()
        if not re.fullmatch(CVE_PATTERN, value):
            raise ValidationError("Use CVE IDs such as CVE-2024-3094.")
        cleaned.add(value)
    return sorted(cleaned)


_CLEANERS = {
    "title": lambda value: normalize_text(value, required=True, max_length=TITLE_MAX_LENGTH),
    "description": lambda value: normalize_multiline_text(
        value, required=False, max_length=DESCRIPTION_MAX_LENGTH
    ),
    "category": _choice(Category),
    "severity": _choice(Severity),
    "cve_ids": _cve_ids,
}


def _clean(values):
    """Canonical values for the listed fields; any other key is refused (CWE-915)."""
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


def _uuid(value, missing):
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (TypeError, ValueError):
        raise missing from None


def _require_user(principal):
    # Operator, system and provider principals hold no finding authority.
    if not isinstance(principal, UserPrincipal):
        raise FindingForbidden


def _constraint(cause):
    return getattr(getattr(cause, "diag", None), "constraint_name", None)


@contextmanager
def _mutation(operation, principal):
    """One transaction with bounded lock waits; database failures are reported without details."""
    try:
        with transaction.atomic():
            bound_lock_waits(LOCK_TIMEOUT)
            yield
    except IntegrityError as exc:
        # Identified by constraint name, never by message text, which may quote row content.
        logger.error(
            "finding_integrity_error",
            extra={"operation": operation, "constraint": _constraint(exc.__cause__)},
        )
        raise FindingIntegrityFailure from None
    except OperationalError as exc:
        reason = lock_failure(exc)
        if reason is None:
            raise
        logger.warning(
            "finding_lock_unavailable",
            extra={"operation": operation, "actor_id": str(principal.user_id), "reason": reason},
        )
        # A fresh error without the database cause: the 503 handler logs no SQL or row data.
        raise OperationalError("Finding lock unavailable.") from None


def _lock_authority(principal, operation, team_id):
    if not lock_authority(principal, {team_id}):
        logger.warning(
            "finding_lock_unavailable",
            extra={
                "operation": operation,
                "actor_id": str(principal.user_id),
                "reason": "role_drift",
            },
        )
        raise StaleFinding


def _require(principal, team_id, codes, finding=None):
    for code in codes:
        if not can_access(principal, code, team_id=team_id, action=catalog_action(code)):
            raise FindingForbidden(finding.pk if finding is not None else None)


def _locked_asset(principal, asset_id, team_id, missing):
    """The asset row under FOR NO KEY UPDATE, still in the team whose authority is locked."""
    try:
        team, status = (
            scoped_assets(principal)
            .select_for_update(no_key=True)
            .values_list("team_id", "status")
            .get(pk=asset_id)
        )
    except Asset.DoesNotExist:
        raise missing from None
    if team != team_id:
        raise StaleFinding
    return status


def _next_entry(finding, event, actor_id, metadata=None):
    """The finding's next system entry. The caller holds the finding row and saves it, so the
    sequence advances with the row lock held: gapless and in commit order (BR-24)."""
    finding.log_sequence += 1
    return FindingLogEntry(
        finding=finding,
        sequence=finding.log_sequence,
        kind=LogKind.SYSTEM,
        event=event,
        actor_id=actor_id,
        metadata=metadata or {},
    )


def _audit(principal, action, finding, changes, metadata=None):
    record_event(
        actor=audit_actor(principal),
        action=action,
        resource=Resource.of(finding),
        changes=changes,
        metadata=metadata,
    )


def _digest(text):
    return content_digest(text, context=DIGEST_CONTEXT)


def create_finding(principal, *, asset_id=None, **fields):
    _require_user(principal)
    missing = {
        field: ["This field is required."]
        for field in ("title", "category", "severity")
        if field not in fields
    }
    if missing:
        raise ValidationError(missing)
    values = _clean(fields)
    asset_id = _uuid(asset_id, AssetUnavailable)
    with _mutation("create", principal):
        try:
            team_id = scoped_assets(principal).values_list("team_id", flat=True).get(pk=asset_id)
        except Asset.DoesNotExist:
            raise AssetUnavailable from None
        _lock_authority(principal, "create", team_id)
        status = _locked_asset(principal, asset_id, team_id, AssetUnavailable)
        # Without view on the asset the request is answered like an unknown asset (SEC-04).
        if not can_access(principal, VIEW_ASSET, team_id=team_id):
            raise AssetUnavailable
        _require(principal, team_id, (VIEW, ADD))
        if status != AssetStatus.ACTIVE:
            raise AssetRetired
        finding = Finding(asset_id=asset_id, reported_by_id=principal.user_id, **values)
        entry = _next_entry(finding, "finding_created", principal.user_id)
        finding.save(force_insert=True)
        entry.save()
        _audit(
            principal,
            "findings.finding_created",
            finding,
            field_changes({}, snapshot(finding, CREATED_FIELDS), CREATED_FIELDS),
            {
                "description_digest": _digest(finding.description),
                "description_length": len(finding.description),
            },
        )
    return finding


def update_finding(principal, finding_id, *, version, changes):
    _require_user(principal)
    version = _version(version)
    finding_id = _uuid(finding_id, FindingNotFound)
    if not isinstance(changes, dict) or not changes:
        raise ValidationError({"non_field_errors": ["Provide at least one field to change."]})
    values = _clean(changes)
    with _mutation("update", principal):
        try:
            team_id, asset_id = (
                scoped_findings(principal)
                .values_list("asset__team_id", "asset_id")
                .get(pk=finding_id)
            )
        except Finding.DoesNotExist:
            raise FindingNotFound from None
        _lock_authority(principal, "update", team_id)
        _locked_asset(principal, asset_id, team_id, FindingNotFound)
        finding = Finding.objects.select_for_update().get(pk=finding_id)
        _require(principal, team_id, (VIEW, CHANGE), finding)
        if finding.version != version:  # before no-op detection (SEC-07)
            raise StaleFinding
        changed = tuple(
            field for field, value in values.items() if getattr(finding, field) != value
        )
        if not changed:
            return finding
        before = snapshot(finding, AUDITED_FIELDS)
        old_description = finding.description
        for field in changed:
            setattr(finding, field, values[field])
        finding.version += 1
        metadata = {"fields": sorted(changed)}
        metadata |= {
            field: {"before": before[field], "after": values[field]}
            for field in LOGGED_VALUES
            if field in changed
        }
        entry = _next_entry(finding, "finding_updated", principal.user_id, metadata)
        finding.save(update_fields=[*changed, "version", "log_sequence", "updated_at"])
        entry.save()
        audited = field_changes(before, snapshot(finding, AUDITED_FIELDS), AUDITED_FIELDS)
        if "description" in changed:
            audited["description_digest"] = {
                "before": _digest(old_description),
                "after": _digest(finding.description),
            }
            audited["description_length"] = {
                "before": len(old_description),
                "after": len(finding.description),
            }
        _audit(principal, "findings.finding_updated", finding, audited)
    return finding
