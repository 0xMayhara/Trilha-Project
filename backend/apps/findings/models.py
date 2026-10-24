"""Findings and their Operational Logbook (SPEC-0007 Data Model, ADR-0008 §1-§2).

A finding has no team: its owning team is always its asset's current team (BR-01). Changed only
through apps.findings services; log entries are append-only in four layers (service rules, the
guards below, the append-only privilege class and the database trigger)."""

import logging
import uuid
from typing import Any, ClassVar, NoReturn

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models.functions import Length
from django.db.models.lookups import LessThanOrEqual

from apps.assets.models import IsNFCNormalized

logger = logging.getLogger("apps.findings")

TITLE_MAX_LENGTH = 200
DESCRIPTION_MAX_LENGTH = 10_000
COMMENT_MAX_LENGTH = 4_000
MAX_CVE_IDS = 20
CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"
EVENT_PATTERN = r"^[a-z][a-z_]{0,47}$"


class Category(models.TextChoices):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    HARDENING_GAP = "hardening_gap"
    END_OF_LIFE = "end_of_life"
    OTHER = "other"


class Severity(models.TextChoices):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(models.TextChoices):
    OPEN = "open"
    IN_PROGRESS = "in_progress"


class CveIdsWellFormed(models.Func):
    """Every element of the array is one canonical CVE ID. Joined with commas, the text must be IDs
    separated by commas, and the comma count must match the element count, so an element holding
    two IDs, a NULL or an empty string fails. Static SQL; no input reaches it."""

    _ID = "CVE-[0-9]{4}-[0-9]{4,19}"
    template = (
        "(cardinality(%(expressions)s) = 0 OR ("
        f"array_to_string(%(expressions)s, ',') ~ '^{_ID}(,{_ID})*$'"
        " AND cardinality(%(expressions)s)"
        " = length(regexp_replace(array_to_string(%(expressions)s, ','), '[^,]', '', 'g')) + 1))"
    )
    arity = 1
    output_field = models.BooleanField()


class Finding(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Set at creation, never changed (BR-03); an asset with findings cannot be deleted.
    asset = models.ForeignKey("assets.Asset", on_delete=models.PROTECT, related_name="findings")
    title = models.CharField(max_length=TITLE_MAX_LENGTH)
    description = models.TextField(blank=True, default="")
    category = models.CharField(max_length=24, choices=Category.choices)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    # Attributes, never identity (BR-02): canonical, sorted and unique, written by the service.
    cve_ids = ArrayField(models.CharField(max_length=32), blank=True, default=list)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    # Set only by the assignment service (slice D); assignment grants nothing (BR-12).
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
    )
    reported_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+"
    )
    version = models.PositiveIntegerField(default=1)
    # The last logbook sequence. Writers increment it under the finding row lock (BR-24).
    log_sequence = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        default_permissions = ("view", "add", "change")
        permissions = (
            ("comment_finding", "Can comment on finding"),
            ("work_finding", "Can work on finding"),
            ("override_priority", "Can override finding priority"),
        )
        indexes = (
            models.Index(fields=["status", "created_at"], name="finding_status_created_idx"),
        )
        constraints: ClassVar = [
            models.CheckConstraint(
                condition=models.Q(category__in=Category.values), name="finding_category"
            ),
            models.CheckConstraint(
                condition=models.Q(severity__in=Severity.values), name="finding_severity"
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=Status.values), name="finding_status"
            ),
            models.CheckConstraint(condition=~models.Q(title=""), name="finding_title_nonempty"),
            models.CheckConstraint(condition=IsNFCNormalized("title"), name="finding_title_nfc"),
            models.CheckConstraint(
                condition=models.Q(cve_ids__len__lte=MAX_CVE_IDS), name="finding_cve_count"
            ),
            models.CheckConstraint(condition=CveIdsWellFormed("cve_ids"), name="finding_cve_ids"),
            models.CheckConstraint(condition=models.Q(version__gte=1), name="finding_version"),
            models.CheckConstraint(
                condition=models.Q(log_sequence__gte=0), name="finding_log_sequence"
            ),
        ]

    def __str__(self):
        return str(self.pk)


class LogKind(models.TextChoices):
    COMMENT = "comment"
    SYSTEM = "system"


class RedactionReason(models.TextChoices):
    SECRET = "secret"  # noqa: S105 (a category name, not a credential)
    PERSONAL_DATA = "personal_data"


class LogEntryImmutable(Exception):
    """An attempt to change or remove a logbook entry through the ORM (BR-23)."""


def _reject(operation: str, entry_id: uuid.UUID | None = None) -> NoReturn:
    # The attempted values are never logged: only what was tried, on which entry.
    logger.warning(
        "logbook_tamper_attempt",
        extra={"operation": operation, "entry_id": str(entry_id) if entry_id else None},
    )
    raise LogEntryImmutable(f"Logbook entries are append-only: {operation} rejected.")


class LogEntryQuerySet(models.QuerySet):
    """Rejects bulk writes before any SQL runs; the database trigger covers raw SQL."""

    def update(self, **kwargs: Any) -> NoReturn:
        _reject("queryset.update")

    def delete(self) -> NoReturn:
        _reject("queryset.delete")

    def bulk_update(self, objs: Any, fields: Any, batch_size: int | None = None) -> NoReturn:
        _reject("queryset.bulk_update")

    def bulk_create(
        self,
        objs: Any,
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Any = None,
        unique_fields: Any = None,
    ) -> list["FindingLogEntry"]:
        # INSERT ... ON CONFLICT DO UPDATE would rewrite existing entries.
        if update_conflicts:
            _reject("queryset.bulk_create(update_conflicts)")
        return super().bulk_create(objs, batch_size=batch_size, ignore_conflicts=ignore_conflicts)


class FindingLogEntry(models.Model):
    """One human comment or one system event of a finding's logbook (BR-20)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(Finding, on_delete=models.PROTECT, related_name="log_entries")
    # Per finding, gapless, in commit order: assigned under the finding row lock (BR-24).
    sequence = models.IntegerField()
    kind = models.CharField(max_length=8, choices=LogKind.choices)
    event = models.CharField(max_length=48, blank=True, default="")
    # Comment author, or the user who caused a system event; null for system tasks (BR-28).
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
    )
    body = models.TextField(blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)
    idempotency_key = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # Set only by the owner-controlled emergency redaction (BR-51), never by the application.
    redacted_at = models.DateTimeField(null=True, blank=True)
    redaction_reason = models.CharField(  # noqa: DJ001
        max_length=16, choices=RedactionReason.choices, null=True, blank=True
    )

    objects = LogEntryQuerySet.as_manager()

    class Meta:
        default_permissions = ()
        # Django internals (related lookups) use the base manager: it must be the guarded one.
        base_manager_name = "objects"
        constraints: ClassVar = [
            # Also the index behind both cursor directions of the logbook API.
            models.UniqueConstraint(
                fields=["finding", "sequence"], name="logentry_finding_sequence"
            ),
            models.UniqueConstraint(
                fields=["actor", "idempotency_key"],
                condition=models.Q(idempotency_key__isnull=False),
                name="logentry_actor_idempotency",
            ),
            models.CheckConstraint(
                condition=models.Q(kind__in=LogKind.values), name="logentry_kind"
            ),
            models.CheckConstraint(condition=models.Q(sequence__gte=1), name="logentry_sequence"),
            models.CheckConstraint(
                condition=~models.Q(kind=LogKind.COMMENT)
                | (
                    models.Q(
                        actor__isnull=False, idempotency_key__isnull=False, event="", metadata={}
                    )
                    & (~models.Q(body="") | models.Q(redacted_at__isnull=False))
                    & models.Q(LessThanOrEqual(Length("body"), COMMENT_MAX_LENGTH))
                ),
                name="logentry_comment_shape",
            ),
            models.CheckConstraint(
                condition=~models.Q(kind=LogKind.SYSTEM)
                | models.Q(body="", idempotency_key__isnull=True, event__regex=EVENT_PATTERN),
                name="logentry_system_shape",
            ),
            models.CheckConstraint(
                condition=models.Q(redacted_at__isnull=True, redaction_reason__isnull=True)
                # IS NOT NULL is explicit: with a NULL reason, IN is unknown and CHECK passes it.
                | models.Q(
                    redacted_at__isnull=False,
                    redaction_reason__isnull=False,
                    redaction_reason__in=RedactionReason.values,
                ),
                name="logentry_redaction_complete",
            ),
            models.CheckConstraint(
                condition=models.Q(redacted_at__isnull=True)
                | (models.Q(body="") & ~models.Q(metadata__has_key="reason")),
                name="logentry_redacted_blank",
            ),
        ]

    def __str__(self):
        return str(self.pk)

    def save(self, **kwargs: Any) -> None:
        if not self._state.adding:
            _reject("save", self.pk)
        # Always INSERT: Django would otherwise try an UPDATE first for an instance with an id.
        kwargs["force_insert"] = True
        super().save(**kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> NoReturn:
        _reject("delete", self.pk)
