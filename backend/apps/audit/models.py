"""Immutable audit record (SPEC-0002, ADR-0003). Events are created only through
apps.audit.services.record_event(); nothing in the application can update or delete them."""

import logging
import uuid
from typing import Any, NoReturn

from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.utils import timezone

from apps.audit.exceptions import AuditEventImmutable

logger = logging.getLogger("apps.audit")

ACTION_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
RESOURCE_TYPE_PATTERN = r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$"


class ActorType(models.TextChoices):
    USER = "user"
    SYSTEM = "system"
    PROVIDER = "provider"
    ANONYMOUS = "anonymous"


class Outcome(models.TextChoices):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class Source(models.TextChoices):
    HTTP = "http"
    TASK = "task"
    SYNC = "sync"
    COMMAND = "command"


def reject_tamper(operation: str, event_id: uuid.UUID | None = None) -> NoReturn:
    # The attempted values are never logged (SEC-18): only what was tried and on which event.
    logger.warning(
        "audit_tamper_attempt",
        extra={
            "event": "audit_tamper_attempt",
            "operation": operation,
            "audit_event_id": str(event_id) if event_id else None,
        },
    )
    raise AuditEventImmutable(f"Audit events are append-only: {operation} rejected.")


class AuditEventQuerySet(models.QuerySet):
    """Rejects bulk writes before any SQL runs (SEC-02). The database trigger covers raw SQL."""

    def update(self, **kwargs: Any) -> NoReturn:
        reject_tamper("queryset.update")

    def delete(self) -> NoReturn:
        reject_tamper("queryset.delete")

    def bulk_update(self, objs: Any, fields: Any, batch_size: int | None = None) -> NoReturn:
        reject_tamper("queryset.bulk_update")


class AuditEvent(models.Model):
    id = models.BigAutoField(primary_key=True)
    event_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    occurred_at = models.DateTimeField(default=timezone.now, editable=False)
    actor_type = models.CharField(max_length=16, choices=ActorType.choices)
    actor_id = models.UUIDField(null=True, blank=True)
    actor_label = models.CharField(max_length=150, blank=True, default="")
    action = models.CharField(max_length=100)
    outcome = models.CharField(max_length=16, choices=Outcome.choices, default=Outcome.SUCCESS)
    resource_type = models.CharField(max_length=100, blank=True, default="")
    resource_id = models.CharField(max_length=64, blank=True, default="")
    source = models.CharField(max_length=16, choices=Source.choices)
    request_id = models.UUIDField(null=True, blank=True)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    changes = models.JSONField(default=dict, encoder=DjangoJSONEncoder)
    metadata = models.JSONField(default=dict, encoder=DjangoJSONEncoder)

    objects = AuditEventQuerySet.as_manager()

    class Meta:
        # Django internals (related lookups) use the base manager: it must be the guarded one.
        base_manager_name = "objects"
        indexes = (
            models.Index(fields=["occurred_at"], name="audit_event_occurred_idx"),
            models.Index(
                fields=["resource_type", "resource_id", "occurred_at"],
                name="audit_event_resource_idx",
            ),
            models.Index(fields=["actor_id", "occurred_at"], name="audit_event_actor_idx"),
        )
        constraints = (
            models.CheckConstraint(
                condition=models.Q(action__regex=ACTION_PATTERN),
                name="audit_event_action_format",
            ),
            models.CheckConstraint(
                condition=models.Q(resource_type="")
                | models.Q(resource_type__regex=RESOURCE_TYPE_PATTERN),
                name="audit_event_resource_type_format",
            ),
            models.CheckConstraint(
                condition=models.Q(resource_id="") | ~models.Q(resource_type=""),
                name="audit_event_resource_id_needs_type",
            ),
            models.CheckConstraint(
                condition=models.Q(actor_type__in=ActorType.values),
                name="audit_event_actor_type_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(outcome__in=Outcome.values),
                name="audit_event_outcome_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(source__in=Source.values),
                name="audit_event_source_valid",
            ),
            models.CheckConstraint(
                condition=(models.Q(actor_type=ActorType.USER) & models.Q(actor_id__isnull=False))
                | (~models.Q(actor_type=ActorType.USER) & models.Q(actor_id__isnull=True)),
                name="audit_event_actor_id_iff_user",
            ),
            models.CheckConstraint(
                condition=models.Q(client_ip__isnull=True) | models.Q(source=Source.HTTP),
                name="audit_event_client_ip_only_http",
            ),
        )

    def __str__(self) -> str:
        return f"{self.action} ({self.event_id})"

    def save(self, **kwargs: Any) -> None:
        if not self._state.adding:
            reject_tamper("save", self.event_id)
        # Always INSERT: Django would otherwise try UPDATE first for an instance whose id is set,
        # overwriting an existing event (SEC-01).
        kwargs["force_insert"] = True
        super().save(**kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> NoReturn:
        reject_tamper("delete", self.event_id)
