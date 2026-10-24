"""Read-only audit queries. Callers authorize first: SPEC-0010 allows only current Admins."""

from apps.audit.models import AuditEvent


def search_events(
    *,
    occurred_after,
    occurred_before,
    action=None,
    actor_id=None,
    resource_type=None,
    resource_id=None,
    outcome=None,
    source=None,
):
    """Exact matches inside a bounded time range, newest first; served by the existing indexes."""
    exact = {
        "action": action,
        "actor_id": actor_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "source": source,
    }
    return (
        AuditEvent.objects.filter(occurred_at__gte=occurred_after, occurred_at__lt=occurred_before)
        .filter(**{field: value for field, value in exact.items() if value is not None})
        .order_by("-occurred_at", "-id")
    )


def resource_events(*, actions, resource_type, resource_id=None, metadata=None):
    """Events of the given actions on one resource type (or one resource), oldest first, optionally
    matching exact metadata values. For read-only verification commands of the owning module; no
    HTTP route uses it. `metadata` keys are code constants, never request input."""
    events = AuditEvent.objects.filter(action__in=actions, resource_type=resource_type)
    if resource_id is not None:
        events = events.filter(resource_id=resource_id)
    for key, value in (metadata or {}).items():
        events = events.filter(**{f"metadata__{key}": value})
    return events.order_by("id")
