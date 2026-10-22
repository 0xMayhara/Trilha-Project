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
