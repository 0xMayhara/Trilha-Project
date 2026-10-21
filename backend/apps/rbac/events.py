from apps.audit.changes import field_changes, snapshot
from apps.audit.services import record_event
from apps.audit.types import Resource
from apps.rbac.policy import audit_actor


def emit(principal, action, resource, *, before=None, fields=(), metadata=None, removed=False):
    after = {} if removed else snapshot(resource, fields)
    record_event(
        actor=audit_actor(principal),
        action=action,
        resource=Resource.of(resource),
        changes=field_changes(before or {}, after, fields),
        metadata=metadata,
    )
