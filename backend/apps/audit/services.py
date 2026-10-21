"""The only sanctioned way to create audit events (SPEC-0002 BR-11).

Call record_event() from the service layer, inside the transaction.atomic block of the change it
describes. Any error propagates and rolls the change back: a change is never committed without its
event (BR-02, BR-03).
"""

import json
import re
import uuid
from collections.abc import Mapping
from typing import Any

from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction

from apps.audit.context import current_context
from apps.audit.exceptions import (
    AuditPayloadTooLarge,
    AuditTransactionRequired,
    AuditValidationError,
)
from apps.audit.models import (
    ACTION_PATTERN,
    RESOURCE_TYPE_PATTERN,
    ActorType,
    AuditEvent,
    Outcome,
)
from apps.audit.types import Actor, Resource
from apps.core.logging import redact
from apps.core.request_context import get_request_id

MAX_PAYLOAD_BYTES = 64 * 1024
ACTOR_LABEL_MAX_LENGTH = 150
ACTION_MAX_LENGTH = 100
RESOURCE_TYPE_MAX_LENGTH = 100
RESOURCE_ID_MAX_LENGTH = 64

_ACTION = re.compile(ACTION_PATTERN)
_RESOURCE_TYPE = re.compile(RESOURCE_TYPE_PATTERN)
# System components and providers are named by code constants such as "celery-beat" or "wazuh".
_COMPONENT_LABEL = re.compile(r"^[a-z][a-z0-9_.:-]*$")
# Unicode category Cc (C0 and C1 control characters) (BR-10, CWE-150).
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_NO_RESOURCE = Resource(type="")


def record_event(
    *,
    actor: Actor,
    action: str,
    resource: Resource | None = None,
    outcome: Outcome = Outcome.SUCCESS,
    changes: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> AuditEvent:
    """Records one event. Time, request ID, source and client IP are derived on the server and
    cannot be passed in (BR-05)."""
    if not transaction.get_connection().in_atomic_block:
        raise AuditTransactionRequired(
            "record_event() must run inside the transaction.atomic block of the audited change."
        )
    context = current_context()
    resource = resource or _NO_RESOURCE
    _validate_action(action)
    _validate_actor(actor)
    _validate_resource(resource)
    try:
        outcome = Outcome(outcome)
    except ValueError as exc:
        raise AuditValidationError(f"Invalid outcome: {outcome!r}") from exc
    clean_changes = _clean_payload("changes", changes)
    clean_metadata = _clean_payload("metadata", metadata)
    _check_size(clean_changes, clean_metadata)

    request_id = get_request_id()
    return AuditEvent.objects.create(
        actor_type=actor.type,
        actor_id=actor.id,
        actor_label=actor.label,
        action=action,
        outcome=outcome,
        resource_type=resource.type,
        resource_id=resource.id,
        source=context.source,
        request_id=uuid.UUID(request_id) if request_id else None,
        client_ip=context.client_ip,
        changes=clean_changes,
        metadata=clean_metadata,
    )


def _validate_action(action: str) -> None:
    if not isinstance(action, str) or len(action) > ACTION_MAX_LENGTH or not _ACTION.match(action):
        raise AuditValidationError(f"Invalid action code: {action!r}")


def _validate_text(name: str, value: str, max_length: int) -> None:
    if not isinstance(value, str) or len(value) > max_length:
        raise AuditValidationError(f"Invalid {name}.")
    if _CONTROL_CHARACTERS.search(value):
        raise AuditValidationError(f"{name} must not contain control characters.")


def _validate_actor(actor: Actor) -> None:
    if not isinstance(actor, Actor) or actor.type not in ActorType.values:
        raise AuditValidationError("actor must be built with an Actor constructor.")
    _validate_text("actor label", actor.label, ACTOR_LABEL_MAX_LENGTH)
    if actor.type == ActorType.USER:
        if not isinstance(actor.id, uuid.UUID) or not actor.label:
            raise AuditValidationError("A user actor needs the user's id and username.")
    elif actor.id is not None:
        raise AuditValidationError("Only user actors carry an id.")
    if actor.type in (ActorType.SYSTEM, ActorType.PROVIDER) and not _COMPONENT_LABEL.match(
        actor.label
    ):
        raise AuditValidationError(f"Invalid {actor.type} name: {actor.label!r}")
    if actor.type == ActorType.ANONYMOUS and actor.label:
        raise AuditValidationError("An anonymous actor has no label.")


def _validate_resource(resource: Resource) -> None:
    if not isinstance(resource, Resource):
        raise AuditValidationError("resource must be a Resource.")
    _validate_text("resource type", resource.type, RESOURCE_TYPE_MAX_LENGTH)
    _validate_text("resource id", resource.id, RESOURCE_ID_MAX_LENGTH)
    if resource.type and not _RESOURCE_TYPE.match(resource.type):
        raise AuditValidationError(f"Invalid resource type: {resource.type!r}")
    if resource.id and not resource.type:
        raise AuditValidationError("A resource id needs a resource type.")


def _clean_payload(name: str, payload: Mapping[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        return {}
    if not isinstance(payload, Mapping):
        raise AuditValidationError(f"{name} must be a mapping.")
    # Same sensitive-key pattern as the logs; the key stays so the event shows what changed (BR-08).
    return redact(dict(payload))


def _check_size(changes: dict[str, Any], metadata: dict[str, Any]) -> None:
    payload = {"changes": changes, "metadata": metadata}
    try:
        # allow_nan=False: PostgreSQL jsonb rejects NaN and Infinity.
        encoded = json.dumps(payload, cls=DjangoJSONEncoder, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise AuditValidationError("changes and metadata must be JSON-serializable.") from exc
    # PostgreSQL jsonb also rejects NUL. shortcut: the literal text "\u0000" is rejected too, which
    # fails closed; match escapes precisely if a feature ever needs to store that text.
    if "\\u0000" in encoded:
        raise AuditValidationError("changes and metadata must not contain NUL characters.")
    if len(encoded.encode()) > MAX_PAYLOAD_BYTES:
        raise AuditPayloadTooLarge(f"changes + metadata exceed {MAX_PAYLOAD_BYTES} bytes.")
    # jsonb also rejects lone surrogates (json.loads turns "\ud800" into one); they cannot be UTF-8.
    try:
        json.dumps(payload, cls=DjangoJSONEncoder, ensure_ascii=False).encode()
    except UnicodeEncodeError as exc:
        raise AuditValidationError("changes and metadata must be valid Unicode.") from exc
