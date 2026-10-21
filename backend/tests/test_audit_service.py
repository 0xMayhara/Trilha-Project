"""Recording audit events (SPEC-0002 SEC-05…SEC-07, SEC-10…SEC-17)."""

import inspect
import json
import re
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.db import IntegrityError, transaction
from django.urls import URLPattern, URLResolver, get_resolver
from django.utils import timezone

from apps.audit.changes import field_changes, snapshot
from apps.audit.context import audit_source
from apps.audit.exceptions import (
    AuditContextMissing,
    AuditPayloadTooLarge,
    AuditTransactionRequired,
    AuditValidationError,
)
from apps.audit.models import ActorType, AuditEvent, Outcome
from apps.audit.services import MAX_PAYLOAD_BYTES, record_event
from apps.audit.types import Actor, Resource
from apps.core.request_context import request_id_var

BACKEND = Path(settings.BASE_DIR)
SYSTEM = Actor.system("tests")
ACTION = "tests.event_recorded"


@pytest.fixture
def command_context():
    with audit_source("command"):
        yield


def _record(**kwargs):
    kwargs.setdefault("actor", SYSTEM)
    kwargs.setdefault("action", ACTION)
    with transaction.atomic():
        return record_event(**kwargs)


@pytest.mark.django_db
def test_event_stores_what_the_service_passes(command_context, user):
    event = _record(
        actor=Actor.user(user),
        action="accounts.user_disabled",
        resource=Resource.of(user),
        outcome=Outcome.SUCCESS,
        changes={"is_active": {"before": True, "after": False}},
        # Control characters other than NUL are valid JSON and stay storable.
        metadata={"reason": "left the company\nper HR ticket"},
    )

    stored = AuditEvent.objects.get(pk=event.pk)
    assert stored.actor_type == ActorType.USER
    assert stored.actor_id == user.pk
    assert stored.actor_label == "analyst"
    assert stored.action == "accounts.user_disabled"
    assert stored.resource_type == "accounts.user"
    assert stored.resource_id == str(user.pk)
    assert stored.outcome == "success"
    assert stored.source == "command"
    assert stored.client_ip is None
    assert stored.changes == {"is_active": {"before": True, "after": False}}
    assert stored.metadata == {"reason": "left the company\nper HR ticket"}
    assert isinstance(stored.event_id, uuid.UUID)


def test_record_event_accepts_no_provenance_arguments_cwe_345():
    parameters = inspect.signature(record_event).parameters

    assert set(parameters) == {"actor", "action", "resource", "outcome", "changes", "metadata"}
    assert all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values())
    for forged in ("occurred_at", "request_id", "source", "client_ip"):
        with pytest.raises(TypeError):
            record_event(actor=SYSTEM, action=ACTION, **{forged: "forged"})


@pytest.mark.django_db
def test_event_records_request_context(command_context):
    request_id = str(uuid.uuid4())
    token = request_id_var.set(request_id)
    try:
        event = _record()
    finally:
        request_id_var.reset(token)

    stored = AuditEvent.objects.get(pk=event.pk)
    assert str(stored.request_id) == request_id
    assert abs(stored.occurred_at - timezone.now()) < timedelta(seconds=5)


@pytest.mark.django_db(transaction=True)
def test_record_event_requires_atomic_block_cwe_778(command_context):
    with pytest.raises(AuditTransactionRequired):
        record_event(actor=SYSTEM, action=ACTION)

    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_event_rolls_back_with_failed_transaction_cwe_778(command_context):
    with pytest.raises(RuntimeError), transaction.atomic():
        record_event(actor=SYSTEM, action=ACTION)
        raise RuntimeError("the audited change failed")

    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_failed_recording_rolls_back_business_change_cwe_636(command_context):
    with pytest.raises(AuditValidationError), transaction.atomic():
        get_user_model().objects.create_user(username="new-user", password="x" * 16)
        record_event(actor=SYSTEM, action="Not A Valid Code")

    assert not get_user_model().objects.filter(username="new-user").exists()
    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_missing_audit_context_is_rejected_cwe_345():
    with pytest.raises(AuditContextMissing), transaction.atomic():
        record_event(actor=SYSTEM, action=ACTION)

    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_sensitive_keys_are_redacted_at_any_depth_cwe_532(command_context):
    event = _record(
        changes={
            "password": {"before": "old-hash-value", "after": "new-hash-value"},
            "settings": {"api_key": "provider-key-value", "url": "https://wazuh.example"},
        },
        metadata={"items": [{"token": "token-value"}], "note": "kept"},
    )

    stored = AuditEvent.objects.get(pk=event.pk)
    assert stored.changes == {
        "password": "[REDACTED]",
        "settings": {"api_key": "[REDACTED]", "url": "https://wazuh.example"},
    }
    assert stored.metadata == {"items": [{"token": "[REDACTED]"}], "note": "kept"}
    rendered = json.dumps([stored.changes, stored.metadata])
    for secret in ("old-hash-value", "new-hash-value", "provider-key-value", "token-value"):
        assert secret not in rendered


@pytest.mark.django_db
def test_changes_include_only_listed_fields_cwe_532(user):
    assert snapshot(user, ["username", "is_active"]) == {"username": "analyst", "is_active": True}
    for invalid in ("username", ["__all__"], ["missing_field"], ["groups"], [1]):
        with pytest.raises(AuditValidationError):
            snapshot(user, invalid)

    before = snapshot(user, ["username", "is_active", "email"])
    user.is_active = False
    after = snapshot(user, ["username", "is_active", "email"])
    assert field_changes(before, after, ["username", "is_active", "email"]) == {
        "is_active": {"before": True, "after": False}
    }
    assert field_changes({}, after, ["username"]) == {
        "username": {"before": None, "after": "analyst"}
    }
    assert field_changes(before, after, ["username"]) == {}
    with pytest.raises(AuditValidationError):
        field_changes(before, after, ["__all__"])


@pytest.mark.django_db
def test_oversized_payload_is_rejected_cwe_779(command_context):
    with pytest.raises(AuditPayloadTooLarge):
        _record(metadata={"blob": "x" * MAX_PAYLOAD_BYTES})

    _record(metadata={"blob": "x" * (MAX_PAYLOAD_BYTES - 1024)})
    assert AuditEvent.objects.count() == 1


@pytest.mark.django_db
@pytest.mark.parametrize(
    "kwargs",
    [
        {"action": ""},
        {"action": "accounts"},
        {"action": "accounts."},
        {"action": "Accounts.user_created"},
        {"action": "accounts.user created"},
        {"action": "accounts." + "a" * 100},
        {"resource": Resource(type="Accounts.User", id="1")},
        {"resource": Resource(type="accounts", id="1")},
        {"resource": Resource(type="", id="1")},
        {"resource": Resource(type="accounts.user", id="x" * 65)},
        {"outcome": "maybe"},
        {"actor": "admin"},
        {"actor": Actor(type=ActorType.USER, id=None, label="admin")},
        {"actor": Actor(type=ActorType.SYSTEM, id=uuid.uuid4(), label="tests")},
        {"actor": Actor.system("Celery Beat")},
        {"actor": Actor.provider("")},
        {"actor": Actor(type=ActorType.ANONYMOUS, label="admin")},
        {"metadata": {"value": object()}},
        {"metadata": ["not", "a", "mapping"]},
        # Valid for Python's json module, rejected by PostgreSQL jsonb (CWE-20).
        {"changes": {"cvss": {"before": None, "after": float("nan")}}},
        {"metadata": {"score": float("inf")}},
        {"metadata": {"hostname": "web\x0001"}},
        {"metadata": {"host\x00name": "web01"}},
        {"metadata": {"hostname": json.loads('"web\\ud800"')}},
    ],
)
def test_invalid_codes_are_rejected_by_service(command_context, kwargs):
    with pytest.raises(AuditValidationError):
        _record(**kwargs)

    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
@pytest.mark.parametrize(
    "fields",
    [
        {"action": "Bad Action"},
        {"resource_type": "BAD"},
        {"resource_id": "1"},
        {"actor_type": "root"},
        {"outcome": "maybe"},
        {"source": "web"},
        {"actor_type": "user"},
        {"actor_id": uuid.uuid4()},
        {"client_ip": "203.0.113.7"},
    ],
)
def test_database_constraints_reject_invalid_rows(fields):
    row = {"actor_type": "system", "actor_label": "tests", "action": ACTION, "source": "task"}
    row.update(fields)

    with pytest.raises(IntegrityError), transaction.atomic():
        AuditEvent.objects.create(**row)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "kwargs",
    [
        {"actor": Actor(type=ActorType.USER, id=uuid.uuid4(), label="evil\x1b[2Jname")},
        {"actor": Actor(type=ActorType.USER, id=uuid.uuid4(), label="line\nbreak")},
        {"resource": Resource(type="tests.item", id="1\r\n2")},
        {"resource": Resource(type="tests.item", id="1\x85")},
    ],
)
def test_control_characters_are_rejected_cwe_150(command_context, kwargs):
    with pytest.raises(AuditValidationError):
        _record(**kwargs)


@pytest.mark.django_db
def test_actor_constructors(user):
    assert Actor.for_request_user(AnonymousUser()) == Actor.anonymous()
    assert Actor.for_request_user(user) == Actor(type=ActorType.USER, id=user.pk, label="analyst")
    with pytest.raises(AuditValidationError):
        Actor.user(AnonymousUser())
    with pytest.raises(AuditValidationError):
        Actor.user(get_user_model()(username="unsaved"))
    with pytest.raises(AuditValidationError):
        Resource.of(get_user_model()(username="unsaved"))


@pytest.mark.django_db
def test_deleting_user_keeps_events_unchanged_cwe_223(command_context, user):
    user_id = user.pk
    event = _record(actor=Actor.user(user), resource=Resource.of(user))

    user.delete()

    stored = AuditEvent.objects.get(pk=event.pk)
    assert stored.actor_id == user_id
    assert stored.actor_label == "analyst"
    assert stored.resource_id == str(user_id)


def _routes(patterns):
    for pattern in patterns:
        if isinstance(pattern, URLResolver):
            yield from _routes(pattern.url_patterns)
        elif isinstance(pattern, URLPattern):
            yield pattern


def test_audit_has_no_routes_or_admin_cwe_200():
    audit_dir = BACKEND / "apps" / "audit"
    for module in ("views.py", "urls.py", "serializers.py", "admin.py"):
        assert not (audit_dir / module).exists(), module
    assert "django.contrib.admin" not in settings.INSTALLED_APPS
    modules = {pattern.callback.__module__ for pattern in _routes(get_resolver().url_patterns)}
    assert not any(module.startswith("apps.audit") for module in modules)


def test_audit_model_is_used_only_by_audit_app():
    audit_dir = BACKEND / "apps" / "audit"
    offenders = [
        str(path.relative_to(BACKEND))
        for directory in (BACKEND / "apps", BACKEND / "config")
        for path in directory.rglob("*.py")
        if audit_dir not in path.parents and re.search(r"\bAuditEvent\b", path.read_text())
    ]
    assert offenders == []
