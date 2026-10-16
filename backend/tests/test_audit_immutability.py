"""Audit events are append-only in the application and in PostgreSQL (SPEC-0002 SEC-01…SEC-04,
SEC-18, ADR-0003)."""

import logging

import pytest
from django.core.management import call_command
from django.db import IntegrityError, connection, transaction
from django.db.migrations.exceptions import IrreversibleError

from apps.audit.context import audit_source
from apps.audit.exceptions import AuditEventImmutable
from apps.audit.models import AuditEvent, AuditEventQuerySet
from apps.audit.services import record_event
from apps.audit.types import Actor

pytestmark = pytest.mark.django_db


@pytest.fixture
def event():
    with audit_source("command"), transaction.atomic():
        return record_event(
            actor=Actor.system("tests"),
            action="tests.event_recorded",
            metadata={"note": "original-value"},
        )


def _assert_unchanged(event):
    stored = AuditEvent.objects.get(pk=event.pk)
    assert stored.action == "tests.event_recorded"
    assert stored.metadata == {"note": "original-value"}


def test_saving_existing_event_is_rejected_cwe_471(event):
    loaded = AuditEvent.objects.get(pk=event.pk)
    loaded.action = "tests.event_rewritten"

    with pytest.raises(AuditEventImmutable):
        loaded.save()
    with pytest.raises(AuditEventImmutable):
        loaded.save(update_fields=["action"])
    with pytest.raises(AuditEventImmutable):
        loaded.delete()
    _assert_unchanged(event)


def test_new_instance_with_existing_id_cannot_overwrite_cwe_471(event):
    forged = AuditEvent(
        id=event.id,
        actor_type="system",
        actor_label="attacker",
        action="tests.event_rewritten",
        source="command",
    )

    with pytest.raises(IntegrityError), transaction.atomic():
        forged.save()
    _assert_unchanged(event)


@pytest.mark.parametrize("manager_name", ["objects", "_base_manager"])
def test_queryset_update_and_delete_are_rejected_cwe_471(
    event, manager_name, django_assert_num_queries
):
    manager = getattr(AuditEvent, manager_name)
    assert isinstance(manager.all(), AuditEventQuerySet)
    event.action = "tests.event_rewritten"

    with django_assert_num_queries(0):
        with pytest.raises(AuditEventImmutable):
            manager.all().update(action="tests.event_rewritten")
        with pytest.raises(AuditEventImmutable):
            manager.all().delete()
        with pytest.raises(AuditEventImmutable):
            manager.bulk_update([event], ["action"])
    _assert_unchanged(event)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_auditevent SET actor_label = 'someone-else' WHERE id = %s",
        "DELETE FROM audit_auditevent WHERE id = %s",
    ],
)
def test_raw_sql_update_and_delete_are_rejected_by_database_cwe_471(event, statement):
    with pytest.raises(IntegrityError) as excinfo, transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(statement, [event.pk])

    assert excinfo.value.__cause__.sqlstate == "23001"
    assert "append-only" in str(excinfo.value)
    _assert_unchanged(event)


def test_audit_migrations_cannot_be_reversed(event):
    with pytest.raises(IrreversibleError):
        call_command("migrate", "audit", "zero", verbosity=0)

    _assert_unchanged(event)


def test_tamper_attempt_is_logged_without_values(event, caplog):
    loaded = AuditEvent.objects.get(pk=event.pk)

    with caplog.at_level(logging.WARNING, logger="apps.audit"):
        with pytest.raises(AuditEventImmutable):
            loaded.save()
        with pytest.raises(AuditEventImmutable):
            AuditEvent.objects.filter(pk=event.pk).update(metadata={"note": "forged-value"})

    records = [record for record in caplog.records if record.name == "apps.audit"]
    assert [record.operation for record in records] == ["save", "queryset.update"]
    assert records[0].audit_event_id == str(event.event_id)
    for record in records:
        assert record.levelno == logging.WARNING
        rendered = str(vars(record))
        assert "original-value" not in rendered
        assert "forged-value" not in rendered
