"""Audit context: source and client IP come from the server, never from the caller
(SPEC-0002 SEC-07…SEC-09, SEC-19)."""

import logging
import uuid
from types import SimpleNamespace

import pytest
from django.db import transaction
from django.test import RequestFactory

from apps.audit.celery_signals import bind_audit_task_context, unbind_audit_task_context
from apps.audit.context import AuditContext, audit_source, current_context, http_context
from apps.audit.exceptions import AuditContextMissing
from apps.audit.middleware import AuditContextMiddleware
from apps.audit.models import AuditEvent, Source
from apps.audit.services import record_event
from apps.audit.types import Actor
from config.celery import app

TEST_URLS = pytest.mark.urls("tests.urls")
AUDITED_URL = "/api/test/audited/"


def _assert_no_context():
    with pytest.raises(AuditContextMissing):
        current_context()


@pytest.mark.django_db
@TEST_URLS
def test_http_request_sets_http_source_and_ip(api_client, user):
    api_client.force_login(user)
    request_id = str(uuid.uuid4())

    response = api_client.post(AUDITED_URL, HTTP_X_REQUEST_ID=request_id)

    assert response.status_code == 200
    event = AuditEvent.objects.get(event_id=response.json()["event_id"])
    assert event.source == "http"
    assert event.client_ip == "127.0.0.1"
    assert str(event.request_id) == request_id
    assert event.actor_id == user.pk
    _assert_no_context()


@pytest.mark.django_db
@TEST_URLS
def test_audit_ip_ignores_spoofed_forwarded_for_cwe_348(api_client, user):
    api_client.force_login(user)

    # The client sent "10.0.0.7"; the trusted proxy appended the real address it saw.
    response = api_client.post(AUDITED_URL, HTTP_X_FORWARDED_FOR="10.0.0.7, 203.0.113.9")

    event = AuditEvent.objects.get(event_id=response.json()["event_id"])
    assert event.client_ip == "203.0.113.9"


@pytest.mark.django_db
@TEST_URLS
def test_invalid_client_address_is_not_recorded_cwe_20(api_client, user, caplog):
    api_client.force_login(user)

    with caplog.at_level(logging.WARNING, logger="apps.core.http"):
        response = api_client.post(AUDITED_URL, HTTP_X_FORWARDED_FOR="not-an-ip\nforged")

    assert response.status_code == 200
    event = AuditEvent.objects.get(event_id=response.json()["event_id"])
    assert event.client_ip is None
    warnings = [r for r in caplog.records if getattr(r, "event", None) == "invalid_client_address"]
    assert len(warnings) == 1
    assert "not-an-ip" not in str(vars(warnings[0]))


def test_audit_context_is_reset_after_failed_request():
    def failing_view(request):
        assert current_context() == AuditContext(source=Source.HTTP, client_ip="127.0.0.1")
        raise RuntimeError("view failed")

    middleware = AuditContextMiddleware(failing_view)

    with pytest.raises(RuntimeError):
        middleware(RequestFactory().get("/"))
    _assert_no_context()


def test_audit_source_restores_previous_context():
    _assert_no_context()
    with audit_source("sync"):
        with audit_source(Source.COMMAND):
            assert current_context().source == Source.COMMAND
        assert current_context() == AuditContext(source=Source.SYNC, client_ip=None)
    _assert_no_context()
    with pytest.raises(ValueError):
        with audit_source("web"):
            pass


def test_task_signals_bind_task_source_and_restore_enclosing_context():
    task = SimpleNamespace(request=SimpleNamespace())

    with http_context("203.0.113.9"):
        bind_audit_task_context(task=task)
        assert current_context() == AuditContext(source=Source.TASK, client_ip=None)
        unbind_audit_task_context(task=task)
        assert current_context() == AuditContext(source=Source.HTTP, client_ip="203.0.113.9")
    _assert_no_context()


@app.task(name="tests.audited_task")
def audited_task():
    with transaction.atomic():
        return str(record_event(actor=Actor.system("tests"), action="tests.task_ran").event_id)


@app.task(name="tests.failing_task")
def failing_task():
    assert current_context().source == Source.TASK
    raise RuntimeError("task failed")


@pytest.mark.django_db
def test_celery_task_sets_task_source():
    result = audited_task.apply()

    event = AuditEvent.objects.get(event_id=result.get())
    assert event.source == "task"
    assert event.client_ip is None
    _assert_no_context()


def test_audit_context_is_reset_after_failed_task():
    result = failing_task.apply()

    assert isinstance(result.result, RuntimeError)
    _assert_no_context()
