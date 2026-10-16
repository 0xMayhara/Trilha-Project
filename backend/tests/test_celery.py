"""Celery baseline (SPEC-0001 SEC-14, SEC-15)."""

import pickle
import uuid
from types import SimpleNamespace

import pytest
from kombu.exceptions import ContentDisallowed
from kombu.serialization import loads

from apps.core.celery_signals import attach_request_id, bind_request_id, unbind_request_id
from apps.core.request_context import get_request_id, request_id_var
from config.celery import app


def test_celery_accepts_only_json_cwe_502():
    malicious = pickle.dumps({"task": "anything"})

    assert app.conf.accept_content == ["json"]
    assert app.conf.task_serializer == "json"
    with pytest.raises(ContentDisallowed):
        loads(malicious, "application/x-python-serialize", "binary", accept=app.conf.accept_content)


def test_celery_default_limits():
    assert app.conf.task_time_limit == 300
    assert app.conf.task_soft_time_limit == 270
    assert app.conf.task_ignore_result is True
    assert app.conf.result_backend is None


def test_request_id_propagates_to_celery():
    request_id = str(uuid.uuid4())
    headers: dict = {}
    token = request_id_var.set(request_id)
    try:
        attach_request_id(headers=headers)
    finally:
        request_id_var.reset(token)

    bind_request_id(task=SimpleNamespace(request=SimpleNamespace(**headers)))
    try:
        assert get_request_id() == request_id
    finally:
        unbind_request_id()
    assert get_request_id() is None


def test_forged_task_request_id_is_replaced_cwe_117():
    forged = 'x\n{"level": "INFO"}'

    bind_request_id(task=SimpleNamespace(request=SimpleNamespace(request_id=forged)))
    try:
        bound = get_request_id()
        assert bound != forged
        assert str(uuid.UUID(bound)) == bound
    finally:
        unbind_request_id()
