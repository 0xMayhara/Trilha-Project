"""Logging and correlation ID (SPEC-0001 SEC-13, SEC-14)."""

import json
import logging
import uuid

import pytest
from django.test import RequestFactory

from apps.core.logging import REDACTED, JsonFormatter

HEALTH_URL = "/api/v1/health/live/"


def _format(message: str = "event", **extra) -> str:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, message, None, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return JsonFormatter().format(record)


@pytest.fixture
def access_log(caplog):
    caplog.set_level(logging.INFO, logger="apps.access")
    return caplog


def test_log_redaction_masks_sensitive_keys_cwe_532():
    output = _format(
        password="hunter2",
        headers={"Authorization": "Bearer abc.def", "Cookie": "sessionid=s3ss10n", "Accept": "*/*"},
        provider={"API_KEY": "k-123", "private_key": "-----BEGIN", "url": "https://wazuh"},
        items=[{"refresh_token": "r-1"}],
    )

    for leaked in ("hunter2", "abc.def", "s3ss10n", "k-123", "BEGIN", "r-1"):
        assert leaked not in output
    payload = json.loads(output)
    assert payload["password"] == REDACTED
    assert payload["headers"]["Accept"] == "*/*"
    assert payload["provider"]["url"] == "https://wazuh"


def test_log_output_escapes_control_chars_cwe_117():
    forged = 'ok\n{"level": "INFO", "message": "forged entry"}\r'

    output = _format(forged)

    assert "\n" not in output and "\r" not in output
    assert json.loads(output)["message"] == forged


def test_django_request_context_is_reduced_to_method_and_path():
    request = RequestFactory().get("/api/v1/items/?token=s3cr3t")

    payload = json.loads(_format(request=request))

    assert payload["request"] == {"method": "GET", "path": "/api/v1/items/"}


def test_invalid_request_id_is_replaced_cwe_117(api_client):
    forged = 'abc\n{"level": "INFO"}'

    response = api_client.get(HEALTH_URL, HTTP_X_REQUEST_ID=forged)

    assigned = response.headers["X-Request-ID"]
    assert assigned != forged
    assert str(uuid.UUID(assigned)) == assigned


def test_valid_request_id_is_propagated(api_client):
    incoming = str(uuid.uuid4())

    response = api_client.get(HEALTH_URL, HTTP_X_REQUEST_ID=incoming)

    assert response.headers["X-Request-ID"] == incoming


def test_error_envelope_includes_request_id(api_client):
    response = api_client.get("/api/v1/does-not-exist/")

    assert response.json()["error"]["request_id"] == response.headers["X-Request-ID"]


def test_request_log_excludes_query_values_and_headers(api_client, access_log):
    api_client.get(
        f"{HEALTH_URL}?token=qu3ry-s3cr3t",
        HTTP_AUTHORIZATION="Bearer h34der-s3cr3t",
        HTTP_COOKIE="sessionid=c00kie-s3cr3t",
    )

    (record,) = [r for r in access_log.records if r.name == "apps.access"]
    output = JsonFormatter().format(record)
    for leaked in ("qu3ry-s3cr3t", "h34der-s3cr3t", "c00kie-s3cr3t"):
        assert leaked not in output
    payload = json.loads(output)
    assert payload["path"] == HEALTH_URL
    assert payload["status"] == 200
    assert payload["level"] == "INFO"


@pytest.mark.urls("tests.urls")
def test_denied_request_is_logged_as_security_event(api_client, db, access_log):
    api_client.get("/api/test/authenticated/")

    (record,) = [r for r in access_log.records if r.name == "apps.access"]
    assert record.levelno == logging.WARNING
    assert record.status == 401
