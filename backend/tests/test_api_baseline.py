"""API baseline: deny by default, error envelope, limits and headers (SPEC-0001)."""

import base64

import pytest
from django.conf import settings
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.request import Request
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from tests.conftest import USER_PASSWORD

HEALTH_URL = "/api/v1/health/live/"
TEST_URLS = pytest.mark.urls("tests.urls")


def _iter_api_views(patterns, prefix=""):
    for pattern in patterns:
        if isinstance(pattern, URLResolver):
            yield from _iter_api_views(pattern.url_patterns, prefix + str(pattern.pattern))
        elif isinstance(pattern, URLPattern):
            view_class = getattr(pattern.callback, "cls", None)
            if view_class is not None and issubclass(view_class, APIView):
                yield prefix + str(pattern.pattern), view_class


def _assert_envelope(response, status: int, code: str):
    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == code
    assert isinstance(body["error"]["message"], str)
    return body["error"]


def test_all_api_views_declare_permission_classes_cwe_862():
    views = list(_iter_api_views(get_resolver().url_patterns))

    assert views, "expected at least one API view"
    undeclared = [
        route for route, cls in views if cls.permission_classes is APIView.permission_classes
    ]
    assert undeclared == []


@TEST_URLS
def test_view_without_permissions_denies_authenticated_user_cwe_862(api_client, user):
    api_client.force_login(user)

    response = api_client.get("/api/test/no-permissions/")

    _assert_envelope(response, 403, "permission_denied")


@TEST_URLS
def test_unauthenticated_request_returns_401(api_client, db):
    response = api_client.get("/api/test/authenticated/")

    _assert_envelope(response, 401, "not_authenticated")
    assert response.headers["WWW-Authenticate"]


@TEST_URLS
def test_basic_auth_is_not_accepted_cwe_287(api_client, user):
    credentials = base64.b64encode(f"{user.username}:{USER_PASSWORD}".encode()).decode()

    response = api_client.get("/api/test/authenticated/", HTTP_AUTHORIZATION=f"Basic {credentials}")

    _assert_envelope(response, 401, "not_authenticated")


@TEST_URLS
def test_mutation_without_csrf_token_is_rejected_cwe_352(user):
    client = APIClient(enforce_csrf_checks=True)
    client.force_login(user)

    response = client.post("/api/test/authenticated/", {}, format="json")

    error = _assert_envelope(response, 403, "permission_denied")
    assert "CSRF" in error["message"]


@TEST_URLS
def test_mutation_with_csrf_token_is_accepted(user):
    client = APIClient(enforce_csrf_checks=True)
    client.force_login(user)
    token = "a" * 32
    client.cookies[settings.CSRF_COOKIE_NAME] = token

    response = client.post("/api/test/authenticated/", {}, format="json", HTTP_X_CSRFTOKEN=token)

    assert response.status_code == 200


def test_cross_origin_request_gets_no_cors_headers(api_client):
    get_response = api_client.get(HEALTH_URL, HTTP_ORIGIN="https://evil.example")
    preflight = api_client.options(
        HEALTH_URL,
        HTTP_ORIGIN="https://evil.example",
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
    )

    for response in (get_response, preflight):
        assert not any(name.lower().startswith("access-control-") for name in response.headers)


def test_api_security_headers_present(api_client):
    response = api_client.get(HEALTH_URL)

    assert (
        response.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "same-origin"


def test_health_live_body_is_constant_cwe_200(api_client):
    # No django_db mark: any database access by the view would fail this test.
    response = api_client.get(HEALTH_URL)

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "Server" not in response.headers
    assert "X-Powered-By" not in response.headers


def test_admin_is_not_mounted(api_client):
    response = api_client.get("/admin/")

    _assert_envelope(response, 404, "not_found")


def test_disallowed_host_returns_400_cwe_644(api_client):
    response = api_client.get(HEALTH_URL, HTTP_HOST="evil.example")

    _assert_envelope(response, 400, "bad_request")


@TEST_URLS
def test_validation_error_envelope_has_field_details(api_client, user):
    api_client.force_login(user)

    response = api_client.post("/api/test/validation/", {"name": "too-long"}, format="json")

    error = _assert_envelope(response, 400, "validation_error")
    assert "name" in error["details"]


@TEST_URLS
def test_malformed_json_returns_generic_parse_error(api_client, user):
    api_client.force_login(user)

    response = api_client.post(
        "/api/test/validation/", data="{not json", content_type="application/json"
    )

    error = _assert_envelope(response, 400, "parse_error")
    assert error["message"] == "Malformed request body."


@TEST_URLS
def test_unsupported_media_type_returns_415(api_client, user):
    api_client.force_login(user)

    response = api_client.post("/api/test/validation/", data="name=x", content_type="text/plain")

    _assert_envelope(response, 415, "unsupported_media_type")


def test_unknown_route_returns_404_envelope(api_client):
    response = api_client.get("/api/v1/does-not-exist/")

    _assert_envelope(response, 404, "not_found")


def test_method_not_allowed_returns_405_envelope(api_client):
    response = api_client.post(HEALTH_URL, {}, format="json")

    _assert_envelope(response, 405, "method_not_allowed")


def test_conflict_returns_409_envelope():
    from apps.core.api.exceptions import Conflict, exception_handler

    response = exception_handler(Conflict("The asset changed. Reload and try again."), {})

    assert response.status_code == 409
    assert response.data["error"]["code"] == "conflict"
    assert response.data["error"]["message"] == "The asset changed. Reload and try again."


@TEST_URLS
def test_unhandled_exception_returns_generic_envelope_cwe_209(api_client, user):
    api_client.force_login(user)

    response = api_client.get("/api/test/boom/")

    error = _assert_envelope(response, 500, "server_error")
    assert error["message"] == "Internal server error."
    assert "secret" not in response.content.decode()
    assert "Traceback" not in response.content.decode()


@TEST_URLS
def test_unavailable_database_returns_503_without_details(api_client, user):
    api_client.force_login(user)

    response = api_client.get("/api/test/db-down/")

    _assert_envelope(response, 503, "service_unavailable")
    assert "10.0.0.5" not in response.content.decode()


def test_request_body_over_limit_returns_413_cwe_400(api_client):
    oversized = "x" * (settings.DATA_UPLOAD_MAX_MEMORY_SIZE + 1)

    response = api_client.post(HEALTH_URL, data=oversized, content_type="application/json")

    _assert_envelope(response, 413, "payload_too_large")


@TEST_URLS
def test_page_size_is_capped_cwe_400(api_client, user):
    api_client.force_login(user)

    response = api_client.get("/api/test/items/", {"page_size": 100000})

    assert response.status_code == 200
    assert len(response.json()["results"]) == 100


@TEST_URLS
def test_throttled_request_returns_429_with_retry_after(api_client):
    for _ in range(2):
        assert api_client.get("/api/test/throttled/").status_code == 200

    response = api_client.get("/api/test/throttled/")

    _assert_envelope(response, 429, "throttled")
    assert int(response.headers["Retry-After"]) > 0


def test_default_throttles_are_configured():
    rest_framework = settings.REST_FRAMEWORK

    assert rest_framework["DEFAULT_THROTTLE_CLASSES"] == [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ]
    assert set(rest_framework["DEFAULT_THROTTLE_RATES"]) == {
        "anon",
        "user",
        # Authentication endpoints (SPEC-0003 BR-09).
        "login_ip",
        "login_username",
        "password_set",
        "password_change",
        # Per-user asset mutations (SPEC-0005 SEC-30).
        "asset_write",
        # Per-user administrative mutations (SPEC-0010 SEC-22).
        "admin_write",
        # Per-user finding mutations (SPEC-0007 SEC-32).
        "finding_write",
    }


def test_throttle_ident_ignores_spoofed_xff_cwe_348():
    # The proxy appends the real client address as the last X-Forwarded-For entry.
    raw_request = APIRequestFactory().get(
        HEALTH_URL, HTTP_X_FORWARDED_FOR="6.6.6.6, 203.0.113.10", REMOTE_ADDR="172.18.0.2"
    )

    ident = AnonRateThrottle().get_ident(Request(raw_request))

    assert ident == "203.0.113.10"
