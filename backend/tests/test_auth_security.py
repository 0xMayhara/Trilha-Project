"""Cross-cutting security requirements of SPEC-0003 (SEC-01, SEC-02, SEC-15, SEC-16, SEC-20)."""

import json
import logging
from io import StringIO
from urllib.parse import parse_qs, urlsplit

import pytest
from django.conf import settings
from django.core.cache import cache
from django.core.management import call_command
from django.urls import get_resolver
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.audit.models import AuditEvent
from apps.core.logging import JsonFormatter
from tests.test_api_baseline import _iter_api_views
from tests.test_auth_api import AUTH, PASSWORD, Browser

PUBLIC_ROUTES = {
    "api/v1/health/live/",
    "api/v1/auth/csrf/",
    "api/v1/auth/login/",
    "api/v1/auth/password/set/",
}
# Metadata keys and values each event may carry (SPEC-0003 Audit Requirements).
AUDIT_METADATA = {
    "accounts.user_created": {},
    "accounts.password_link_issued": {"purpose": {"setup", "reset"}},
    "accounts.user_disabled": {},
    "accounts.user_enabled": {},
    "accounts.login_succeeded": {},
    "accounts.login_failed": {"reason": {"invalid_credentials", "inactive", "no_usable_password"}},
    "accounts.logged_out": {},
    "accounts.password_changed": {"method": {"self_service"}},
    "accounts.password_change_failed": {"reason": {"wrong_current"}},
    "accounts.password_set": {"method": {"setup", "reset"}},
    "accounts.password_set_failed": {"reason": {"invalid_link", "disabled"}},
}


def api_views():
    return list(_iter_api_views(get_resolver().url_patterns))


def test_only_session_authentication_is_configured_cwe_287():
    assert settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] == [
        "rest_framework.authentication.SessionAuthentication"
    ]
    for route, view in api_views():
        for authentication in view.authentication_classes:
            assert issubclass(authentication, SessionAuthentication), route


def test_allowany_views_are_allowlisted_cwe_862():
    public = {route for route, view in api_views() if AllowAny in view.permission_classes}

    assert public == PUBLIC_ROUTES


def test_accounts_api_has_no_user_id_routes_cwe_639():
    auth_routes = [route for route, _ in api_views() if route.startswith("api/v1/auth/")]

    # SPEC-0010 adds reauthenticate/, which also acts on request.user only.
    assert len(auth_routes) == 7
    assert not [route for route in auth_routes if "<" in route]


@pytest.mark.django_db
def test_me_returns_only_the_requesting_user():
    alice = User.objects.create_user(username="alice", password=PASSWORD)
    bob = User.objects.create_user(username="bob", password=PASSWORD)
    browser = Browser()
    browser.login()

    response = browser.client.get(AUTH + "me/", {"id": str(bob.pk), "username": "bob"})

    assert response.json()["id"] == str(alice.pk)


@pytest.mark.django_db
def test_auth_endpoints_ignore_privilege_fields_cwe_915():
    alice = User.objects.create_user(username="alice", password=PASSWORD)
    privileged = {"is_staff": True, "is_superuser": True, "is_active": False}
    browser = Browser()
    new_password = "a-brand-new-passphrase-42"

    login = browser.post("login/", {"username": "alice", "password": PASSWORD, **privileged})
    change = browser.post(
        "password/change/",
        {"current_password": PASSWORD, "new_password": new_password, "username": "root"}
        | privileged,
    )

    assert (login.status_code, change.status_code) == (200, 204)
    alice.refresh_from_db()
    assert (alice.username, alice.is_active, alice.is_staff, alice.is_superuser) == (
        "alice",
        True,
        False,
        False,
    )
    assert alice.check_password(new_password)


@pytest.mark.django_db
def test_auth_responses_expose_no_secrets_cwe_200():
    alice = User.objects.create_user(username="alice", password=PASSWORD)
    browser = Browser()

    login = browser.login()
    me = browser.get("me/")

    for response in (login, me):
        body = response.content.decode()
        assert set(response.json()) == {"id", "username", "first_name", "last_name"}
        for secret in (browser.session_key, browser.client.cookies["csrftoken"].value):
            assert secret not in body
        assert alice.password not in body
        assert "argon2" not in body


@pytest.mark.django_db
def test_username_throttle_key_is_not_raw_username_cwe_532():
    submitted = "Pw-Typed-As-Username-5519"

    Browser().login(submitted, PASSWORD)

    keys = list(cache._cache)  # LocMemCache in tests; Redis keeps the same key strings.
    assert any("login_username" in key for key in keys)
    assert not [key for key in keys if submitted.lower() in key.lower()]


@pytest.mark.django_db
def test_audit_metadata_keys_are_allowlisted(caplog):
    exercise_every_flow()

    events = AuditEvent.objects.filter(action__startswith="accounts.")
    assert {event.action for event in events} == set(AUDIT_METADATA)
    for event in events:
        allowed = AUDIT_METADATA[event.action]
        assert set(event.metadata) == set(allowed), event.action
        for key, value in event.metadata.items():
            assert value in allowed[key], event.action


@pytest.mark.django_db
def test_credentials_never_reach_audit_or_logs_cwe_532(caplog):
    with caplog.at_level(logging.DEBUG):
        secrets = exercise_every_flow()

    stored = json.dumps(
        list(
            AuditEvent.objects.values(
                "actor_label", "resource_id", "action", "changes", "metadata", "client_ip"
            )
        ),
        default=str,
    )
    formatter = JsonFormatter()
    logged = "\n".join(formatter.format(record) for record in caplog.records)
    # Case-insensitive: values are normalized (usernames are lowercased) before they could leak.
    stored, logged = stored.lower(), logged.lower()
    for secret in secrets:
        assert secret.lower() not in stored
        assert secret.lower() not in logged


def exercise_every_flow() -> list[str]:
    """Runs every audited flow with canary values and returns the secrets that were in play."""
    canary_password = "Canary-Passphrase-7731"
    changed_password = "Canary-Changed-Pass-8842"
    typed_into_username = "Canary-Pw-In-Username-5519"
    secrets = [canary_password, changed_password, typed_into_username]

    def command(*args) -> str:
        output = StringIO()
        call_command(*args, stdout=output)
        return output.getvalue().splitlines()[0]

    def payload(link: str, password: str) -> dict:
        fragment = parse_qs(urlsplit(link).fragment)
        secrets.append(fragment["token"][0])
        return {"uid": fragment["uid"][0], "token": fragment["token"][0], "new_password": password}

    setup_link = command("accounts_create_user", "carol")
    browser = Browser(address="203.0.113.150")
    assert browser.post("password/set/", payload(setup_link, canary_password)).status_code == 204
    browser.post("password/set/", payload(setup_link, canary_password))  # Reused: failure event.

    assert browser.login("carol", canary_password).status_code == 200
    secrets += [browser.session_key, browser.client.cookies["csrftoken"].value]
    Browser(address="203.0.113.151").login(typed_into_username, canary_password)
    Browser(address="203.0.113.152").login("carol", "wrong-" + canary_password)
    browser.post(
        "password/change/", {"current_password": "wrong", "new_password": changed_password}
    )
    assert (
        browser.post(
            "password/change/",
            {"current_password": canary_password, "new_password": changed_password},
        ).status_code
        == 204
    )
    secrets.append(browser.session_key)
    assert browser.post("logout/").status_code == 204

    reset_link = command("accounts_password_link", "carol")
    secrets.append(payload(reset_link, changed_password)["token"])
    command("accounts_disable_user", "carol")
    Browser(address="203.0.113.153").login("carol", changed_password)
    Browser(address="203.0.113.154").post("password/set/", payload(reset_link, changed_password))
    enable_link = command("accounts_enable_user", "carol")
    assert (
        Browser(address="203.0.113.155")
        .post("password/set/", payload(enable_link, "Canary-Reenabled-Pass-9953"))
        .status_code
        == 204
    )
    secrets.append("Canary-Reenabled-Pass-9953")
    # A pending account, then the password hash itself.
    command("accounts_create_user", "dave")
    Browser(address="203.0.113.156").login("dave", canary_password)
    secrets.append(User.objects.get(username="carol").password)
    APIClient().get(AUTH + "me/")
    return secrets
