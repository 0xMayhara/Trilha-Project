"""SPEC-0010 step-up re-authentication and platform self state (BR-07, BR-08; SEC-11, SEC-12)."""

import json
import logging
import time
from datetime import datetime

import pytest
from django.contrib.sessions.models import Session
from django.core.cache import cache
from rest_framework.test import APIClient

from apps.accounts import services as accounts
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from apps.core.logging import JsonFormatter
from apps.rbac import administration
from tests.platform_support import OPERATOR, PASSWORD, Browser, make_admin, make_user

pytestmark = pytest.mark.django_db
REAUTH = "/api/v1/auth/reauthenticate/"
PLATFORM = "/api/v1/rbac/me/platform/"
WRONG = "Wrong-Canary-Passphrase-4471"


# SEC-12 — re-authentication rotates the session key and the CSRF token (T-12, CWE-384)


def test_reauthentication_rotates_session_key_and_csrf_cwe_384():
    make_user("alice")
    browser = Browser().login("alice")
    old_key, old_csrf = browser.session_key, browser.client.cookies["csrftoken"].value
    old_expiry = Session.objects.get(session_key=old_key).expire_date
    time.sleep(0.01)
    response = browser.reauthenticate()
    assert response.status_code == 204 and response.content == b""
    assert browser.session_key != old_key
    assert browser.client.cookies["csrftoken"].value != old_csrf
    assert not Session.objects.filter(session_key=old_key).exists()
    proof = browser.session_data()[accounts.STEP_UP_SESSION_KEY]
    assert proof["user_id"] == str(browser.session_data()["_auth_user_id"])
    assert abs(proof["verified_at"] - time.time()) < 5
    # The rewrite restarts the server-side lifetime, as a login does (Q-02, SPEC-0003 BR-08).
    assert Session.objects.get(session_key=browser.session_key).expire_date > old_expiry
    stolen = APIClient()
    stolen.cookies["sessionid"] = old_key
    assert stolen.get("/api/v1/auth/me/").status_code == 401
    assert browser.get("/api/v1/auth/me/").status_code == 200
    # The old CSRF token no longer passes with the new cookie.
    stale = browser.send(
        "post", REAUTH, {"password": PASSWORD}, csrf=False, HTTP_X_CSRFTOKEN=old_csrf
    )
    assert stale.status_code == 403


# SEC-11 — guessing is throttled with the password-change budget and audited (T-11, CWE-307)


def test_reauthentication_is_throttled_and_audited_cwe_307(caplog):
    alice = make_user("alice")
    browser = Browser().login("alice")
    with caplog.at_level(logging.DEBUG):
        failed = browser.reauthenticate(WRONG)
    assert failed.status_code == 400
    error = failed.json()["error"]
    assert (error["code"], error["message"]) == (
        "invalid_credentials",
        "The password is incorrect.",
    )
    event = AuditEvent.objects.get(action="accounts.reauthentication_failed")
    assert event.outcome == "failure" and event.actor_id == alice.pk
    assert event.metadata == {"reason": "invalid_password"} and event.changes == {}
    (record,) = [r for r in caplog.records if r.getMessage() == "reauthentication_failed"]
    assert record.levelname == "WARNING" and record.actor_id == str(alice.pk)
    logged = "\n".join(JsonFormatter().format(r) for r in caplog.records)
    stored = json.dumps(list(AuditEvent.objects.values("changes", "metadata")))
    assert WRONG not in logged and WRONG not in stored and PASSWORD not in logged
    assert accounts.STEP_UP_SESSION_KEY not in browser.session_data()

    # One budget for password changes and re-authentications (design review F-04): 10/hour.
    for _ in range(4):
        change = browser.post(
            "/api/v1/auth/password/change/",
            {"current_password": WRONG, "new_password": "Another-Passphrase-99"},
        )
        assert change.status_code == 400
    statuses = [browser.reauthenticate(WRONG).status_code for _ in range(6)]
    assert statuses == [400] * 5 + [429]
    assert browser.reauthenticate().status_code == 429  # even the right password waits
    assert [key for key in cache._cache if "password_change" in key]
    assert not [key for key in cache._cache if "reauthenticat" in key]
    assert AuditEvent.objects.filter(action="accounts.reauthentication_failed").count() == 6

    cache.clear()
    assert browser.reauthenticate().status_code == 204
    success = AuditEvent.objects.get(action="accounts.reauthenticated")
    assert success.actor_id == alice.pk and success.metadata == {} and success.changes == {}


def test_reauthentication_requires_session_csrf_and_strict_body():
    assert APIClient().post(REAUTH, {"password": PASSWORD}, format="json").status_code == 401
    make_user("alice")
    browser = Browser().login("alice")
    key = browser.session_key
    assert browser.post(REAUTH, {"password": PASSWORD}, csrf=False).status_code == 403
    for body in (
        {"password": PASSWORD, "reauthenticated_at": time.time()},
        {"password": 123},
        {"password": "x" * 1025},
        {},
        [],
    ):
        assert browser.post(REAUTH, body).status_code == 400, body
    duplicated = browser.send(
        "post", REAUTH, raw='{"password": "a", "password": "' + PASSWORD + '"}'
    )
    assert duplicated.status_code == 400
    assert browser.session_key == key and accounts.STEP_UP_SESSION_KEY not in browser.session_data()
    assert not AuditEvent.objects.filter(action__startswith="accounts.reauth").exists()
    for method in ("get", "put", "delete"):
        assert browser.send(method, REAUTH).status_code == 405


def test_disabled_account_cannot_reauthenticate():
    make_user("alice")
    browser = Browser().login("alice")
    with audit_source("command"):
        administration.disable_account(OPERATOR, browser.session_data()["_auth_user_id"])
    assert browser.reauthenticate().status_code == 401
    assert browser.get(PLATFORM).status_code == 401


def test_logout_and_password_reset_end_the_proof():
    alice = make_user("alice")
    browser = Browser().login("alice")
    assert browser.reauthenticate().status_code == 204
    assert browser.post("/api/v1/auth/logout/").status_code == 204
    browser.login("alice")
    assert accounts.STEP_UP_SESSION_KEY not in browser.session_data()
    assert browser.reauthenticate().status_code == 204
    with audit_source("command"):
        link = administration.issue_password_link(OPERATOR, alice.pk)
    fragment = dict(part.split("=", 1) for part in link.split("#", 1)[1].split("&"))
    reset = Browser(address="203.0.113.99").post(
        "/api/v1/auth/password/set/", {**fragment, "new_password": "A-Fresh-Passphrase-31"}
    )
    assert reset.status_code == 204
    assert browser.get(PLATFORM).status_code == 401  # the session and its proof ended


# PlatformSelf — the caller's own state, for the UI only


def test_platform_self_reports_own_state_only():
    assert APIClient().get(PLATFORM).status_code == 401
    make_user("plain")
    plain = Browser().login("plain")
    assert plain.get(PLATFORM).json() == {
        "is_admin": False,
        "position": None,
        "reauthenticated_until": None,
    }
    assert plain.get(PLATFORM, {"user": "x"}).status_code == 400
    admin = make_admin("root")
    with audit_source("command"):
        administration.set_position(OPERATOR, admin.pk, "engineer")
    browser = Browser().login("root")
    body = browser.get(PLATFORM).json()
    assert body == {"is_admin": True, "position": "engineer", "reauthenticated_until": None}
    browser.reauthenticate()
    until = datetime.fromisoformat(browser.get(PLATFORM).json()["reauthenticated_until"])
    assert 590 < until.timestamp() - time.time() <= 600
    # A forged timestamp in a header or the query string changes nothing.
    forged = plain.get(PLATFORM, HTTP_X_REAUTHENTICATED_AT=str(time.time()))
    assert forged.json()["reauthenticated_until"] is None
