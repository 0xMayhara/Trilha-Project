"""Session authentication API (SPEC-0003 BR-04..BR-09, SEC-03..SEC-13, SEC-19)."""

import threading
import time
import uuid
from datetime import datetime, timedelta
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import pytest
from django.conf import settings
from django.contrib.auth.hashers import Argon2PasswordHasher
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from django.utils.http import urlsafe_base64_encode
from redis.exceptions import ConnectionError as RedisConnectionError
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle

from apps.accounts import services
from apps.accounts.models import User
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent

AUTH = "/api/v1/auth/"
PASSWORD = "correct-horse-battery-staple"
WRONG_PASSWORD = "wrong-password-123"
NEW_PASSWORD = "a-brand-new-passphrase-42"
WEAK_PASSWORDS = ["short-pass1", "password1234", "123456789012"]


class Browser:
    """Behaves like the frontend: CSRF checks on, the token read from the csrftoken cookie."""

    def __init__(self, address: str = "203.0.113.10", forwarded_for: str | None = None):
        environ = {"REMOTE_ADDR": address}
        if forwarded_for:
            environ["HTTP_X_FORWARDED_FOR"] = forwarded_for
        self.client = APIClient(enforce_csrf_checks=True, **environ)

    def get(self, path):
        return self.client.get(AUTH + path)

    def post(self, path, data=None, *, csrf=True):
        headers = {}
        if csrf:
            if "csrftoken" not in self.client.cookies:
                self.client.get(AUTH + "csrf/")
            headers["HTTP_X_CSRFTOKEN"] = self.client.cookies["csrftoken"].value
        return self.client.post(AUTH + path, data or {}, format="json", **headers)

    def login(self, username="alice", password=PASSWORD):
        return self.post("login/", {"username": username, "password": password})

    @property
    def session_key(self) -> str:
        return self.client.cookies["sessionid"].value


@pytest.fixture
def alice(db):
    return User.objects.create_user(username="alice", password=PASSWORD)


def as_command(function, *args):
    with audit_source("command"):
        return function(*args)


def link_payload(link: str, new_password: str = NEW_PASSWORD) -> dict:
    fragment = parse_qs(urlsplit(link).fragment)
    return {"uid": fragment["uid"][0], "token": fragment["token"][0], "new_password": new_password}


def set_password(link: str, new_password: str = NEW_PASSWORD):
    return Browser(address="203.0.113.200").post("password/set/", link_payload(link, new_password))


def assert_invalid_link(response):
    assert response.status_code == 400
    error = response.json()["error"]
    assert set(error) == {"code", "message", "request_id"}
    assert (error["code"], error["message"]) == (
        "invalid_link",
        "This link is invalid or has expired.",
    )


def assert_csrf_rejected(response):
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "permission_denied"
    assert "CSRF" in error["message"]


def failure_cases():
    """(username, password, resource id, audit reason) for every kind of failed login."""
    alice = User.objects.create_user(username="alice", password=PASSWORD)
    dora = User.objects.create_user(username="dora", password=PASSWORD)
    as_command(services.disable_user, "dora")
    pete, _ = as_command(services.create_user, "pete")
    return [
        ("nobody", PASSWORD, "", "invalid_credentials"),
        ("alice", WRONG_PASSWORD, str(alice.pk), "invalid_credentials"),
        ("dora", PASSWORD, str(dora.pk), "inactive"),
        ("pete", PASSWORD, str(pete.pk), "no_usable_password"),
    ]


# --- CSRF bootstrap and login --------------------------------------------------------------------


@pytest.mark.django_db
def test_csrf_endpoint_sets_the_cookie_and_returns_no_data():
    client = APIClient(enforce_csrf_checks=True)

    response = client.get(AUTH + "csrf/")

    assert response.status_code == 204
    assert response.content == b""
    assert client.cookies["csrftoken"].value


def test_login_returns_the_user_summary_and_starts_a_session(alice):
    browser = Browser()

    response = browser.login()

    assert response.status_code == 200
    assert response.json() == {
        "id": str(alice.pk),
        "username": "alice",
        "first_name": "",
        "last_name": "",
    }
    assert browser.get("me/").json()["id"] == str(alice.pk)


def test_login_lowercases_username(alice):
    assert Browser().login(username="ALICE").status_code == 200


@pytest.mark.django_db
def test_login_failures_are_indistinguishable_cwe_204():
    responses = [
        Browser(address=f"203.0.113.{20 + index}").login(username, password)
        for index, (username, password, _, _) in enumerate(failure_cases())
    ]

    shapes = set()
    for response in responses:
        error = response.json()["error"]
        del error["request_id"]
        shapes.add(
            (
                response.status_code,
                tuple(sorted(error.items())),
                tuple(sorted(name.lower() for name in response.headers)),
                tuple(sorted(response.cookies)),
            )
        )
    assert len(shapes) == 1
    status, error, _, cookies = shapes.pop()
    assert status == 400
    assert dict(error) == {
        "code": "invalid_credentials",
        "message": "Invalid username or password.",
    }
    assert "sessionid" not in cookies


def _hasher_calls(username: str, password: str) -> int:
    encode, verify = Argon2PasswordHasher.encode, Argon2PasswordHasher.verify
    with (
        mock.patch.object(Argon2PasswordHasher, "encode", autospec=True, side_effect=encode) as e,
        mock.patch.object(Argon2PasswordHasher, "verify", autospec=True, side_effect=verify) as v,
    ):
        assert Browser().login(username, password).status_code == 400
    return e.call_count + v.call_count


@pytest.mark.django_db
def test_login_runs_password_hasher_for_unknown_user_cwe_208():
    assert _hasher_calls("nobody", PASSWORD) >= 1


@pytest.mark.django_db
@pytest.mark.parametrize("username", ["dora", "pete"])
def test_login_runs_password_hasher_for_disabled_or_pending_account_cwe_208(username):
    failure_cases()

    assert _hasher_calls(username, PASSWORD) >= 1


def test_login_failure_query_count_does_not_depend_on_account_cwe_208(alice):
    browser = Browser()
    browser.client.get(AUTH + "csrf/")
    counts = []
    for username in ("nobody", "alice"):
        with CaptureQueriesContext(connection) as queries:
            assert browser.login(username, WRONG_PASSWORD).status_code == 400
        counts.append(len(queries))

    assert counts[0] == counts[1]


def test_login_without_csrf_token_is_rejected_cwe_352(alice):
    browser = Browser()

    response = browser.post("login/", {"username": "alice", "password": PASSWORD}, csrf=False)

    assert_csrf_rejected(response)
    assert "sessionid" not in browser.client.cookies
    assert not AuditEvent.objects.filter(action="accounts.login_succeeded").exists()


def test_login_accepts_the_configured_origin_through_the_proxy(alice):
    # nginx forwards Host without the published port; the browser's Origin keeps it.
    browser = Browser()
    browser.client.get(AUTH + "csrf/")

    response = browser.client.post(
        AUTH + "login/",
        {"username": "alice", "password": PASSWORD},
        format="json",
        HTTP_ORIGIN=settings.TRILHA_BASE_URL,
        HTTP_X_CSRFTOKEN=browser.client.cookies["csrftoken"].value,
    )

    assert response.status_code == 200


def test_login_from_a_foreign_origin_is_rejected_cwe_352(alice):
    browser = Browser()
    browser.client.get(AUTH + "csrf/")

    response = browser.client.post(
        AUTH + "login/",
        {"username": "alice", "password": PASSWORD},
        format="json",
        HTTP_ORIGIN="http://evil.example",
        HTTP_X_CSRFTOKEN=browser.client.cookies["csrftoken"].value,
    )

    assert_csrf_rejected(response)
    assert "sessionid" not in browser.client.cookies


def test_login_rotates_session_key_cwe_384(alice):
    planted = SessionStore()
    planted.create()  # A session key the attacker knows and plants in the victim's browser.
    browser = Browser()
    browser.client.cookies["sessionid"] = planted.session_key

    assert browser.login().status_code == 200

    assert browser.session_key != planted.session_key
    attacker = APIClient()
    attacker.cookies["sessionid"] = planted.session_key
    assert attacker.get(AUTH + "me/").status_code == 401


def test_login_rotates_csrf_token_cwe_352(alice):
    browser = Browser()
    browser.client.get(AUTH + "csrf/")
    before = browser.client.cookies["csrftoken"].value

    browser.login()

    assert browser.client.cookies["csrftoken"].value != before


# --- Sessions: logout, expiry, cookies -----------------------------------------------------------


def test_logout_deletes_server_side_session_cwe_613(alice):
    browser = Browser()
    browser.login()
    key = browser.session_key

    assert browser.post("logout/").status_code == 204

    assert not Session.objects.filter(session_key=key).exists()
    replay = APIClient()
    replay.cookies["sessionid"] = key
    assert replay.get(AUTH + "me/").status_code == 401


def test_logout_without_csrf_token_is_rejected_cwe_352(alice):
    browser = Browser()
    browser.login()

    assert_csrf_rejected(browser.post("logout/", csrf=False))
    assert browser.get("me/").status_code == 200


@pytest.mark.django_db
@pytest.mark.parametrize("path", ["me/", "logout/", "password/change/"])
def test_session_endpoints_require_authentication(path):
    client = APIClient()
    response = client.get(AUTH + path) if path == "me/" else client.post(AUTH + path, {})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"


def test_expired_session_is_rejected_cwe_613(alice):
    browser = Browser()
    browser.login()

    Session.objects.filter(session_key=browser.session_key).update(
        expire_date=timezone.now() - timedelta(seconds=1)
    )

    assert browser.get("me/").status_code == 401


def test_session_cookie_expires_at_browser_close(alice):
    response = Browser().login()

    cookie = response.cookies["sessionid"]
    assert (cookie["max-age"], cookie["expires"]) == ("", "")
    session = Session.objects.get(session_key=cookie.value)
    lifetime = session.expire_date - timezone.now()
    assert timedelta(seconds=settings.SESSION_COOKIE_AGE - 60) < lifetime
    assert lifetime <= timedelta(seconds=settings.SESSION_COOKIE_AGE)


# --- Account disabling ---------------------------------------------------------------------------


def test_disabled_user_session_is_rejected_cwe_613(alice):
    browser = Browser()
    browser.login()

    as_command(services.disable_user, "alice")

    assert browser.get("me/").status_code == 401


def test_reenabled_user_old_session_stays_invalid_cwe_613(alice):
    browser = Browser()
    browser.login()
    key = browser.session_key

    as_command(services.disable_user, "alice")
    as_command(services.enable_user, "alice")

    replay = APIClient()
    replay.cookies["sessionid"] = key
    assert replay.get(AUTH + "me/").status_code == 401


# --- Password change -----------------------------------------------------------------------------


def change(browser, current=PASSWORD, new=NEW_PASSWORD, **kwargs):
    return browser.post(
        "password/change/", {"current_password": current, "new_password": new}, **kwargs
    )


def test_password_change_requires_current_password_cwe_620(alice):
    browser = Browser()
    browser.login()

    response = change(browser, current=WRONG_PASSWORD)

    assert response.status_code == 400
    assert response.json()["error"]["details"] == {
        "current_password": ["The current password is incorrect."]
    }
    alice.refresh_from_db()
    assert alice.check_password(PASSWORD)


def test_password_change_keeps_current_session_with_new_key_cwe_384(alice):
    browser = Browser()
    browser.login()
    before = browser.session_key

    assert change(browser).status_code == 204

    assert browser.session_key != before
    assert browser.get("me/").status_code == 200
    alice.refresh_from_db()
    assert alice.check_password(NEW_PASSWORD)


def test_password_change_ends_other_sessions_cwe_613(alice):
    laptop, phone = Browser(), Browser(address="203.0.113.11")
    laptop.login()
    phone.login()

    assert change(laptop).status_code == 204

    assert phone.get("me/").status_code == 401
    assert laptop.get("me/").status_code == 200


def test_password_change_without_csrf_token_is_rejected_cwe_352(alice):
    browser = Browser()
    browser.login()

    assert_csrf_rejected(change(browser, csrf=False))
    alice.refresh_from_db()
    assert alice.check_password(PASSWORD)


@pytest.mark.parametrize("weak", WEAK_PASSWORDS)
def test_weak_password_is_rejected_cwe_521(alice, weak):
    browser = Browser()
    browser.login()
    _, link = as_command(services.create_user, "pete")

    for response in (change(browser, new=weak), set_password(link, weak)):
        assert response.status_code == 400
        assert set(response.json()["error"]["details"]) == {"new_password"}
    alice.refresh_from_db()
    assert alice.check_password(PASSWORD)


def test_oversized_password_is_rejected_cwe_400(alice):
    browser = Browser()
    browser.login()
    oversized = "x" * 1025

    changed = change(browser, new=oversized)
    login = Browser(address="203.0.113.12").login("alice", oversized)

    assert changed.status_code == 400
    assert set(changed.json()["error"]["details"]) == {"new_password"}
    assert login.status_code == 400
    assert set(login.json()["error"]["details"]) == {"password"}


def test_password_errors_do_not_echo_value_cwe_209(alice):
    browser = Browser()
    browser.login()
    weak = "1234567890123456"

    response = change(browser, new=weak)

    assert response.status_code == 400
    assert weak not in response.content.decode()


# --- Set-password links --------------------------------------------------------------------------


@pytest.mark.django_db
def test_setup_link_sets_password_and_allows_login():
    _, link = as_command(services.create_user, "pete")

    assert set_password(link).status_code == 204

    assert Browser().login("pete", NEW_PASSWORD).status_code == 200


@pytest.mark.django_db
def test_link_is_single_use_cwe_640():
    _, link = as_command(services.create_user, "pete")
    assert set_password(link).status_code == 204

    assert_invalid_link(set_password(link, "another-new-passphrase-7"))
    assert Browser().login("pete", NEW_PASSWORD).status_code == 200


@pytest.mark.django_db
def test_link_expires_cwe_640():
    _, link = as_command(services.create_user, "pete")
    later = datetime.now() + timedelta(seconds=settings.PASSWORD_RESET_TIMEOUT + 1)

    with mock.patch.object(PasswordResetTokenGenerator, "_now", return_value=later):
        assert_invalid_link(set_password(link))


def test_link_is_invalid_after_login_cwe_640(alice):
    link = as_command(services.issue_password_link, "alice")

    Browser().login()

    assert_invalid_link(set_password(link))
    alice.refresh_from_db()
    assert alice.check_password(PASSWORD)


def test_forged_link_is_rejected_cwe_640(alice):
    payload = link_payload(as_command(services.issue_password_link, "alice"))
    payload["token"] = "d0abcd-" + "0" * 32

    assert_invalid_link(Browser().post("password/set/", payload))


@pytest.mark.django_db
@pytest.mark.parametrize(
    "uid", [urlsafe_base64_encode(str(uuid.uuid4()).encode()), "!!!", "bm90LWEtdXVpZA"]
)
def test_unknown_uid_is_rejected_cwe_640(uid):
    payload = {"uid": uid, "token": "d0abcd-" + "0" * 32, "new_password": NEW_PASSWORD}

    assert_invalid_link(Browser().post("password/set/", payload))


def test_link_for_disabled_account_is_rejected_cwe_640(alice):
    link = as_command(services.issue_password_link, "alice")
    as_command(services.disable_user, "alice")

    assert_invalid_link(set_password(link))


@pytest.mark.django_db
def test_rejected_new_password_does_not_consume_link():
    _, link = as_command(services.create_user, "pete")

    weak = set_password(link, "123456789012")

    assert weak.json()["error"]["code"] == "validation_error"
    assert set_password(link).status_code == 204


@pytest.mark.django_db
def test_password_set_without_csrf_token_is_rejected_cwe_352():
    pete, link = as_command(services.create_user, "pete")

    assert_csrf_rejected(Browser().post("password/set/", link_payload(link), csrf=False))
    pete.refresh_from_db()
    assert not pete.has_usable_password()


def test_password_set_ends_existing_sessions_cwe_613(alice):
    browser = Browser()
    browser.login()
    link = as_command(services.issue_password_link, "alice")

    assert set_password(link).status_code == 204

    assert browser.get("me/").status_code == 401


@pytest.mark.django_db
def test_password_set_locks_the_account_row_cwe_362():
    _, link = as_command(services.create_user, "pete")
    payload = link_payload(link)

    with audit_source("command"), CaptureQueriesContext(connection) as queries:
        services.set_password_from_link(payload["uid"], payload["token"], NEW_PASSWORD)

    assert any("FOR UPDATE" in query["sql"] for query in queries.captured_queries)


@pytest.mark.django_db(transaction=True)
def test_concurrent_link_use_sets_one_password_cwe_362():
    _, link = as_command(services.create_user, "pete")
    payload = link_payload(link)
    start = threading.Barrier(2)
    outcomes = []

    def use(password):
        try:
            with audit_source("command"):
                start.wait()
                services.set_password_from_link(payload["uid"], payload["token"], password)
            outcomes.append("set")
        except services.InvalidLink:
            outcomes.append("invalid")
        finally:
            connection.close()

    threads = [threading.Thread(target=use, args=(f"concurrent-passphrase-{i}",)) for i in (1, 2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["invalid", "set"]


# --- Throttling ----------------------------------------------------------------------------------


def statuses(responses) -> list[int]:
    return [response.status_code for response in responses]


@pytest.mark.django_db
def test_login_is_throttled_per_ip_cwe_307():
    browser = Browser(address="203.0.113.50")

    responses = [browser.login(f"user{i}", WRONG_PASSWORD) for i in range(11)]

    assert statuses(responses) == [400] * 10 + [429]
    assert int(responses[-1].headers["Retry-After"]) > 0
    assert responses[-1].json()["error"]["code"] == "throttled"


@pytest.mark.django_db
@pytest.mark.parametrize("username", ["alice", "nobody"])
def test_login_is_throttled_per_username_cwe_307(username):
    User.objects.create_user(username="alice", password=PASSWORD)

    responses = [
        Browser(address=f"198.51.100.{i}").login(username, WRONG_PASSWORD) for i in range(11)
    ]

    # Unknown usernames are throttled exactly like existing ones (SEC-06).
    assert statuses(responses) == [400] * 10 + [429]


def test_username_throttle_is_temporary(alice):
    for i in range(10):
        Browser(address=f"198.51.100.{i}").login("alice", WRONG_PASSWORD)
    assert Browser(address="198.51.100.100").login().status_code == 429

    one_hour_later = time.time() + 60 * 60 + 1
    with mock.patch.object(SimpleRateThrottle, "timer", mock.Mock(return_value=one_hour_later)):
        assert Browser(address="198.51.100.101").login().status_code == 200


@pytest.mark.django_db
def test_login_throttle_ignores_spoofed_forwarded_for_cwe_348():
    responses = [
        Browser(forwarded_for=f"6.6.6.{i}, 203.0.113.60").login(f"user{i}", WRONG_PASSWORD)
        for i in range(11)
    ]

    assert statuses(responses)[-1] == 429


@pytest.mark.django_db
def test_invalid_client_addresses_share_one_throttle_bucket_cwe_348():
    responses = [
        Browser(forwarded_for=f"not-an-ip-{i}").login(f"user{i}", WRONG_PASSWORD) for i in range(11)
    ]

    assert statuses(responses) == [400] * 10 + [429]


@pytest.mark.django_db
def test_password_set_is_throttled_cwe_307():
    browser = Browser(address="203.0.113.70")
    payload = {"uid": "x", "token": "y", "new_password": NEW_PASSWORD}

    assert statuses(browser.post("password/set/", payload) for _ in range(11)) == [400] * 10 + [429]


def test_password_change_is_throttled_cwe_307(alice):
    browser = Browser()
    browser.login()

    responses = [change(browser, current=WRONG_PASSWORD) for _ in range(11)]

    assert statuses(responses) == [400] * 10 + [429]


def test_auth_throttles_fail_closed_when_cache_is_unavailable(alice):
    browser = Browser()
    browser.client.get(AUTH + "csrf/")
    unavailable = mock.Mock()
    unavailable.get.side_effect = RedisConnectionError("cache down")

    with mock.patch.object(SimpleRateThrottle, "cache", unavailable):
        response = browser.login()

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"
    assert "sessionid" not in browser.client.cookies
    assert not AuditEvent.objects.filter(action="accounts.login_succeeded").exists()


def test_throttled_login_is_not_audited(alice):
    browser = Browser(address="203.0.113.80")

    responses = [browser.login("alice", WRONG_PASSWORD) for _ in range(11)]

    assert statuses(responses)[-1] == 429
    assert AuditEvent.objects.filter(action="accounts.login_failed").count() == 10


# --- Audit events --------------------------------------------------------------------------------


def test_login_success_is_audited(alice):
    Browser(address="203.0.113.90").login()

    event = AuditEvent.objects.get(action="accounts.login_succeeded")
    assert (event.actor_type, event.actor_id, event.actor_label) == ("user", alice.pk, "alice")
    assert (event.resource_type, event.resource_id) == ("accounts.user", str(alice.pk))
    assert (event.source, event.client_ip, event.outcome) == ("http", "203.0.113.90", "success")
    assert (event.changes, event.metadata) == ({}, {})


@pytest.mark.django_db
def test_login_failure_is_audited_cwe_778():
    cases = failure_cases()
    for index, (username, password, _, _) in enumerate(cases):
        Browser(address=f"203.0.113.{30 + index}").login(username, password)

    events = AuditEvent.objects.filter(action="accounts.login_failed").order_by("id")
    assert [(e.actor_type, e.outcome, e.resource_id, e.metadata) for e in events] == [
        ("anonymous", "failure", resource_id, {"reason": reason})
        for _, _, resource_id, reason in cases
    ]


def test_logout_is_audited(alice):
    browser = Browser()
    browser.login()

    browser.post("logout/")

    event = AuditEvent.objects.get(action="accounts.logged_out")
    assert (event.actor_id, event.resource_id) == (alice.pk, str(alice.pk))


def test_password_change_is_audited(alice):
    browser = Browser()
    browser.login()

    change(browser)

    event = AuditEvent.objects.get(action="accounts.password_changed")
    assert (event.actor_id, event.metadata, event.changes) == (
        alice.pk,
        {"method": "self_service"},
        {},
    )


def test_password_change_failure_is_audited_cwe_778(alice):
    browser = Browser()
    browser.login()

    change(browser, current=WRONG_PASSWORD)

    event = AuditEvent.objects.get(action="accounts.password_change_failed")
    assert (event.actor_id, event.outcome, event.metadata) == (
        alice.pk,
        "failure",
        {"reason": "wrong_current"},
    )


@pytest.mark.django_db
def test_password_set_is_audited():
    pete, link = as_command(services.create_user, "pete")
    set_password(link)
    set_password(as_command(services.issue_password_link, "pete"), "a-second-passphrase-9")

    events = AuditEvent.objects.filter(action="accounts.password_set").order_by("id")
    assert [(e.actor_id, e.source, e.metadata) for e in events] == [
        (pete.pk, "http", {"method": "setup"}),
        (pete.pk, "http", {"method": "reset"}),
    ]


def test_password_set_failure_is_audited_cwe_778(alice):
    forged = link_payload(as_command(services.issue_password_link, "alice"))
    forged["token"] = "d0abcd-" + "0" * 32
    unknown = {**forged, "uid": urlsafe_base64_encode(str(uuid.uuid4()).encode())}
    Browser().post("password/set/", forged)
    Browser(address="203.0.113.13").post("password/set/", unknown)
    as_command(services.disable_user, "alice")
    Browser(address="203.0.113.14").post("password/set/", forged)

    events = AuditEvent.objects.filter(action="accounts.password_set_failed").order_by("id")
    assert [(e.actor_type, e.outcome, e.resource_id, e.metadata) for e in events] == [
        ("anonymous", "failure", str(alice.pk), {"reason": "invalid_link"}),
        ("anonymous", "failure", "", {"reason": "invalid_link"}),
        ("anonymous", "failure", str(alice.pk), {"reason": "disabled"}),
    ]
