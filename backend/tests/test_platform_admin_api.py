"""SPEC-0010 administration API: authority matrix, step-up, CSRF, schemas, disclosure, limits,
failure handling and functional flows over HTTP (TM-0010)."""

import json
import logging
import re
import threading
import time
import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

import psycopg.errors
import pytest
from django.core.cache import cache
from django.db import OperationalError, connection, transaction
from django.test.utils import CaptureQueriesContext
from django.urls import get_resolver
from django.utils import timezone
from redis.exceptions import ConnectionError as RedisConnectionError
from rest_framework.permissions import AllowAny
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle

from apps.accounts import services as accounts
from apps.accounts.models import User
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from apps.core.logging import JsonFormatter
from apps.rbac import administration, events, policy
from apps.rbac import services as rbac
from apps.rbac.catalog import SUPPORTED_PERMISSIONS
from apps.rbac.models import PlatformAccess, Role, RoleAssignment
from apps.teams import services as teams
from apps.teams.models import Membership, Team
from tests.platform_support import OPERATOR, PASSWORD, Browser, make_admin, make_user

pytestmark = pytest.mark.django_db
ADMIN = "/api/v1/admin/"
VIEW = "teams.view_team"


def operator(function, *args, **kwargs):
    with audit_source("command"):
        return function(OPERATOR, *args, **kwargs)


def active_team(code):
    team = operator(teams.create_team, code=code, name=code.title())
    revision = operator(teams.preview_team_activation, team.pk).revision
    return operator(teams.activate_team, team.pk, revision, code)


def build_world():
    w = SimpleNamespace()
    w.root = make_admin("root")
    w.deputy = make_admin("deputy")
    w.alpha, w.beta = active_team("alpha"), active_team("beta")
    w.dormant = operator(teams.create_team, code="dormant", name="Dormant")
    w.member = make_user("member")
    w.membership = operator(teams.add_member, w.alpha.pk, w.member.pk)
    w.role = operator(rbac.create_role, code="reader", name="Reader")
    operator(rbac.grant_permission, w.role.pk, VIEW)
    operator(rbac.assign_role, w.membership.pk, w.role.pk)
    w.spare = operator(rbac.create_role, code="spare", name="Spare")
    w.leaver = make_user("leaver")
    operator(teams.add_member, w.alpha.pk, w.leaver.pk)
    w.joiner = make_user("joiner")
    for name in ("t_update", "t_disable", "t_link", "t_position", "t_grant"):
        setattr(w, name, make_user(name.replace("_", "-")))
    w.disabled = make_user("off")
    operator(administration.disable_account, w.disabled.pk)
    w.revision = operator(teams.preview_team_activation, w.dormant.pk).revision
    return w


@pytest.fixture
def world():
    return build_world()


def reads(w):
    return [
        f"{ADMIN}users/",
        f"{ADMIN}users/{w.member.pk}/",
        f"{ADMIN}teams/",
        f"{ADMIN}teams/{w.alpha.pk}/",
        f"{ADMIN}teams/{w.dormant.pk}/activation-preview/",
        f"{ADMIN}teams/{w.alpha.pk}/members/",
        f"{ADMIN}roles/",
        f"{ADMIN}roles/{w.role.pk}/",
        f"{ADMIN}permissions/",
        f"{ADMIN}audit-events/",
    ]


def mutations(w):
    """(operation, method, path, body, success status) for every administrative mutation route."""
    user = f"{ADMIN}users/"
    team, role = f"{ADMIN}teams/", f"{ADMIN}roles/"
    membership = f"{ADMIN}memberships/{w.membership.pk}/roles/"
    return [
        ("create_account", "post", user, {"username": "newbie"}, 201),
        ("update_account", "patch", f"{user}{w.t_update.pk}/", {"first_name": "New"}, 200),
        ("disable_account", "post", f"{user}{w.t_disable.pk}/disable/", {}, 200),
        ("enable_account", "post", f"{user}{w.disabled.pk}/enable/", {}, 200),
        ("issue_password_link", "post", f"{user}{w.t_link.pk}/password-link/", {}, 200),
        (
            "set_position",
            "post",
            f"{user}{w.t_position.pk}/position/",
            {"position": "analyst"},
            200,
        ),
        ("grant_admin", "post", f"{user}{w.t_grant.pk}/grant-admin/", {}, 200),
        ("revoke_admin", "post", f"{user}{w.deputy.pk}/revoke-admin/", {}, 200),
        ("create_team", "post", team, {"code": "gamma", "name": "Gamma"}, 201),
        ("update_team", "patch", f"{team}{w.alpha.pk}/", {"name": "Alpha Renamed"}, 200),
        ("deactivate_team", "post", f"{team}{w.beta.pk}/deactivate/", {}, 200),
        (
            "activate_team",
            "post",
            f"{team}{w.dormant.pk}/activate/",
            {"revision": w.revision, "confirmation_code": "dormant"},
            200,
        ),
        ("add_member", "post", f"{team}{w.alpha.pk}/members/", {"user_id": str(w.joiner.pk)}, 201),
        ("remove_member", "post", f"{team}{w.alpha.pk}/members/{w.leaver.pk}/remove/", {}, 204),
        ("assign_role", "post", membership, {"role_id": str(w.spare.pk)}, 201),
        ("revoke_role", "post", f"{membership}{w.role.pk}/revoke/", {}, 200),
        ("create_role", "post", role, {"code": "auditor", "name": "Auditor"}, 201),
        ("update_role", "patch", f"{role}{w.role.pk}/", {"name": "Readers"}, 200),
        (
            "grant_permission",
            "post",
            f"{role}{w.spare.pk}/grant-permission/",
            {"permission": VIEW},
            200,
        ),
        (
            "revoke_permission",
            "post",
            f"{role}{w.role.pk}/revoke-permission/",
            {"permission": VIEW},
            200,
        ),
    ]


def state():
    models = (Team, Membership, Role, RoleAssignment, Role.permissions.through, PlatformAccess)
    rows = [list(model.objects.order_by("pk").values()) for model in models]
    rows.append(list(User.objects.order_by("pk").values()))
    return rows


def success_events():
    return AuditEvent.objects.filter(outcome="success").count()


def formatted(caplog):
    formatter = JsonFormatter()
    return "\n".join(formatter.format(record) for record in caplog.records)


def age_proof(browser, seconds):
    session = browser.client.session
    proof = dict(session[accounts.STEP_UP_SESSION_KEY])
    proof["verified_at"] -= seconds
    session[accounts.STEP_UP_SESSION_KEY] = proof
    session.save()


def login_as(user, *, step_up=True):
    browser = Browser().login(user.username)
    if step_up:
        assert browser.reauthenticate().status_code == 204
    return browser


def body_of(response):
    error = dict(response.json()["error"])
    error.pop("request_id", None)
    return error


# SEC-01 — enabled session required everywhere (T-01, CWE-862)


def test_admin_routes_require_active_session_cwe_862(world):
    anonymous = APIClient()
    root = login_as(world.root)
    before, events_before = state(), AuditEvent.objects.count()
    for path in reads(world):
        assert anonymous.get(path).status_code == 401, path
    for _, method, path, body, _ in mutations(world):
        response = getattr(anonymous, method)(path, body, format="json")
        assert response.status_code == 401, path
        assert response.json()["error"]["code"] == "not_authenticated"
    # The old cookie of a now-disabled account.
    User.objects.filter(pk=world.root.pk).update(is_active=False)
    for path in reads(world):
        assert root.get(path).status_code == 401, path
    for _, method, path, body, _ in mutations(world):
        assert root.send(method, path, body).status_code == 401, path
    User.objects.filter(pk=world.root.pk).update(is_active=True)
    assert state() == before and AuditEvent.objects.count() == events_before


# SEC-02 — non-Admins are denied every administrative operation (T-02, CWE-862)


def _actors(w):
    plain = make_user("plain")
    analyst, engineer = make_user("analyst"), make_user("engineer")
    operator(administration.set_position, analyst.pk, "analyst")
    operator(administration.set_position, engineer.pk, "engineer")
    insider = make_user("insider")  # every team grant in a team, still not an Admin
    membership = operator(teams.add_member, w.alpha.pk, insider.pk)
    everything = operator(rbac.create_role, code="everything", name="Everything")
    for code in SUPPORTED_PERMISSIONS:
        operator(rbac.grant_permission, everything.pk, code)
    operator(rbac.assign_role, membership.pk, everything.pk)
    revoked = make_admin("revoked")
    operator(administration.revoke_admin, revoked.pk)
    return {
        "no_position": plain,
        "analyst": analyst,
        "engineer": engineer,
        "cross_team_all_grants": insider,
        "partial_grant": w.member,
        "revoked_admin": revoked,
    }


def test_non_admin_users_cannot_administer_cwe_862(world, caplog):
    for label, actor in _actors(world).items():
        browser = login_as(actor)  # a fresh step-up proof: the denial is about authority
        before, successes = state(), success_events()
        denials = AuditEvent.objects.filter(action="rbac.administration_denied").count()
        with caplog.at_level(logging.WARNING, logger="apps.rbac"):
            for path in reads(world):
                response = browser.get(path)
                assert response.status_code == 403, (label, path)
                assert response.json()["error"]["code"] == "permission_denied"
            for operation, method, path, body, _ in mutations(world):
                response = browser.send(method, path, body)
                assert response.status_code == 403, (label, operation)
                assert response.json()["error"]["code"] == "permission_denied"
        assert state() == before, label
        assert success_events() == successes, label
        recorded = AuditEvent.objects.filter(action="rbac.administration_denied").order_by("id")
        new = list(recorded[denials:])
        assert [e.metadata["operation"] for e in new] == [m[0] for m in mutations(world)], label
        assert {(e.actor_id, e.outcome) for e in new} == {(actor.pk, "denied")}
        read_denials = [
            r
            for r in caplog.records
            if r.getMessage() == "authorization_denied" and r.actor_id == str(actor.pk)
        ]
        assert len(read_denials) >= len(reads(world)), label
        caplog.clear()


# SEC-04 over HTTP — a revoked Admin is denied on the next request without being logged out


def test_revoked_admin_is_denied_on_the_next_request(world):
    deputy = login_as(world.deputy)
    assert deputy.get(f"{ADMIN}users/").status_code == 200
    operator(administration.revoke_admin, world.deputy.pk)
    assert deputy.get(f"{ADMIN}users/").status_code == 403
    assert deputy.post(f"{ADMIN}teams/", {"code": "late", "name": "Late"}).status_code == 403
    assert deputy.get("/api/v1/auth/me/").status_code == 200  # the session itself continues
    assert deputy.get("/api/v1/rbac/me/platform/").json()["is_admin"] is False


# SEC-05 — HTTP can never obtain operator authority or a step-up exemption (CWE-863)


def test_http_cannot_obtain_operator_authority_cwe_863(world):
    root = login_as(world.root, step_up=False)
    before = state()
    forged = {
        "HTTP_X_TRILHA_OPERATOR": "true",
        "HTTP_X_AUDIT_SOURCE": "command",
        "HTTP_X_REAUTHENTICATED_AT": str(time.time()),
        "HTTP_X_FORWARDED_USER": "trilha-operator",
    }
    for operation, method, path, body, _ in mutations(world):
        response = root.send(method, path, body, **forged)
        assert response.status_code == 403, operation
        assert response.json()["error"]["code"] == "reauthentication_required", operation
        for extra in ({"operator": True}, {"principal": "trilha-operator"}):
            assert root.send(method, path, {**body, **extra}).status_code == 400, operation
    assert state() == before
    plain = login_as(make_user("plain"))
    response = plain.post(f"{ADMIN}teams/", {"code": "x", "name": "X"}, HTTP_X_TRILHA_OPERATOR="1")
    assert response.status_code == 403
    for module in ("apps/rbac/admin_views.py", "apps/rbac/views.py", "apps/accounts/views.py"):
        with open(module, encoding="utf-8") as source:
            assert "infrastructure_operator" not in source.read(), module


# SEC-09 — every mutating route needs a fresh step-up; reads do not (T-09, CWE-306)


def test_sensitive_admin_operations_require_recent_reauthentication_cwe_306(world, caplog):
    root = login_as(world.root, step_up=False)
    for path in reads(world):
        assert root.get(path).status_code == 200, path
    before = state()
    with caplog.at_level(logging.WARNING, logger="apps.rbac"):
        for operation, method, path, body, _ in mutations(world):
            response = root.send(method, path, body)
            assert response.status_code == 403, operation
            assert body_of(response) == {
                "code": "reauthentication_required",
                "message": "Confirm your password to continue.",
            }
    assert state() == before
    assert not AuditEvent.objects.filter(action="rbac.administration_denied").exists()
    required = {
        r.operation for r in caplog.records if r.getMessage() == "reauthentication_required"
    }
    assert required == {m[0] for m in mutations(world)}
    assert root.reauthenticate().status_code == 204
    age_proof(root, 601)
    for operation, method, path, body, _ in mutations(world):
        assert root.send(method, path, body).status_code == 403, operation
    assert state() == before
    assert root.reauthenticate().status_code == 204
    for operation, method, path, body, status in mutations(world):
        response = root.send(method, path, body)
        assert response.status_code == status, (operation, response.content)


# SEC-10 — the proof is server-side, bound to the session user, and expires (T-10, CWE-287)


def test_step_up_proof_is_server_side_bound_and_expires_cwe_287(world, monkeypatch):
    path, body = f"{ADMIN}teams/", {"code": "gamma", "name": "Gamma"}
    root = login_as(world.root, step_up=False)
    # Client-supplied timestamps never count, in a header, the query string or the body.
    assert root.post(path, body, HTTP_X_REAUTHENTICATED_AT=str(time.time())).status_code == 403
    assert root.post(f"{path}?reauthenticated_at={time.time()}", body).status_code == 403
    assert root.post(path, {**body, "reauthenticated_at": time.time()}).status_code == 400
    # A proof recorded for another user is ignored, even inside this user's session.
    session = root.client.session
    session[accounts.STEP_UP_SESSION_KEY] = {
        "user_id": str(world.deputy.pk),
        "verified_at": time.time(),
    }
    session.save()
    assert root.post(path, body).status_code == 403
    for forged in (
        {"user_id": str(world.root.pk), "verified_at": str(time.time())},
        {"user_id": str(world.root.pk), "verified_at": True},
        "not-a-mapping",
    ):
        session[accounts.STEP_UP_SESSION_KEY] = forged
        session.save()
        assert root.post(path, body).status_code == 403, forged
    # A genuine proof works until the server clock passes 600 s.
    assert root.reauthenticate().status_code == 204
    issued = root.session_data()[accounts.STEP_UP_SESSION_KEY]["verified_at"]
    monkeypatch.setattr(policy.time, "time", lambda: issued + 601)
    assert root.post(path, body).status_code == 403
    monkeypatch.setattr(policy.time, "time", lambda: issued + 599)
    assert root.post(path, body).status_code == 201
    # Another browser of the same user has its own session and no proof.
    other = Browser(address="203.0.113.77").login("root")
    assert other.post(path, {"code": "delta", "name": "Delta"}).status_code == 403
    assert not Team.objects.filter(code="delta").exists()


# SEC-13 — CSRF on every mutation and on re-authentication (T-13, CWE-352)


def test_admin_mutations_and_reauthentication_require_csrf_cwe_352(world):
    root = login_as(world.root)
    before, count = state(), AuditEvent.objects.count()
    for operation, method, path, body, _ in mutations(world):
        response = root.send(method, path, body, csrf=False)
        assert response.status_code == 403, operation
        assert "CSRF" in response.json()["error"]["message"], operation
    key = root.session_key
    response = root.post("/api/v1/auth/reauthenticate/", {"password": PASSWORD}, csrf=False)
    assert response.status_code == 403 and root.session_key == key
    assert state() == before and AuditEvent.objects.count() == count


# SEC-14 — only listed keys with strict types; no PUT/DELETE/bulk (T-14, CWE-915)


PRIVILEGED = {
    "is_admin": True,
    "position": "engineer",
    "is_active": False,
    "password": "x",
    "username": "renamed",
    "is_staff": True,
    "is_superuser": True,
    "permissions": [VIEW],
    "groups": [1],
}


@mock.patch.dict(SimpleRateThrottle.THROTTLE_RATES, {"admin_write": "10000/min"})
def test_admin_payloads_reject_privileged_and_unknown_fields_cwe_915(world):
    root = login_as(world.root)
    before = state()
    for operation, method, path, body, _ in mutations(world):
        for key, value in PRIVILEGED.items():
            if key in body:
                continue
            response = root.send(method, path, {**body, key: value})
            assert response.status_code == 400, (operation, key)
        for key in body:
            for wrong in (1, True, ["x"], {"x": 1}):
                if key == "position" and wrong is None:
                    continue
                response = root.send(method, path, {**body, key: wrong})
                assert response.status_code == 400, (operation, key, wrong)
        duplicated = (
            '{"x": 1, "x": 2}' if not body else json.dumps(body)[:-1] + ", " + json.dumps(body)[1:]
        )
        assert root.send(method, path, raw=duplicated).status_code == 400, operation
        assert root.send(method, path, raw="[]").status_code == 400, operation
        for verb in ("put", "delete"):
            assert root.send(verb, path, body).status_code == 405, (operation, verb)
    assert root.patch(f"{ADMIN}users/{world.t_update.pk}/", {}).status_code == 400
    assert state() == before


# SEC-15 — password links appear once, never in logs, audit, caches or other responses (CWE-532)


def test_password_links_absent_from_logs_audit_and_cache_cwe_532(world, caplog):
    root = login_as(world.root)
    with caplog.at_level(logging.DEBUG):
        created = root.post(f"{ADMIN}users/", {"username": "newbie"})
        enabled = root.post(f"{ADMIN}users/{world.disabled.pk}/enable/")
        issued = root.post(f"{ADMIN}users/{world.t_link.pk}/password-link/")
        detail = root.get(f"{ADMIN}users/{world.t_link.pk}/")
        listing = root.get(f"{ADMIN}users/")
    links = [
        created.json()["password_link"]["url"],
        enabled.json()["password_link"]["url"],
        issued.json()["url"],
    ]
    for response in (created, enabled, issued):
        assert response["Cache-Control"] == "no-store"
    assert issued.json() == {"url": links[2], "expires_in_seconds": 3600}
    tokens = [link.split("token=", 1)[1] for link in links] + [
        link.split("#", 1)[1] for link in links
    ]
    stored = json.dumps(list(AuditEvent.objects.values()), default=str)
    logged = formatted(caplog)
    for secret in tokens:
        assert secret not in stored and secret not in logged
        assert secret not in detail.content.decode() and secret not in listing.content.decode()
    assert all("/set-password#uid=" in link for link in links)


# SEC-16 — disable and Admin-issued links end the target's sessions (T-16, CWE-613)


def test_admin_account_changes_end_target_sessions_cwe_613(world):
    root = login_as(world.root)
    target = make_user("victim")
    first, second = Browser().login("victim"), Browser(address="203.0.113.50").login("victim")
    assert root.post(f"{ADMIN}users/{target.pk}/disable/").status_code == 200
    for browser in (first, second):
        assert browser.get("/api/v1/auth/me/").status_code == 401
    enabled = root.post(f"{ADMIN}users/{target.pk}/enable/").json()
    fragment = dict(
        p.split("=", 1) for p in enabled["password_link"]["url"].split("#")[1].split("&")
    )
    set_response = Browser(address="203.0.113.60").post(
        "/api/v1/auth/password/set/", {**fragment, "new_password": "Brand-New-Passphrase-77"}
    )
    assert set_response.status_code == 204
    signed_in = Browser().login("victim", "Brand-New-Passphrase-77")
    link = root.post(f"{ADMIN}users/{target.pk}/password-link/").json()["url"]
    fragment = dict(p.split("=", 1) for p in link.split("#")[1].split("&"))
    reset = Browser(address="203.0.113.61").post(
        "/api/v1/auth/password/set/", {**fragment, "new_password": "Another-New-Passphrase-88"}
    )
    assert reset.status_code == 204
    assert signed_in.get("/api/v1/auth/me/").status_code == 401


# SEC-19 / SEC-20 — directory and audit trail are Admin-only, before any lookup (CWE-200)


def test_admin_directory_is_admin_only_cwe_200(world, caplog):
    plain = login_as(make_user("plain"))
    pairs = [
        (f"{ADMIN}users/{world.member.pk}/", f"{ADMIN}users/{uuid.uuid4()}/"),
        (f"{ADMIN}teams/{world.alpha.pk}/", f"{ADMIN}teams/{uuid.uuid4()}/"),
        (f"{ADMIN}teams/{world.alpha.pk}/members/", f"{ADMIN}teams/{uuid.uuid4()}/members/"),
        (f"{ADMIN}roles/{world.role.pk}/", f"{ADMIN}roles/{uuid.uuid4()}/"),
        (
            f"{ADMIN}teams/{world.dormant.pk}/activation-preview/",
            f"{ADMIN}teams/{uuid.uuid4()}/activation-preview/",
        ),
    ]
    with caplog.at_level(logging.WARNING, logger="apps.rbac"):
        for existing, missing in pairs:
            first, second = plain.get(existing), plain.get(missing)
            assert first.status_code == second.status_code == 403, existing
            assert body_of(first) == body_of(second)
    denials = [r for r in caplog.records if r.getMessage() == "authorization_denied"]
    assert len(denials) == 2 * len(pairs)  # the view permission logs each one before any lookup
    root = login_as(world.root, step_up=False)
    for _, missing in pairs:
        assert root.get(missing).status_code == 404, missing


def test_audit_search_is_admin_only_cwe_200(world):
    url = f"{ADMIN}audit-events/"
    assert APIClient().get(url).status_code == 401
    assert login_as(world.member).get(url).status_code == 403
    assert login_as(world.root, step_up=False).get(url).status_code == 200
    routes = [str(p.pattern) for p in get_resolver().url_patterns]
    assert not [r for r in routes if "audit" in r and not r.startswith("api/v1/admin/")]


# SEC-21 — fixed, typed filter allowlists (T-21, CWE-943)


def test_admin_filters_are_allowlisted_cwe_943(world):
    root = login_as(world.root, step_up=False)
    bad = {
        "users/": [
            {"username__startswith": "r"},
            {"is_admin": "yes"},
            {"position": "admin"},
            {"q": "x" * 101},
            {"q": "a‮b"},
            {"ordering": "-username"},
        ],
        "teams/": [{"is_active": "1"}, {"code__in": "a,b"}, {"q": ""}],
        "roles/": [{"permissions__codename": "view_team"}],
        "audit-events/": [
            {"action": "rbac.*"},
            {"action": "x" * 101},
            {"actor_id": "not-a-uuid"},
            {"resource_type": "AuditEvent"},
            {"resource_id": "a b"},
            {"outcome": "maybe"},
            {"source": "browser"},
            {"occurred_after": "2026-10-01"},
            {"occurred_after": "yesterday"},
            {"changes__password": "x"},
            {"metadata": "{}"},
        ],
        "permissions/": [{"code": VIEW}],
    }
    for route, cases in bad.items():
        for params in cases:
            assert root.get(ADMIN + route, params).status_code == 400, (route, params)
        assert root.get(f"{ADMIN}{route}?page=1&page=2").status_code == 400, route
    assert root.get(f"{ADMIN}users/?q=a&q=b").status_code == 400
    found = root.get(f"{ADMIN}users/", {"q": "ROOT"}).json()
    assert [row["username"] for row in found["results"]] == ["root"]
    assert root.get(f"{ADMIN}users/", {"position": "none", "is_admin": "true"}).json()["count"] == 2


# SEC-22 — bounded pages, ranges, queries and writes (T-22, CWE-770)


def test_admin_lists_and_writes_are_bounded_cwe_770(world):
    root = login_as(world.root)
    # Unusable passwords: no hashing cost, and none of these accounts can sign in.
    User.objects.bulk_create(User(username=f"bulk-{i:03d}", password="!") for i in range(120))
    page = root.get(f"{ADMIN}users/", {"page_size": "1000"}).json()
    assert page["count"] > 100 and len(page["results"]) == 100
    assert len(root.get(f"{ADMIN}users/", {"page_size": "5"}).json()["results"]) == 5
    old = timezone.now() - timedelta(days=45)
    with transaction.atomic():
        AuditEvent.objects.create(
            occurred_at=old,
            actor_type="system",
            actor_label="seed",
            action="seed.old",
            source="command",
        )
    recent = root.get(f"{ADMIN}audit-events/", {"action": "seed.old"}).json()
    assert recent["count"] == 0  # the default range is the last 30 days
    after = (old - timedelta(days=1)).isoformat()
    assert (
        root.get(f"{ADMIN}audit-events/", {"action": "seed.old", "occurred_after": after}).json()[
            "count"
        ]
        == 1
    )
    too_long = {"occurred_after": (old - timedelta(days=400)).isoformat()}
    assert root.get(f"{ADMIN}audit-events/", too_long).status_code == 400
    reversed_range = {
        "occurred_after": timezone.now().isoformat(),
        "occurred_before": old.isoformat(),
    }
    assert root.get(f"{ADMIN}audit-events/", reversed_range).status_code == 400
    for route in (
        "users/",
        "teams/",
        "roles/",
        f"teams/{world.alpha.pk}/members/",
        "audit-events/",
    ):
        counts = []
        for size in ("1", "25"):
            with CaptureQueriesContext(connection) as queries:
                assert root.get(ADMIN + route, {"page_size": size}).status_code == 200
            counts.append(len(queries))
        assert counts[0] == counts[1], (route, counts)
    statuses = [
        root.patch(f"{ADMIN}users/{world.t_update.pk}/", {"first_name": f"N{i}"}).status_code
        for i in range(61)
    ]
    assert statuses == [200] * 60 + [429]
    assert root.get(f"{ADMIN}users/").status_code == 200  # reads keep working


# SEC-25 — exact allowlists; no secret in audit or logs (T-25, CWE-532)


def test_admin_audit_allowlists_and_secret_canaries_cwe_532(world, caplog):
    root = login_as(world.root)
    canary_name = "Canary-Name-5521"
    with caplog.at_level(logging.DEBUG):
        created = root.post(f"{ADMIN}users/", {"username": "canary", "first_name": canary_name})
        user_id = created.json()["user"]["id"]
        root.patch(f"{ADMIN}users/{user_id}/", {"email": "canary@example.com"})
        root.post(f"{ADMIN}users/{user_id}/position/", {"position": "engineer"})
        root.post(f"{ADMIN}users/{user_id}/grant-admin/")
        root.post(f"{ADMIN}users/{user_id}/revoke-admin/")
        preview = root.get(f"{ADMIN}teams/{world.dormant.pk}/activation-preview/").json()
        root.post(
            f"{ADMIN}teams/{world.dormant.pk}/activate/",
            {"revision": preview["revision"], "confirmation_code": "dormant"},
        )
        root.post(f"{ADMIN}users/{user_id}/disable/")
        link = root.post(f"{ADMIN}users/{user_id}/enable/").json()["password_link"]["url"]
        root.reauthenticate("Wrong-Canary-Passphrase-1")
    secrets = [
        PASSWORD,
        "Wrong-Canary-Passphrase-1",
        link.split("#", 1)[1],
        preview["revision"],
        root.session_key,
        root.client.cookies["csrftoken"].value,
    ]
    stored = json.dumps(list(AuditEvent.objects.values()), default=str)
    logged = formatted(caplog)
    for secret in secrets:
        assert secret not in stored, secret[:6]
        assert secret not in logged, secret[:6]
    assert canary_name not in logged and "canary@example.com" not in logged
    activated = AuditEvent.objects.get(
        action="teams.team_activated", resource_id=str(world.dormant.pk)
    )
    assert set(activated.metadata) == {"membership_count", "role_assignment_count"}
    assert "dormant" not in json.dumps(activated.metadata)
    for event in AuditEvent.objects.filter(source="http", outcome="success").exclude(
        action__startswith="accounts.log"
    ):
        assert event.actor_id == world.root.pk and event.client_ip is not None, event.action


# SEC-26 (backend half) — untrusted text is returned as data, never interpreted


def test_admin_responses_return_markup_as_plain_data(world):
    root = login_as(world.root)
    markup = "<img src=x onerror=alert(1)>"
    created = root.post(f"{ADMIN}users/", {"username": "markup", "last_name": markup})
    assert created.status_code == 201 and created.json()["user"]["last_name"] == markup
    assert created["Content-Type"].startswith("application/json")
    team = root.post(f"{ADMIN}teams/", {"code": "markup", "name": markup}).json()
    assert team["name"] == markup


# SEC-27 — HTTP activation needs the current digest and the exact code (T-27, CWE-367)


def test_http_team_activation_requires_current_revision_and_code_cwe_367(world):
    root = login_as(world.root)
    url = f"{ADMIN}teams/{world.dormant.pk}/"
    user = make_user("dormant-member")
    first = operator(teams.add_member, world.dormant.pk, user.pk)
    preview = root.get(f"{url}activation-preview/").json()
    assert preview["membership_count"] == 1 and re.fullmatch(r"[0-9a-f]{64}", preview["revision"])
    assert preview["team"]["code"] == "dormant" and preview["team"]["is_active"] is False
    # A same-count replacement after the preview still invalidates it.
    operator(teams.remove_member, world.dormant.pk, user.pk)
    operator(teams.add_member, world.dormant.pk, make_user("replacement").pk)
    assert Membership.objects.filter(team=world.dormant).count() == 1 and first
    for body, status in (
        ({"revision": preview["revision"], "confirmation_code": "dormant"}, 409),
        ({"revision": "f" * 64, "confirmation_code": "dormant"}, 409),
        ({"revision": "F" * 64, "confirmation_code": "dormant"}, 400),
        ({"revision": "short", "confirmation_code": "dormant"}, 400),
        ({"revision": preview["revision"]}, 400),
    ):
        assert root.post(f"{url}activate/", body).status_code == status, body
    current = root.get(f"{url}activation-preview/").json()["revision"]
    wrong_code = root.post(f"{url}activate/", {"revision": current, "confirmation_code": "DORMANT"})
    assert wrong_code.status_code == 409
    assert not Team.objects.get(pk=world.dormant.pk).is_active
    done = root.post(f"{url}activate/", {"revision": current, "confirmation_code": "dormant"})
    assert done.status_code == 200 and done.json()["is_active"] is True
    assert root.get(f"{url}activation-preview/").status_code == 409


# SEC-28 — lock timeouts and deadlocks answer 503 with nothing written (T-28, CWE-833)


@pytest.mark.django_db(transaction=True)
def test_admin_lock_timeout_and_deadlock_fail_closed_cwe_833(monkeypatch, caplog):
    w = build_world()
    root = login_as(w.root)
    monkeypatch.setattr(policy, "ADMIN_LOCK_TIMEOUT", "300ms")
    held, release = threading.Event(), threading.Event()

    def hold():
        try:
            with transaction.atomic():
                list(PlatformAccess.objects.select_for_update().values_list("pk", flat=True))
                held.set()
                assert release.wait(10)
        finally:
            connection.close()

    holder = threading.Thread(target=hold)
    holder.start()
    try:
        assert held.wait(10)
        started = time.monotonic()
        response = root.post(f"{ADMIN}teams/", {"code": "gamma", "name": "Gamma"})
        elapsed = time.monotonic() - started
    finally:
        release.set()
        holder.join(10)
    assert response.status_code == 503 and elapsed < 3
    assert body_of(response)["code"] == "service_unavailable"
    assert not Team.objects.filter(code="gamma").exists()
    assert any(getattr(r, "reason", None) == "lock_timeout" for r in caplog.records)
    assert "rbac_platformaccess" not in formatted(caplog)

    def deadlock(*args, **kwargs):
        try:
            raise psycopg.errors.DeadlockDetected("deadlock detected")
        except psycopg.errors.DeadlockDetected as exc:
            raise OperationalError("deadlock detected") from exc

    with mock.patch.object(policy, "bound_lock_waits", deadlock):
        response = root.post(f"{ADMIN}teams/", {"code": "gamma", "name": "Gamma"})
    assert response.status_code == 503
    assert any(getattr(r, "reason", None) == "deadlock" for r in caplog.records)
    assert not Team.objects.filter(code="gamma").exists()


# SEC-29 — dependency failures deny (T-29, CWE-636)


def test_admin_dependency_failures_fail_closed_cwe_636(world, monkeypatch):
    root = login_as(world.root)
    before = state()
    unavailable = mock.Mock()
    unavailable.get.side_effect = RedisConnectionError("cache down")
    with mock.patch.object(SimpleRateThrottle, "cache", unavailable):
        assert root.post(f"{ADMIN}teams/", {"code": "gamma", "name": "Gamma"}).status_code == 503
        assert root.reauthenticate().status_code == 503
    with mock.patch.object(policy, "is_platform_admin", side_effect=OperationalError("db canary")):
        response = root.post(f"{ADMIN}teams/", {"code": "gamma", "name": "Gamma"})
    assert response.status_code == 503 and "db canary" not in response.content.decode()
    real = events.record_event

    def broken(**kwargs):
        real(**kwargs)
        raise RuntimeError("audit canary")

    monkeypatch.setattr(events, "record_event", broken)
    response = root.post(f"{ADMIN}teams/", {"code": "gamma", "name": "Gamma"})
    assert response.status_code == 500 and "audit canary" not in response.content.decode()
    monkeypatch.undo()
    assert state() == before


# SEC-30 — fixed messages only (T-30, CWE-209)


def test_admin_error_responses_use_fixed_messages_cwe_209(world):
    root = login_as(world.root)
    duplicate = root.post(f"{ADMIN}teams/", {"code": "alpha", "name": "Again"})
    assert duplicate.status_code == 409
    assert body_of(duplicate) == {
        "code": "conflict",
        "message": "The request conflicts with the current state.",
    }
    responses = [
        duplicate,
        root.post(f"{ADMIN}roles/", {"code": "reader", "name": "Again"}),
        root.post(f"{ADMIN}users/", {"username": "root"}),
        root.post(f"{ADMIN}users/{world.root.pk}/revoke-admin/"),
        root.post(f"{ADMIN}users/{world.root.pk}/disable/"),
        root.post(f"{ADMIN}users/{world.t_grant.pk}/revoke-admin/"),
        root.post(f"{ADMIN}teams/{world.dormant.pk}/deactivate/"),
    ]
    assert [r.status_code for r in responses] == [409] * len(responses)
    for response in responses:
        text = response.content.decode()
        for leak in ("SELECT", "constraint", "unique", "Traceback", "psycopg", "rbac_", "teams_"):
            assert leak not in text, (leak, text)
    assert body_of(responses[3])["message"] == "You cannot revoke your own Admin grant."
    assert body_of(responses[4])["message"] == "You cannot disable your own account."


# SEC-31 — logs carry IDs and enums only (T-31, CWE-117)


def test_admin_logs_contain_structured_ids_only_cwe_117(world, caplog):
    root = login_as(world.root)
    plain = login_as(make_user("plain"))
    injected = 'Line\\n{"level": "CRITICAL", "message": "forged"}'
    with caplog.at_level(logging.DEBUG):
        root.post(f"{ADMIN}users/", {"username": "logtarget", "first_name": injected})
        root.get(f"{ADMIN}users/", {"q": "secret-search-value"})
        root.get(f"{ADMIN}audit-events/", {"resource_id": "secret-resource-value"})
        root.post(f"{ADMIN}users/{world.root.pk}/disable/")
        plain.get(f"{ADMIN}users/")
        plain.post(f"{ADMIN}teams/", {"code": "x", "name": "X"})
    logged = formatted(caplog)
    for value in ("logtarget", injected, "forged", "secret-search-value", "secret-resource-value"):
        assert value not in logged, value
    read = [r for r in caplog.records if r.getMessage() == "audit_trail_read"]
    assert read and read[0].filters == ["resource_id"]
    refused = [r for r in caplog.records if r.getMessage() == "administration_refused"]
    assert refused and refused[0].reason == "self_target"
    for line in logged.splitlines():
        json.loads(line)  # one structured record per line


# SEC-33 — no default Admin, no bootstrap route (T-33, CWE-1188)


def test_no_default_admin_or_bootstrap_route_cwe_1188():
    assert not PlatformAccess.objects.exists() and not User.objects.exists()
    for pattern in _all_routes(get_resolver().url_patterns, ""):
        route, callback = pattern
        view = getattr(callback, "cls", None) or getattr(callback, "view_class", None)
        if route.startswith("api/v1/admin/"):
            assert view is not None
            assert AllowAny not in getattr(view, "permission_classes", ()), route
    anonymous = APIClient()
    for path in (f"{ADMIN}users/", f"{ADMIN}setup/", "/api/v1/setup/", "/api/v1/auth/register/"):
        assert anonymous.post(path, {"username": "evil"}, format="json").status_code in {
            401,
            403,
            404,
        }
    assert not User.objects.exists() and not PlatformAccess.objects.exists()


def _all_routes(patterns, prefix):
    for pattern in patterns:
        if hasattr(pattern, "url_patterns"):
            yield from _all_routes(pattern.url_patterns, prefix + str(pattern.pattern))
        else:
            yield prefix + str(pattern.pattern), pattern.callback


# Functional flows (AC-F2..AC-F5)


def test_admin_manages_accounts_end_to_end(world):
    root = login_as(world.root)
    created = root.post(
        f"{ADMIN}users/",
        {"username": "carol", "first_name": "Carol", "last_name": "Doe", "email": "c@example.com"},
    )
    assert created.status_code == 201
    user = created.json()["user"]
    assert user["password_set"] is False and user["is_active"] is True
    assert user["is_admin"] is False and user["position"] is None
    url = f"{ADMIN}users/{user['id']}/"
    updated = root.patch(url, {"last_name": "Smith"}).json()
    assert updated["last_name"] == "Smith" and updated["first_name"] == "Carol"
    assert root.patch(url, {"last_name": "Smith"}).status_code == 200  # no-op: 200, no event
    assert AuditEvent.objects.filter(action="accounts.user_updated").count() == 1
    assert root.post(f"{url}disable/").json()["is_active"] is False
    assert root.post(f"{url}disable/").status_code == 409
    enabled = root.post(f"{url}enable/").json()
    assert (
        enabled["user"]["is_active"] is True and "/set-password#" in enabled["password_link"]["url"]
    )
    assert root.post(f"{url}password-link/").status_code == 200
    detail = root.get(url).json()
    assert detail["memberships"] == []


def test_admin_manages_teams_members_roles_over_http(world):
    root = login_as(world.root)
    team = root.post(f"{ADMIN}teams/", {"code": "hdbr-soc", "name": "HDBR SOC"}).json()
    assert team == {**team, "is_active": False, "member_count": 0}
    turl = f"{ADMIN}teams/{team['id']}/"
    analyst = make_user("ana")
    member = root.post(f"{turl}members/", {"user_id": str(analyst.pk)})
    assert member.status_code == 201
    membership_id = member.json()["membership_id"]
    role = root.post(f"{ADMIN}roles/", {"code": "soc-reader", "name": "SOC Reader"}).json()
    granted = root.post(f"{ADMIN}roles/{role['id']}/grant-permission/", {"permission": VIEW})
    assert granted.json()["permissions"] == [VIEW]
    assigned = root.post(f"{ADMIN}memberships/{membership_id}/roles/", {"role_id": role["id"]})
    assert assigned.status_code == 201 and assigned.json()["roles"][0]["code"] == "soc-reader"
    preview = root.get(f"{turl}activation-preview/").json()
    assert (preview["membership_count"], preview["role_assignment_count"]) == (1, 1)
    activated = root.post(
        f"{turl}activate/", {"revision": preview["revision"], "confirmation_code": "hdbr-soc"}
    )
    assert activated.json()["is_active"] is True
    own = Browser(address="203.0.113.90").login("ana").get("/api/v1/rbac/me/").json()
    assert own["results"][0]["team"]["code"] == "hdbr-soc" and own["results"][0]["permissions"] == [
        VIEW
    ]
    roster = root.get(f"{turl}members/").json()["results"]
    assert [row["user"]["username"] for row in roster] == ["ana"]
    revoked = root.post(f"{ADMIN}memberships/{membership_id}/roles/{role['id']}/revoke/")
    assert revoked.json()["roles"] == []
    assert root.post(f"{turl}members/{analyst.pk}/remove/").status_code == 204
    assert root.post(f"{turl}deactivate/").json()["is_active"] is False
    assert root.patch(turl, {"name": "HDBR SOC Team"}).json()["name"] == "HDBR SOC Team"
    assert (
        root.patch(f"{ADMIN}roles/{role['id']}/", {"name": "Readers"}).json()["name"] == "Readers"
    )
    missing = root.post(f"{ADMIN}memberships/{uuid.uuid4()}/roles/", {"role_id": role["id"]})
    assert missing.status_code == 404
    unsupported = root.post(f"{ADMIN}roles/{role['id']}/grant-permission/", {"permission": "x.y"})
    assert unsupported.status_code == 400


def test_admin_position_and_grant_lifecycle(world):
    root = login_as(world.root)
    url = f"{ADMIN}users/{world.t_position.pk}/"
    assert root.post(f"{url}position/", {"position": "analyst"}).json()["position"] == "analyst"
    assert root.post(f"{url}position/", {"position": "analyst"}).status_code == 409
    assert root.post(f"{url}position/", {"position": "engineer"}).json()["position"] == "engineer"
    assert root.post(f"{url}position/", {"position": "both"}).status_code == 400
    assert root.post(f"{url}position/", {"position": None}).json()["position"] is None
    assert root.post(f"{url}grant-admin/").json()["is_admin"] is True
    assert root.post(f"{url}grant-admin/").status_code == 409
    assert root.post(f"{url}revoke-admin/").json()["is_admin"] is False
    assert root.post(f"{ADMIN}users/{world.root.pk}/revoke-admin/").status_code == 409
    assert (
        root.post(f"{ADMIN}users/{world.root.pk}/position/", {"position": "engineer"}).status_code
        == 200
    )
    filtered = root.get(f"{ADMIN}users/", {"is_admin": "true"}).json()["results"]
    assert {row["username"] for row in filtered} == {"root", "deputy"}


def test_admin_capabilities_are_independent_of_position(world):
    """Design review F-06: Admin outcomes on every route are the same with any position."""
    outcomes = {}
    for position in (None, "analyst", "engineer"):
        savepoint = transaction.savepoint()
        if position is not None:
            operator(administration.set_position, world.root.pk, position)
        root = login_as(world.root)
        read_statuses = [root.get(path).status_code for path in reads(world)]
        write_statuses = [root.send(m, p, b).status_code for _, m, p, b, _ in mutations(world)]
        outcomes[position] = (read_statuses, write_statuses)
        transaction.savepoint_rollback(savepoint)
        cache.clear()
    assert outcomes[None] == outcomes["analyst"] == outcomes["engineer"]
    assert outcomes[None] == ([200] * len(reads(world)), [m[4] for m in mutations(world)])


def test_admin_audit_search_contract(world):
    root = login_as(world.root)
    root.post(f"{ADMIN}teams/", {"code": "gamma", "name": "Gamma"})
    page = root.get(
        f"{ADMIN}audit-events/", {"action": "teams.team_created", "source": "http"}
    ).json()
    assert page["count"] == 1
    (entry,) = page["results"]
    assert set(entry) == {
        "event_id",
        "occurred_at",
        "actor",
        "action",
        "outcome",
        "resource",
        "source",
        "request_id",
        "client_ip",
        "changes",
        "metadata",
    }
    assert entry["actor"] == {"type": "user", "id": str(world.root.pk), "label": "root"}
    assert (
        entry["resource"]["type"] == "teams.team" and entry["changes"]["code"]["after"] == "gamma"
    )
    by_actor = root.get(f"{ADMIN}audit-events/", {"actor_id": str(world.root.pk)}).json()["results"]
    assert {row["actor"]["id"] for row in by_actor} == {str(world.root.pk)}
    ordered = root.get(f"{ADMIN}audit-events/").json()["results"]
    stamps = [(row["occurred_at"]) for row in ordered]
    assert stamps == sorted(stamps, reverse=True)
    resource = root.get(
        f"{ADMIN}audit-events/",
        {"resource_type": "teams.team", "resource_id": entry["resource"]["id"]},
    ).json()
    assert resource["count"] == 1
    assert root.get(f"{ADMIN}audit-events/", {"outcome": "denied"}).json()["count"] == 0


def test_admin_response_schemas_are_minimal(world):
    root = login_as(world.root)
    user = root.get(f"{ADMIN}users/{world.member.pk}/").json()
    assert set(user) == {
        "id",
        "username",
        "first_name",
        "last_name",
        "email",
        "is_active",
        "password_set",
        "is_admin",
        "position",
        "date_joined",
        "last_login",
        "memberships",
    }
    (membership,) = user["memberships"]
    assert set(membership) == {"membership_id", "team", "roles"}
    assert set(membership["team"]) == {"id", "code", "name", "is_active", "member_count"}
    assert membership["team"]["member_count"] == 2
    assert set(membership["roles"][0]) == {"id", "code", "name"}
    listed = root.get(f"{ADMIN}users/").json()["results"][0]
    assert set(listed) == set(user) - {"memberships"}
    member = root.get(f"{ADMIN}teams/{world.alpha.pk}/members/").json()["results"][0]
    assert set(member) == {"membership_id", "user", "roles"}
    assert set(member["user"]) == {
        "id",
        "username",
        "first_name",
        "last_name",
        "is_active",
        "position",
    }
    role = root.get(f"{ADMIN}roles/{world.role.pk}/").json()
    assert role == {
        "id": str(world.role.pk),
        "code": "reader",
        "name": "Reader",
        "permissions": [VIEW],
    }
    catalog = root.get(f"{ADMIN}permissions/").json()
    assert catalog["count"] == len(SUPPORTED_PERMISSIONS)
    assert {"code": VIEW, "action": "view"} in catalog["results"]
    text = json.dumps([user, listed, member, role])
    for forbidden in ("pbkdf2", "argon2", "is_staff", "is_superuser", "groups", "user_permissions"):
        assert forbidden not in text


def test_admin_object_matrix_answers_404_for_missing_and_swapped_ids(world):
    root = login_as(world.root)
    other_membership = Membership.objects.get(team=world.alpha, user=world.leaver)
    cases = [
        ("post", f"{ADMIN}users/{uuid.uuid4()}/disable/", {}),
        ("patch", f"{ADMIN}users/{uuid.uuid4()}/", {"first_name": "X"}),
        ("post", f"{ADMIN}teams/{uuid.uuid4()}/members/", {"user_id": str(world.joiner.pk)}),
        ("post", f"{ADMIN}teams/{world.alpha.pk}/members/", {"user_id": str(uuid.uuid4())}),
        ("post", f"{ADMIN}teams/{world.beta.pk}/members/{world.leaver.pk}/remove/", {}),
        ("post", f"{ADMIN}memberships/{other_membership.pk}/roles/{world.role.pk}/revoke/", {}),
        (
            "post",
            f"{ADMIN}memberships/{world.membership.pk}/roles/",
            {"role_id": str(uuid.uuid4())},
        ),
        ("post", f"{ADMIN}roles/{uuid.uuid4()}/grant-permission/", {"permission": VIEW}),
    ]
    before = state()
    for method, path, body in cases:
        assert root.send(method, path, body).status_code == 404, path
    assert root.get(f"{ADMIN}users/not-a-uuid/").status_code == 404
    assert (
        root.post(f"{ADMIN}teams/{world.alpha.pk}/members/", {"user_id": "nope"}).status_code == 400
    )
    assert state() == before
