"""SPEC-0007 slice B / TM-0007: findings API, authorization, logbook reads and audit.

Named tests prove SEC-01-SEC-10, SEC-23, SEC-31 (logbook reads), SEC-32 (finding writes), SEC-45,
SEC-46 and SEC-49. Transfer rules are in test_findings_transfer.py; runtime-role privileges in
test_db_roles.py."""

import hashlib
import json
import uuid
from types import SimpleNamespace
from unittest import mock

import pytest
from django.contrib.auth.models import Group, Permission
from django.db import IntegrityError, OperationalError, connection
from django.test.utils import CaptureQueriesContext
from django.urls import get_resolver
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle

from apps.accounts import services as accounts
from apps.assets import services as assets
from apps.audit.context import audit_source
from apps.audit.digests import VALID, verify_digest
from apps.audit.models import AuditEvent
from apps.findings import services
from apps.findings.models import Finding, FindingLogEntry
from apps.rbac import administration
from apps.rbac.principals import UserPrincipal
from apps.teams import services as teams
from apps.teams.models import Membership
from tests.platform_support import Browser
from tests.test_assets_security import (
    ASSET_CODES,
    OPERATOR,
    client_for,
    formatted_logs,
    grant,
    make_team,
    make_user,
)

pytestmark = pytest.mark.django_db
API = "/api/v1/findings/"
VIEW, ADD, CHANGE = "findings.view_finding", "findings.add_finding", "findings.change_finding"
FINDING_CODES = (
    VIEW,
    ADD,
    CHANGE,
    "findings.comment_finding",
    "findings.work_finding",
    "findings.override_priority",
)
REPORTER = (VIEW, ADD, CHANGE, "assets.view_asset")
ASSET_UNAVAILABLE = {"asset_id": ["Select an asset where you can report findings."]}
NEW = {"title": "Outdated TLS", "category": "vulnerability", "severity": "high"}


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


def build_world():
    alpha, beta = make_team("alpha"), make_team("beta")
    keeper = make_user("keeper")
    for team in (alpha, beta):
        grant(keeper, team, *ASSET_CODES, *FINDING_CODES)
    keeper_principal = UserPrincipal(keeper.pk)
    asset = assets.create_asset(keeper_principal, team_id=alpha.pk, name="Web 01", kind="server")
    beta_asset = assets.create_asset(keeper_principal, team_id=beta.pk, name="Db 01", kind="server")
    reporter = make_user("reporter")
    grant(reporter, alpha, *REPORTER)
    finding = services.create_finding(
        UserPrincipal(reporter.pk), asset_id=asset.pk, description="Seen on 443.", **NEW
    )
    beta_finding = services.create_finding(
        keeper_principal, asset_id=beta_asset.pk, title="Weak SSH", category="other", severity="low"
    )
    return SimpleNamespace(
        alpha=alpha,
        beta=beta,
        keeper=keeper,
        asset=asset,
        beta_asset=beta_asset,
        reporter=reporter,
        client=client_for(reporter),
        finding=finding,
        beta_finding=beta_finding,
    )


@pytest.fixture
def world(db):
    return build_world()


def detail(finding, suffix=""):
    pk = finding if isinstance(finding, uuid.UUID | str) else finding.pk
    return f"{API}{pk}/{suffix}"


def events(action):
    return AuditEvent.objects.filter(action=action)


def state():
    """Everything a refused request must leave untouched."""
    return (
        list(Finding.objects.order_by("pk").values()),
        list(FindingLogEntry.objects.order_by("pk").values()),
        AuditEvent.objects.filter(action__startswith="findings.").count(),
    )


def user_with(team, *codes, username=None):
    user = make_user(username or f"u-{uuid.uuid4().hex[:8]}")
    if codes:
        grant(user, team, *codes)
    else:
        teams.add_member(OPERATOR, team.pk, user.pk)
    return user


def make_admin(username="root"):
    user = make_user(username)
    administration.grant_admin(OPERATOR, user.pk)
    return user


def logbook(client, finding, **params):
    return client.get(detail(finding, "logbook/"), params)


# API contract


def test_findings_api_contract_shapes(world):
    created = world.client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
    assert created.status_code == 201, created.content
    body = created.json()
    summary_keys = {
        "id",
        "title",
        "severity",
        "category",
        "status",
        "created_at",
        "asset",
        "team",
        "assignee",
    }
    assert set(body) == summary_keys | {
        "version",
        "description",
        "cve_ids",
        "updated_at",
        "reported_by",
        "capabilities",
    }
    assert set(body["asset"]) == {
        "id",
        "name",
        "status",
        "kind",
        "environment",
        "criticality",
        "hardening_status",
        "internet_exposure",
        "os_label",
        "os_version",
    }
    assert body["team"] == {"id": str(world.alpha.pk), "code": "alpha", "name": "Alpha"}
    assert body["reported_by"] == {
        "id": str(world.reporter.pk),
        "username": "reporter",
        "display_name": "",
    }
    assert (body["status"], body["version"], body["assignee"]) == ("open", 1, None)
    assert body["capabilities"] == {"edit": True}
    assert world.client.get(detail(body["id"])).json() == body
    page = world.client.get(API).json()
    assert set(page) == {"count", "next", "previous", "results"}
    assert all(set(row) == summary_keys for row in page["results"])
    assert set(page["results"][0]["asset"]) == {"id", "name", "status"}
    entries = logbook(world.client, body["id"]).json()
    assert set(entries) == {"results", "has_more_before", "last_sequence"}
    assert entries["results"][0] == {
        "id": entries["results"][0]["id"],
        "sequence": 1,
        "kind": "system",
        "event": "finding_created",
        "actor": body["reported_by"],
        "body": None,
        "metadata": {},
        "created_at": entries["results"][0]["created_at"],
        "redacted": False,
        "redacted_at": None,
        "redaction_reason": None,
    }


def test_finding_lifecycle_create_edit_assign_work(world):
    # Slice B covers report and edit; assignment and work arrive with slice D.
    created = world.client.post(
        API,
        {
            "asset_id": str(world.asset.pk),
            "title": "  Legacy cipher suites  ",
            "description": "Line 1\r\n\tLine 2",
            "category": "misconfiguration",
            "severity": "medium",
            "cve_ids": [" cve-2024-3094 ", "CVE-2021-44228", "CVE-2024-3094"],
        },
        format="json",
    ).json()
    assert created["title"] == "Legacy cipher suites"
    assert created["description"] == "Line 1\n\tLine 2"
    assert created["cve_ids"] == ["CVE-2021-44228", "CVE-2024-3094"]
    target = detail(created["id"])
    updated = world.client.patch(
        target, {"version": 1, "severity": "critical", "title": "Legacy ciphers"}, format="json"
    )
    assert updated.status_code == 200, updated.content
    assert (updated.json()["version"], updated.json()["severity"]) == (2, "critical")
    assert updated.json()["status"] == "open"
    noop = world.client.patch(target, {"version": 2, "severity": "critical"}, format="json")
    assert noop.status_code == 200 and noop.json()["version"] == 2
    assert events("findings.finding_updated").count() == 1
    entries = logbook(world.client, created["id"]).json()["results"]
    assert [(e["sequence"], e["event"]) for e in entries] == [
        (1, "finding_created"),
        (2, "finding_updated"),
    ]
    assert entries[1]["metadata"] == {
        "fields": ["severity", "title"],
        "severity": {"before": "medium", "after": "critical"},
    }
    listed = world.client.get(API, {"severity": "critical"}).json()
    assert [row["id"] for row in listed["results"]] == [created["id"]]


def test_logbook_records_system_events_for_every_operation(world):
    target = detail(world.finding)
    world.client.patch(target, {"version": 1, "category": "other"}, format="json")
    world.client.patch(target, {"version": 2, "description": "Changed."}, format="json")
    world.client.patch(target, {"version": 3, "cve_ids": ["CVE-2024-3094"]}, format="json")
    entries = list(world.finding.log_entries.order_by("sequence"))
    assert [(e.sequence, e.event, e.actor_id) for e in entries] == [
        (1, "finding_created", world.reporter.pk),
        (2, "finding_updated", world.reporter.pk),
        (3, "finding_updated", world.reporter.pk),
        (4, "finding_updated", world.reporter.pk),
    ]
    assert [e.metadata for e in entries[1:]] == [
        {"fields": ["category"], "category": {"before": "vulnerability", "after": "other"}},
        {"fields": ["description"]},  # never the text itself (BR-27)
        {"fields": ["cve_ids"]},
    ]
    finding = Finding.objects.get(pk=world.finding.pk)
    assert (finding.log_sequence, finding.version) == (4, 4)
    assert {e.kind for e in entries} == {"system"} and not any(e.body for e in entries)


def test_logbook_cursor_directions_and_last_sequence(world):
    target = detail(world.finding)
    for version in range(1, 7):
        title = f"Outdated TLS {version}"
        assert world.client.patch(target, {"version": version, "title": title}, format="json")
    sequences = lambda page: [e["sequence"] for e in page["results"]]  # noqa: E731
    everything = logbook(world.client, world.finding).json()
    assert (sequences(everything), everything["has_more_before"]) == ([1, 2, 3, 4, 5, 6, 7], False)
    assert everything["last_sequence"] == 7
    latest = logbook(world.client, world.finding, limit=3).json()
    assert (sequences(latest), latest["has_more_before"]) == ([5, 6, 7], True)
    earlier = logbook(world.client, world.finding, before=5, limit=2).json()
    assert (sequences(earlier), earlier["has_more_before"]) == ([3, 4], True)
    first = logbook(world.client, world.finding, before=2).json()
    assert (sequences(first), first["has_more_before"]) == ([1], False)
    nothing = logbook(world.client, world.finding, before=1).json()
    assert (sequences(nothing), nothing["has_more_before"]) == ([], False)
    newer = logbook(world.client, world.finding, after=5).json()
    assert (sequences(newer), newer["has_more_before"], newer["last_sequence"]) == ([6, 7], True, 7)
    polled = logbook(world.client, world.finding, after=7).json()
    assert (sequences(polled), polled["last_sequence"]) == ([], 7)
    assert sequences(logbook(world.client, world.finding, after=0, limit=2).json()) == [1, 2]
    ahead = logbook(world.client, world.finding, after=999).json()
    assert (sequences(ahead), ahead["last_sequence"]) == ([], 7)


def test_logbook_cursor_parameters_are_validated_cwe_20(world):
    for params in (
        {"after": "-1"},
        {"after": "abc"},
        {"after": "1.5"},
        {"after": " 1"},
        {"after": "1e3"},
        {"after": "+1"},
        {"after": "2147483648"},
        {"after": "00000000001"},
        {"before": chr(0x661)},  # ARABIC-INDIC DIGIT ONE is decimal, but not ASCII
        {"after": "1", "before": "3"},
        {"limit": "0"},
        {"limit": "101"},
        {"limit": "ten"},
        {"page": "1"},
        {"cursor": "1"},
    ):
        response = logbook(world.client, world.finding, **params)
        assert response.status_code == 400, params
        assert response.json()["error"]["code"] == "validation_error"
    repeated = world.client.get(detail(world.finding, "logbook/") + "?after=1&after=2")
    assert repeated.status_code == 400
    assert logbook(world.client, world.finding, after="2147483647", limit="100").status_code == 200


# SEC-01 — enabled session and CSRF (T-04, CWE-306, CWE-352)


def test_findings_endpoints_require_session_and_csrf_cwe_306_cwe_352(world):
    requests = [
        ("get", API, None),
        ("post", API, {"asset_id": str(world.asset.pk), **NEW}),
        ("get", detail(world.finding), None),
        ("patch", detail(world.finding), {"version": 1, "title": "X"}),
        ("get", detail(world.finding, "logbook/"), None),
    ]
    anonymous = APIClient()
    for method, path, body in requests:
        response = getattr(anonymous, method)(path, body, format="json")
        assert response.status_code == 401, (method, path)
        assert response.json()["error"]["code"] == "not_authenticated"
    before = state()
    browser = Browser().login("reporter")
    for method, path, body in requests:
        if method != "get":
            refused = browser.send(method, path, body, csrf=False)
            assert refused.status_code == 403, (method, path)
    assert state() == before
    assert browser.post(API, requests[1][2]).status_code == 201  # same request with the token
    accounts.disable_user("reporter", actor=accounts.CLI_ACTOR)
    for method, path, body in requests:
        response = browser.send(method, path, body) if method != "get" else browser.get(path)
        assert response.status_code == 401, (method, path)


# SEC-02 — scoped reads, 404 outside scope, 403 without view (T-01, T-02, CWE-639, CWE-862)


def test_finding_read_authorization_matrix_cwe_639_cwe_862(world):
    reader = client_for(user_with(world.alpha, VIEW))
    outsider = client_for(user_with(world.beta, *FINDING_CODES))  # every grant, other team
    no_view = client_for(user_with(world.alpha, ADD, CHANGE, "assets.view_asset"))
    admin = client_for(make_admin())
    alpha_paths = (detail(world.finding), detail(world.finding, "logbook/"))
    for path in alpha_paths:
        assert reader.get(path).status_code == 200
        assert outsider.get(path).status_code == 404
        assert no_view.get(path).status_code == 403
        assert admin.get(path).status_code == 200
        assert reader.get(path.replace(str(world.finding.pk), str(uuid.uuid4()))).status_code == 404
    for path in (detail(world.beta_finding), detail(world.beta_finding, "logbook/")):
        assert reader.get(path).status_code == 404  # swapped UUID of another team
        assert outsider.get(path).status_code == 200
    assert reader.get(f"{API}not-a-uuid/").status_code == 404

    def ids(client, **params):
        page = client.get(API, params).json()
        assert page["count"] == len(page["results"])
        return {row["id"] for row in page["results"]}

    alpha_id, beta_id = str(world.finding.pk), str(world.beta_finding.pk)
    assert ids(reader) == {alpha_id}
    assert ids(reader, team=str(world.beta.pk)) == set()  # filters never widen the scope
    assert ids(reader, asset=str(world.beta_asset.pk)) == set()
    assert ids(reader, q="Weak") == set()
    assert ids(reader, severity="low") == set()
    assert ids(outsider) == {beta_id}
    assert ids(no_view) == set()
    assert ids(admin) == {alpha_id, beta_id}
    assert ids(admin, team=str(world.beta.pk)) == {beta_id}
    disabled = user_with(world.alpha, VIEW, username="leaver")
    client = client_for(disabled)
    accounts.disable_user("leaver", actor=accounts.CLI_ACTOR)
    for path in (API, *alpha_paths):
        assert client.get(path).status_code == 401
        assert APIClient().get(path).status_code == 401


# SEC-03 — a grant in team B never acts in team A (T-03, CWE-863)


def test_permission_in_other_team_never_grants_finding_access_cwe_863(world):
    both = user_with(world.beta, *FINDING_CODES, "assets.view_asset", username="both")
    teams.add_member(OPERATOR, world.alpha.pk, both.pk)  # member of alpha without any grant
    client = client_for(both)
    before = state()
    assert client.get(detail(world.finding)).status_code == 403
    assert client.get(detail(world.finding, "logbook/")).status_code == 403
    assert (
        client.patch(detail(world.finding), {"version": 1, "title": "X"}, format="json").status_code
        == 403
    )
    created = client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
    assert (created.status_code, created.json()["error"]["details"]) == (400, ASSET_UNAVAILABLE)
    assert {row["id"] for row in client.get(API).json()["results"]} == {str(world.beta_finding.pk)}
    assert state() == before


# SEC-04 — create needs add + view + asset view in the asset's team (T-06, CWE-639, CWE-204)


def test_finding_create_authorization_and_asset_scope_cwe_639(world):
    before = state()
    for body in (
        {"asset_id": str(uuid.uuid4()), **NEW},  # unknown
        {"asset_id": "not-a-uuid", **NEW},  # malformed
        NEW,  # missing
        {"asset_id": str(world.beta_asset.pk), **NEW},  # another team's asset
    ):
        response = world.client.post(API, body, format="json")
        assert response.status_code == 400, body
        assert response.json()["error"]["details"] == ASSET_UNAVAILABLE  # one answer, no oracle
    without_asset_view = client_for(user_with(world.alpha, VIEW, ADD))
    response = without_asset_view.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
    assert (response.status_code, response.json()["error"]["details"]) == (400, ASSET_UNAVAILABLE)
    for codes in ((VIEW, "assets.view_asset"), (ADD, "assets.view_asset")):
        client = client_for(user_with(world.alpha, *codes))
        response = client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
        assert response.status_code == 403, codes
    assert state() == before
    assets.retire_asset(UserPrincipal(world.keeper.pk), world.asset.pk, version=1)
    retired = world.client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
    assert retired.status_code == 409
    assert retired.json()["error"]["message"] == (
        "The asset is retired; new findings cannot be reported on it."
    )
    assert state() == before
    assets.restore_asset(UserPrincipal(world.keeper.pk), world.asset.pk, version=2)
    assert (
        world.client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json").status_code
        == 201
    )


# SEC-05 — strict body allowlists (T-05, CWE-915)


def test_finding_writes_reject_unlisted_fields_cwe_915(world):
    before = state()
    forbidden = {
        "status": "in_progress",
        "assignee_id": str(world.reporter.pk),
        "assignee": str(world.reporter.pk),
        "reported_by": str(world.keeper.pk),
        "reported_by_id": str(world.keeper.pk),
        "team_id": str(world.beta.pk),
        "team": str(world.beta.pk),
        "priority": "p4",
        "score": 5,
        "level": "p4",
        "override_level": "p4",
        "override_reason": "x",
        "log_sequence": 0,
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2020-01-01T00:00:00Z",
        "id": str(uuid.uuid4()),
    }
    for key, value in forbidden.items():
        created = world.client.post(
            API, {"asset_id": str(world.asset.pk), **NEW, key: value}, format="json"
        )
        assert created.status_code == 400 and key in created.json()["error"]["details"], key
        patched = world.client.patch(
            detail(world.finding), {"version": 1, "title": "New", key: value}, format="json"
        )
        assert patched.status_code == 400 and key in patched.json()["error"]["details"], key
    moved = world.client.patch(
        detail(world.finding), {"version": 1, "asset_id": str(world.beta_asset.pk)}, format="json"
    )
    assert moved.status_code == 400  # the asset binding is immutable (BR-03)
    for body in (
        {"version": 1, "title": 5},
        {"version": 1, "cve_ids": "CVE-2024-3094"},
        {"version": 1, "cve_ids": [5]},
        {"version": 1, "cve_ids": ["CVE-2024-3094"] * 21},
        {"version": 1, "cve_ids": ["CVE-24-1"]},
        {"version": True, "title": "New"},
        {"version": "1", "title": "New"},
        {"version": 1, "severity": "unknown"},
        {"version": 1, "category": None},
        {"version": 1, "title": ""},
        {"version": 1, "title": "x" * 201},
        {"version": 1, "title": "Line\nbreak"},
        {"version": 1, "description": "x" * 10_001},
        {"version": 1, "description": "a" + chr(0x202E) + "b"},
        {"version": 1},
        {"title": "New"},
    ):
        response = world.client.patch(detail(world.finding), body, format="json")
        assert response.status_code == 400, body
    raw = world.client.generic(
        "PATCH",
        detail(world.finding),
        '{"version": 1, "title": "A", "title": "B"}',
        content_type="application/json",
    )
    assert raw.status_code == 400
    assert state() == before


# SEC-06 — authorship from the session (T-22, CWE-639)


def test_finding_and_comment_authorship_come_from_session_cwe_639(world):
    created = world.client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json").json()
    finding = Finding.objects.get(pk=created["id"])
    assert finding.reported_by_id == world.reporter.pk
    entry = finding.log_entries.get()
    assert (entry.actor_id, entry.kind) == (world.reporter.pk, "system")
    event = events("findings.finding_created").get(resource_id=created["id"])
    assert (event.actor_id, event.actor_label, event.source) == (
        world.reporter.pk,
        "reporter",
        "http",
    )
    spoofed = {"asset_id": str(world.asset.pk), **NEW, "reported_by": str(world.keeper.pk)}
    assert world.client.post(API, spoofed, format="json").status_code == 400
    # Comments (slice C) cannot be posted at all yet.
    assert (
        world.client.post(detail(finding, "logbook/"), {"body": "x"}, format="json").status_code
        == 405
    )


# SEC-07 — stale versions (T-07, CWE-362)


def test_stale_finding_mutations_return_409_cwe_362(world):
    target = detail(world.finding)
    assert (
        world.client.patch(target, {"version": 1, "title": "Second"}, format="json").status_code
        == 200
    )
    before = state()
    for body in (
        {"version": 1, "title": "Third"},
        {"version": 1, "title": "Second"},
        {"version": 3, "title": "X"},
    ):
        response = world.client.patch(target, body, format="json")
        assert response.status_code == 409, body
        assert response.json()["error"]["message"] == "The finding changed. Reload and try again."
    assert state() == before


# SEC-08 — status only through transitions (T-08, CWE-841)


def test_finding_status_changes_only_through_transitions_cwe_841(world):
    before = state()
    for status in ("in_progress", "open", "resolved", "closed"):
        response = world.client.patch(
            detail(world.finding), {"version": 1, "status": status}, format="json"
        )
        assert response.status_code == 400
    assert state() == before
    routes = {
        str(pattern.pattern)
        for pattern in get_resolver().url_patterns
        if str(pattern.pattern).startswith("api/v1/findings/")
    }
    assert routes == {"api/v1/findings/"}
    from apps.findings import urls

    assert sorted(str(p.pattern) for p in urls.urlpatterns) == [
        "",
        "<uuid:pk>/",
        "<uuid:pk>/logbook/",
    ]


# SEC-09 — Admin oversight is read-only (T-09, CWE-863)


def test_admin_oversight_reads_findings_without_write_authority_cwe_863(world):
    root = make_admin()
    client = client_for(root)
    assert {r["id"] for r in client.get(API).json()["results"]} == {
        str(world.finding.pk),
        str(world.beta_finding.pk),
    }
    shown = client.get(detail(world.finding)).json()
    assert shown["capabilities"] == {"edit": False}
    assert logbook(client, world.beta_finding).status_code == 200
    before = state()
    patch = {"version": 1, "title": "Admin edit"}
    assert client.patch(detail(world.finding), patch, format="json").status_code == 404
    created = client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
    # Outside the team path the create answer is SEC-04's generic 400 (as for assets, SPEC-0010).
    assert (created.status_code, created.json()["error"]["details"]) == (400, ASSET_UNAVAILABLE)
    teams.add_member(OPERATOR, world.alpha.pk, root.pk)  # member without grants
    assert client.patch(detail(world.finding), patch, format="json").status_code == 403
    grant(root, world.alpha, "assets.view_asset")
    created = client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
    assert created.status_code == 403
    assert state() == before
    make_admin("deputy")
    administration.revoke_admin(OPERATOR, root.pk)
    assert client.get(detail(world.beta_finding)).status_code == 404
    assert client.get(detail(world.finding)).status_code == 403  # member of alpha, no view


# SEC-10 — native flags, groups and user permissions grant nothing (T-10, CWE-269)


def test_native_flags_grant_no_finding_authority_cwe_269(world):
    flagged = make_user("flagged")
    flagged.is_staff = flagged.is_superuser = True
    flagged.save(update_fields=["is_staff", "is_superuser"])
    permissions = Permission.objects.filter(content_type__app_label="findings")
    assert permissions.count() == 6
    group = Group.objects.create(name="finders")
    group.permissions.set(permissions)
    flagged.groups.add(group)
    flagged.user_permissions.set(permissions)
    client = client_for(flagged)
    before = state()
    assert client.get(API).json()["count"] == 0
    assert client.get(detail(world.finding)).status_code == 404
    assert logbook(client, world.finding).status_code == 404
    assert (
        client.patch(detail(world.finding), {"version": 1, "title": "X"}, format="json").status_code
        == 404
    )
    created = client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
    assert created.status_code == 400
    assert state() == before


# SEC-23 — no route edits or deletes history (T-23, CWE-284)


def test_logbook_has_no_edit_or_delete_path_cwe_284(world):
    entry = world.finding.log_entries.get()
    before = state()
    for method in ("put", "patch", "delete", "post"):
        response = getattr(world.client, method)(
            detail(world.finding, "logbook/"), {"body": "forged"}, format="json"
        )
        assert response.status_code == 405, method
    for path in (
        detail(world.finding, f"logbook/{entry.pk}/"),
        detail(world.finding, "logbook/1/"),
    ):
        for method in ("get", "put", "patch", "delete"):
            assert getattr(world.client, method)(path).status_code == 404
    for method in ("put", "delete"):
        assert getattr(world.client, method)(detail(world.finding)).status_code == 405
    assert state() == before


# SEC-32 — finding writes have their own per-user budget (T-32, CWE-770)


@mock.patch.dict(SimpleRateThrottle.THROTTLE_RATES, {"finding_write": "3/min"})
def test_finding_write_and_comment_throttles_cwe_770(world):
    noop = {"version": 1, "title": "Outdated TLS"}
    statuses = [
        world.client.patch(detail(world.finding), noop, format="json").status_code for _ in range(4)
    ]
    assert statuses == [200, 200, 200, 429]
    throttled = world.client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
    assert throttled.status_code == 429 and int(throttled["Retry-After"]) > 0
    for _ in range(5):  # reads and polls never consume the budget
        assert world.client.get(detail(world.finding)).status_code == 200
        assert logbook(world.client, world.finding).status_code == 200
    other = client_for(user_with(world.alpha, *REPORTER))
    assert other.patch(detail(world.finding), noop, format="json").status_code == 200


# SEC-45 — no user content in logs (T-45, CWE-532)


def test_findings_logs_exclude_user_content_cwe_532(world, caplog):
    marker = "MARKER-7f3a"
    body = {
        "asset_id": str(world.asset.pk),
        "title": f"{marker} title",
        "description": f"{marker} description",
        "category": "other",
        "severity": "low",
        "cve_ids": ["CVE-2099-777777"],
    }
    caplog.set_level("DEBUG")
    created = world.client.post(API, body, format="json").json()
    world.client.patch(
        detail(created["id"]), {"version": 1, "description": f"{marker} 2"}, format="json"
    )
    outsider = client_for(user_with(world.beta, *FINDING_CODES, "assets.view_asset"))
    outsider.get(detail(created["id"]))  # 404, logged
    outsider.post(API, body, format="json")  # 400 asset_unavailable, logged
    no_view = client_for(user_with(world.alpha, ADD, "assets.view_asset"))
    no_view.get(detail(created["id"]))  # 403, logged with the database row's ID
    logs = formatted_logs(caplog)
    assert "authorization_denied" in logs and created["id"] in logs
    for secret in (marker, "CVE-2099-777777", str(world.asset.pk)):
        assert secret not in logs, secret
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")  # the connection is healthy after the logged requests


# SEC-46 — fixed error messages (T-46, CWE-209)


def test_finding_errors_use_fixed_messages_cwe_209(world):
    def failing(cause):
        def run(*args, **kwargs):
            raise cause

        return run

    integrity = IntegrityError("duplicate key value (title)=(secret-title)")
    with mock.patch.object(services.Finding, "save", failing(integrity)):
        response = world.client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json")
    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "server_error",
        "message": "Internal server error.",
        "request_id": response.json()["error"]["request_id"],
    }
    lock = OperationalError("canceling statement due to lock timeout on findings_finding")
    with mock.patch.object(services, "lock_authority", failing(lock)):
        response = world.client.patch(
            detail(world.finding), {"version": 1, "title": "X"}, format="json"
        )
    assert response.status_code == 503
    assert response.json()["error"]["message"] == "Service temporarily unavailable."
    text = json.dumps([response.json()])
    assert "findings_finding" not in text and "secret-title" not in text
    for status, path, body, message in (
        (404, detail(uuid.uuid4()), None, "Not found."),
        (
            409,
            detail(world.finding),
            {"version": 9, "title": "X"},
            "The finding changed. Reload and try again.",
        ),
    ):
        response = world.client.patch(path, body or {"version": 1, "title": "X"}, format="json")
        assert response.status_code == status
        assert response.json()["error"]["message"] == message


# SEC-49 — keyed content digests in audit, never the text (T-29, T-49, CWE-212, CWE-759)


def test_audit_content_digests_are_keyed_cwe_759(world):
    created = world.client.post(
        API, {"asset_id": str(world.asset.pk), **NEW, "description": "token=hunter2"}, format="json"
    ).json()
    event = events("findings.finding_created").get(resource_id=created["id"])
    assert event.resource_type == "findings.finding"
    assert set(event.changes) == {"asset_id", "title", "category", "severity", "cve_ids", "status"}
    assert event.changes["title"] == {"before": None, "after": "Outdated TLS"}
    digest = event.metadata["description_digest"]
    assert event.metadata["description_length"] == len("token=hunter2")
    assert digest.startswith("hmac-sha256:test:")
    assert digest.split(":")[2] != hashlib.sha256(b"token=hunter2").hexdigest()
    context = services.DIGEST_CONTEXT
    assert context == "trilha.findings.content-digest"
    assert verify_digest("token=hunter2", digest, context=context) == (VALID, "test")
    world.client.patch(
        detail(created["id"]), {"version": 1, "description": "rotated"}, format="json"
    )
    updated = events("findings.finding_updated").get(resource_id=created["id"])
    assert set(updated.changes) == {"description_digest", "description_length"}
    assert updated.changes["description_digest"]["before"] == digest
    assert (
        verify_digest("rotated", updated.changes["description_digest"]["after"], context=context)[0]
        == VALID
    )
    assert updated.changes["description_length"] == {"before": 13, "after": 7}
    stored = json.dumps([event.changes, event.metadata, updated.changes, updated.metadata])
    assert "hunter2" not in stored and "rotated" not in stored


# BR-18 — retirement keeps findings visible and workable, blocks new ones


def test_retired_asset_findings_stay_visible_and_block_new_findings(world):
    assets.retire_asset(UserPrincipal(world.keeper.pk), world.asset.pk, version=1)
    shown = world.client.get(detail(world.finding)).json()
    assert shown["asset"]["status"] == "retired"
    assert world.client.get(API).json()["results"][0]["asset"]["status"] == "retired"
    edited = world.client.patch(
        detail(world.finding), {"version": 1, "severity": "low"}, format="json"
    )
    assert edited.status_code == 200
    assert (
        world.client.post(API, {"asset_id": str(world.asset.pk), **NEW}, format="json").status_code
        == 409
    )


# NFR-04 — one query set per list, whatever its length


def test_findings_list_has_no_n_plus_one(world):
    def count():
        with CaptureQueriesContext(connection) as queries:
            assert world.client.get(API, {"page_size": 100}).status_code == 200
        return len(queries)

    few = count()
    principal = UserPrincipal(world.reporter.pk)
    for number in range(50):
        services.create_finding(
            principal, asset_id=world.asset.pk, **{**NEW, "title": f"F {number}"}
        )
    assert world.client.get(API).json()["count"] == 51
    assert count() == few


# SEC-30 (read side) — every poll re-authorizes (T-30, CWE-613)


def test_logbook_poll_fails_closed_after_revocation_cwe_613(world):
    viewer = user_with(world.alpha, VIEW, username="viewer")
    client = client_for(viewer)
    assert logbook(client, world.finding, after=0).status_code == 200
    role_assignment = Membership.objects.get(user=viewer, team=world.alpha).role_assignments.get()
    from apps.rbac import services as rbac

    rbac.revoke_permission(OPERATOR, role_assignment.role_id, VIEW)
    assert logbook(client, world.finding, after=0).status_code == 403
    rbac.grant_permission(OPERATOR, role_assignment.role_id, VIEW)
    assert logbook(client, world.finding, after=0).status_code == 200
    teams.remove_member(OPERATOR, world.alpha.pk, viewer.pk)
    assert logbook(client, world.finding, after=0).status_code == 404
    grant(viewer, world.alpha, VIEW)
    teams.deactivate_team(OPERATOR, world.alpha.pk)
    assert logbook(client, world.finding, after=0).status_code == 404
