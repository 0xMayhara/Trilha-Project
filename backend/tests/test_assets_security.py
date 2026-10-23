"""SPEC-0005 / TM-0005 adversarial acceptance contracts (SEC-01 through SEC-31)."""

import functools
import inspect
import json
import logging
import threading
import time
import uuid
from types import SimpleNamespace
from unittest import mock

import psycopg.errors
import pytest
from django.conf import settings
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import ValidationError
from django.db import IntegrityError, OperationalError, connection, transaction
from django.test.utils import CaptureQueriesContext
from django.urls import get_resolver
from redis.exceptions import ConnectionError as RedisConnectionError
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle

from apps.accounts import services as accounts
from apps.accounts.models import User
from apps.assets import services, views
from apps.assets.exceptions import (
    AssetForbidden,
    AssetNotFound,
    InvalidState,
    NameTaken,
    StaleAsset,
    TeamUnavailable,
)
from apps.assets.models import Asset
from apps.audit.context import audit_source
from apps.audit.exceptions import AuditValidationError
from apps.audit.models import AuditEvent
from apps.core.logging import JsonFormatter
from apps.rbac import events as rbac_events
from apps.rbac import services as rbac
from apps.rbac.catalog import SUPPORTED_PERMISSIONS, catalog_action
from apps.rbac.exceptions import RbacError
from apps.rbac.permissions import ActiveSession
from apps.rbac.principals import UserPrincipal, infrastructure_operator
from apps.rbac.selectors import can_access
from apps.teams import services as teams
from apps.teams.models import Membership, Team

pytestmark = pytest.mark.django_db
OPERATOR = infrastructure_operator()
PASSWORD = "correct-horse-battery-staple"
VIEW, ADD, CHANGE, RETIRE, TRANSFER = (
    "assets.view_asset",
    "assets.add_asset",
    "assets.change_asset",
    "assets.retire_asset",
    "assets.transfer_asset",
)
ASSET_CODES = (VIEW, ADD, CHANGE, RETIRE, TRANSFER)
API = "/api/v1/assets/"


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


def make_team(code):
    team = teams.create_team(OPERATOR, code=code, name=code.title())
    preview = teams.preview_team_activation(OPERATOR, team.pk)
    return teams.activate_team(OPERATOR, team.pk, preview.revision, preview.code)


def make_user(username):
    return User.objects.create_user(username=username, password=PASSWORD)


def grant(user, team, *codes):
    """A fresh role holding exactly `codes`, assigned through the user's membership in `team`."""
    membership = Membership.objects.filter(user=user, team=team).first() or teams.add_member(
        OPERATOR, team.pk, user.pk
    )
    role = rbac.create_role(OPERATOR, code=f"r-{uuid.uuid4().hex[:12]}", name="Role")
    for code in codes:
        rbac.grant_permission(OPERATOR, role.pk, code)
    rbac.assign_role(OPERATOR, membership.pk, role.pk)
    return role


def client_for(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


def allowed(user, team, code, **kwargs):
    kwargs.setdefault("action", catalog_action(code))
    return can_access(UserPrincipal(user.pk), code, team_id=team.pk, **kwargs)


def build_world():
    alpha, beta = make_team("alpha"), make_team("beta")
    manager = make_user("manager")
    role = grant(manager, alpha, *ASSET_CODES)
    asset = services.create_asset(
        UserPrincipal(manager.pk),
        team_id=alpha.pk,
        name="Web 01",
        kind="server",
        hostname="web-01.example.com",
        ip_addresses=["10.0.0.5"],
    )
    return SimpleNamespace(
        alpha=alpha,
        beta=beta,
        manager=manager,
        role=role,
        asset=asset,
        client=client_for(manager),
        principal=UserPrincipal(manager.pk),
    )


@pytest.fixture
def world(db):
    return build_world()


def detail(asset, suffix=""):
    return f"{API}{asset.pk}/{suffix}"


def reload(asset):
    return Asset.objects.get(pk=asset.pk)


def events(action):
    return AuditEvent.objects.filter(action=action)


def mutation_requests(asset, version=1, team_id=None):
    """(method, path, body) for every asset mutation route."""
    return [
        ("post", API, {"team_id": str(team_id or asset.team_id), "name": "New", "kind": "server"}),
        ("patch", detail(asset), {"version": version, "name": "Renamed"}),
        ("post", detail(asset, "retire/"), {"version": version}),
        ("post", detail(asset, "restore/"), {"version": version}),
        ("post", detail(asset, "transfer/"), {"version": version, "team_id": str(team_id)}),
    ]


def send(client, method, path, body=None, **extra):
    return getattr(client, method)(path, body, format="json", **extra)


def in_thread(name, function):
    """Runs `function` on its own thread and database connection; captures result or error."""
    result = {}

    def target():
        try:
            with audit_source("command"):
                result["value"] = function()
        except Exception as exc:  # surfaced through `result` to the caller's assertion
            result["error"] = exc
        finally:
            connection.close()

    thread = threading.Thread(target=target, name=name)
    thread.start()
    return thread, result


class PauseWriter:
    """Pauses the first audited write of a named thread while its transaction holds row locks."""

    def __init__(self, thread_name):
        self.thread_name = thread_name
        self.paused, self.release = threading.Event(), threading.Event()
        self.original = rbac_events.record_event

    def __call__(self, **kwargs):
        event = self.original(**kwargs)
        if threading.current_thread().name == self.thread_name and not self.paused.is_set():
            self.paused.set()
            assert self.release.wait(10)
        return event

    def __enter__(self):
        self.patches = [
            mock.patch.object(rbac_events, "record_event", self),
            mock.patch.object(accounts, "record_event", self),
        ]
        for patch in self.patches:
            patch.start()
        return self

    def __exit__(self, *exc):
        self.release.set()
        for patch in self.patches:
            patch.stop()


def race(writer_name, writer, mutation):
    """Starts `writer`, pauses it holding its locks, then runs `mutation` against it."""
    with PauseWriter(writer_name) as pause:
        writer_thread, writer_result = in_thread(writer_name, writer)
        assert pause.paused.wait(10)
        mutation_thread, mutation_result = in_thread("asset-mutation", mutation)
        time.sleep(0.5)
        blocked = mutation_thread.is_alive()
        pause.release.set()
        writer_thread.join(10)
        mutation_thread.join(10)
    assert "error" not in writer_result, writer_result
    return blocked, mutation_result


def formatted_logs(caplog):
    formatter = JsonFormatter()
    return "\n".join(formatter.format(record) for record in caplog.records)


# SEC-01 — enabled session required (T-01, CWE-862)


def test_asset_endpoints_require_enabled_session(world):
    anonymous = APIClient()
    requests = [("get", API, None), ("get", detail(world.asset), None)]
    requests += mutation_requests(world.asset, team_id=world.beta.pk)
    for method, path, body in requests:
        response = send(anonymous, method, path, body)
        assert response.status_code == 401, (method, path)
        assert response.json()["error"]["code"] == "not_authenticated"
    User.objects.filter(pk=world.manager.pk).update(is_active=False)
    assert world.manager.is_active  # deliberately stale loaded identity
    for method, path, body in requests:
        assert send(world.client, method, path, body).status_code == 401, (method, path)
    assert settings.REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] == [
        "apps.core.api.permissions.DenyAll"
    ]
    for view in (views.AssetListView, views.AssetDetailView, views.AssetRetireView):
        assert view.permission_classes == (ActiveSession,)
    assert reload(world.asset).name == "Web 01"


# SEC-02 — lists and counts scoped in SQL; retired readable only when asked (T-02, CWE-200)


def test_asset_list_and_counts_include_only_authorized_teams(world):
    outsider = make_user("outsider")
    grant(outsider, world.beta, *ASSET_CODES)
    services.create_asset(
        UserPrincipal(outsider.pk), team_id=world.beta.pk, name="Db", kind="server"
    )
    no_view = make_user("noview")
    grant(no_view, world.alpha, ADD, CHANGE, RETIRE, TRANSFER)
    bare = make_user("bare")
    teams.add_member(OPERATOR, world.alpha.pk, bare.pk)

    page = world.client.get(API).json()
    assert page["count"] == 1 and [a["name"] for a in page["results"]] == ["Web 01"]
    for query in (f"team={world.beta.pk}", f"team={uuid.uuid4()}", "q=Db"):
        response = world.client.get(f"{API}?{query}")
        assert response.status_code == 200 and response.json()["count"] == 0, query
    assert [a["name"] for a in client_for(outsider).get(API).json()["results"]] == ["Db"]
    for user in (no_view, bare):
        assert client_for(user).get(API).json()["count"] == 0
    teams.deactivate_team(OPERATOR, world.alpha.pk)
    assert world.client.get(API).json()["count"] == 0


def test_retired_assets_readable_only_through_authorized_filter_and_detail(world):
    services.retire_asset(world.principal, world.asset.pk, version=1)
    assert world.client.get(API).json()["count"] == 0
    retired = world.client.get(f"{API}?status=retired").json()
    assert retired["count"] == 1 and retired["results"][0]["status"] == "retired"
    assert world.client.get(detail(world.asset)).json()["status"] == "retired"
    member = make_user("member")
    grant(member, world.alpha, CHANGE)
    outsider = make_user("outsider")
    grant(outsider, world.beta, *ASSET_CODES)
    for user, status in ((member, 403), (outsider, 404)):
        client = client_for(user)
        assert client.get(f"{API}?status=retired").json()["count"] == 0
        assert client.get(detail(world.asset)).status_code == status


# SEC-03 — scope before lookup; hidden and missing look identical (T-03, CWE-639)


def test_asset_identifier_swap_returns_404_cwe_639(world, caplog):
    outsider = make_user("outsider")
    grant(outsider, world.beta, *ASSET_CODES)
    client = client_for(outsider)
    missing = SimpleNamespace(pk=uuid.uuid4(), team_id=world.alpha.pk)
    for target in (world.asset, missing):
        for method, path, body in [("get", detail(target), None), *mutation_requests(target, 1)][
            :-1
        ]:
            if path == API:
                continue
            response = send(client, method, path, body)
            assert response.status_code == 404, (method, path)
            assert response.json()["error"]["message"] == "Not found."
    transfer = {"version": 1, "team_id": str(world.beta.pk)}
    assert send(client, "post", detail(world.asset, "transfer/"), transfer).status_code == 404
    assert client.get(f"{API}not-a-uuid/").status_code == 404
    member = make_user("member")
    grant(member, world.alpha, CHANGE)
    assert client_for(member).get(detail(world.asset)).status_code == 403
    denials = [r for r in caplog.records if r.getMessage() == "authorization_denied"]
    hidden = [r for r in denials if r.actor_id == str(outsider.pk)]
    assert hidden and not any(hasattr(r, "asset_id") for r in hidden)  # 404s name no asset
    in_scope = [r for r in denials if r.actor_id == str(member.pk)]
    assert [(r.operation, r.asset_id) for r in in_scope] == [("read", str(world.asset.pk))]
    assert reload(world.asset).version == 1


# SEC-04 — no grant mixing across memberships (T-04, CWE-863)


def test_asset_permission_from_team_a_cannot_act_in_team_b(world):
    owner = make_user("owner")
    grant(owner, world.beta, *ASSET_CODES)
    beta_asset = services.create_asset(
        UserPrincipal(owner.pk), team_id=world.beta.pk, name="Beta", kind="server"
    )
    teams.add_member(OPERATOR, world.beta.pk, world.manager.pk)  # member of beta, no grants there
    assert allowed(world.manager, world.alpha, CHANGE)
    assert not allowed(world.manager, world.beta, CHANGE)
    for method, path, body in [
        ("get", detail(beta_asset), None),
        *mutation_requests(beta_asset, 1, team_id=world.beta.pk)[:4],
        ("post", detail(beta_asset, "transfer/"), {"version": 1, "team_id": str(world.alpha.pk)}),
    ]:
        assert send(world.client, method, path, body).status_code == 403, (method, path)
    grant(world.manager, world.beta, VIEW)  # view in beta still does not lend alpha's change
    assert (
        send(world.client, "patch", detail(beta_asset), {"version": 1, "name": "X"}).status_code
        == 403
    )
    assert reload(beta_asset).name == "Beta" and Asset.objects.filter(team=world.beta).count() == 1


# SEC-05 — create needs add + view in the target team (T-05, CWE-639)


def test_create_asset_requires_grants_in_target_team_cwe_639(world, caplog):
    outsider = make_user("outsider")
    grant(outsider, world.beta, *ASSET_CODES)
    inactive = teams.create_team(OPERATOR, code="gamma", name="Gamma")
    teams.add_member(OPERATOR, inactive.pk, outsider.pk)
    created = events("assets.asset_created").count()
    body = {"name": "Probe", "kind": "server"}
    messages = set()
    for team_id in (world.alpha.pk, uuid.uuid4(), inactive.pk):
        response = client_for(outsider).post(API, {**body, "team_id": str(team_id)}, format="json")
        assert response.status_code == 400
        messages.add(json.dumps(response.json()["error"]["details"]))
    assert len(messages) == 1  # absent, inactive and foreign teams answer identically
    probes = [r for r in caplog.records if getattr(r, "reason", None) == "team_unavailable"]
    assert [(r.operation, r.actor_id) for r in probes] == [("create", str(outsider.pk))] * 3
    assert str(world.alpha.pk) not in formatted_logs(caplog)
    for index, codes in enumerate(((VIEW,), (ADD,), (CHANGE, RETIRE, TRANSFER))):
        member = make_user(f"member{index}")
        grant(member, world.alpha, *codes)
        response = client_for(member).post(
            API, {**body, "team_id": str(world.alpha.pk)}, format="json"
        )
        assert response.status_code == 403, codes
    assert Asset.objects.count() == 1 and events("assets.asset_created").count() == created
    response = world.client.post(API, {**body, "team_id": str(world.alpha.pk)}, format="json")
    assert response.status_code == 201


# SEC-06 — every object action needs view plus its own permission (T-06, CWE-863)


def test_asset_actions_require_view_and_action_permission(world):
    blind = make_user("blind")
    grant(blind, world.alpha, CHANGE, RETIRE, TRANSFER)
    grant(blind, world.beta, VIEW, TRANSFER)
    viewer = make_user("viewer")
    grant(viewer, world.alpha, VIEW)
    grant(viewer, world.beta, VIEW, TRANSFER)
    for user in (blind, viewer):
        client = client_for(user)
        for method, path, body in mutation_requests(world.asset, 1, team_id=world.beta.pk)[1:]:
            response = send(client, method, path, body)
            assert response.status_code == 403, (user.username, path)
            assert "Web 01" not in response.content.decode()
    assert client_for(blind).get(detail(world.asset)).status_code == 403
    assert reload(world.asset).version == 1
    editor = make_user("editor")
    grant(editor, world.alpha, VIEW, CHANGE)
    response = client_for(editor).patch(
        detail(world.asset), {"version": 1, "name": "Edited"}, format="json"
    )
    assert response.status_code == 200 and response.json()["name"] == "Edited"


# SEC-07 — mutations recheck under locks; concurrent revocations serialize (T-07, CWE-367)


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize(
    ("change", "denied"),
    [
        ("remove_member", AssetNotFound),
        ("revoke_role", AssetForbidden),
        ("revoke_permission", AssetForbidden),
        ("deactivate_team", AssetNotFound),
    ],
)
def test_asset_mutation_serializes_with_concurrent_rbac_changes(change, denied):
    w = build_world()
    membership = Membership.objects.get(user=w.manager, team=w.alpha)
    writers = {
        "remove_member": lambda: teams.remove_member(OPERATOR, w.alpha.pk, w.manager.pk),
        "revoke_role": lambda: rbac.revoke_role(OPERATOR, membership.pk, w.role.pk),
        "revoke_permission": lambda: rbac.revoke_permission(OPERATOR, w.role.pk, CHANGE),
        "deactivate_team": lambda: teams.deactivate_team(OPERATOR, w.alpha.pk),
    }
    blocked, result = race(
        "rbac-writer",
        writers[change],
        lambda: services.update_asset(w.principal, w.asset.pk, version=1, changes={"name": "X"}),
    )
    assert blocked  # waited on the writer's row lock instead of using the old grant
    assert isinstance(result.get("error"), denied), result
    assert reload(w.asset).name == "Web 01" and not events("assets.asset_updated").exists()


@pytest.mark.django_db(transaction=True)
def test_rbac_revocation_waits_for_an_admitted_asset_mutation():
    w = build_world()
    blocked, result = race(
        "asset-writer",
        lambda: services.update_asset(w.principal, w.asset.pk, version=1, changes={"name": "Y"}),
        lambda: rbac.revoke_permission(OPERATOR, w.role.pk, CHANGE),
    )
    assert blocked  # the revocation waited for the authorized mutation to commit
    assert "error" not in result
    assert reload(w.asset).name == "Y"
    with pytest.raises(AssetForbidden):
        services.update_asset(w.principal, w.asset.pk, version=2, changes={"name": "Z"})


@pytest.mark.django_db(transaction=True)
def test_asset_mutation_serializes_with_account_disable():
    w = build_world()
    blocked, result = race(
        "account-writer",
        lambda: accounts.disable_user("manager"),
        lambda: services.update_asset(w.principal, w.asset.pk, version=1, changes={"name": "X"}),
    )
    assert blocked
    assert isinstance(result.get("error"), AssetNotFound), result
    assert reload(w.asset).name == "Web 01"


@pytest.mark.django_db(transaction=True)
def test_role_assignment_drift_aborts_asset_mutation(caplog):
    w = build_world()
    extra = rbac.create_role(OPERATOR, code="extra", name="Extra")
    membership = Membership.objects.get(user=w.manager, team=w.alpha)
    blocked, result = race(
        "rbac-writer",
        lambda: rbac.assign_role(OPERATOR, membership.pk, extra.pk),
        lambda: services.update_asset(w.principal, w.asset.pk, version=1, changes={"name": "X"}),
    )
    assert blocked
    assert isinstance(result.get("error"), StaleAsset), result
    assert any(getattr(r, "reason", None) == "role_drift" for r in caplog.records)
    assert reload(w.asset).name == "Web 01"


# SEC-08 — native flags, groups and non-user principals grant nothing (T-08, CWE-269)


def test_native_privileges_and_operator_cannot_manage_assets(world):
    root = make_user("root")
    root.is_staff = root.is_superuser = True
    root.save()
    native = Permission.objects.filter(content_type__app_label="assets")
    root.user_permissions.add(*native)
    group = Group.objects.create(name="asset-admins")
    group.permissions.add(*native)
    root.groups.add(group)
    assert root.has_perm(CHANGE)
    client = client_for(root)
    assert client.get(API).json()["count"] == 0
    assert client.get(detail(world.asset)).status_code == 404
    body = {"team_id": str(world.alpha.pk), "name": "X", "kind": "server"}
    assert client.post(API, body, format="json").status_code == 400
    teams.add_member(OPERATOR, world.alpha.pk, root.pk)  # membership alone grants nothing
    assert client.get(detail(world.asset)).status_code == 403
    for principal in (OPERATOR, SimpleNamespace(user_id=world.manager.pk), None):
        for call in (
            lambda p: services.create_asset(p, team_id=world.alpha.pk, name="X", kind="server"),
            lambda p: services.update_asset(p, world.asset.pk, version=1, changes={"name": "X"}),
            lambda p: services.retire_asset(p, world.asset.pk, version=1),
            lambda p: services.transfer_asset(p, world.asset.pk, version=1, team_id=world.beta.pk),
        ):
            with pytest.raises(AssetForbidden):
                call(principal)
    assert Asset.objects.count() == 1 and reload(world.asset).version == 1


# SEC-09 — explicit write fields, strict types (T-09, CWE-915)


def test_asset_writes_reject_unknown_and_read_only_fields_cwe_915(world):
    base = {"team_id": str(world.alpha.pk), "name": "New", "kind": "server"}
    for extra in (
        {"id": str(uuid.uuid4())},
        {"status": "retired"},
        {"version": 9},
        {"created_at": "2020-01-01T00:00:00Z"},
        {"is_superuser": True},
        {"team": "x"},
    ):
        response = world.client.post(API, {**base, **extra}, format="json")
        assert response.status_code == 400, extra
        assert set(response.json()["error"]["details"]) == set(extra)
    for extra in (
        {"team_id": str(world.beta.pk)},
        {"team": str(world.beta.pk)},
        {"status": "retired"},
        {"id": str(uuid.uuid4())},
        {"created_at": "2020"},
        {"updated_at": "2020"},
        {"owner": "x"},
    ):
        response = world.client.patch(detail(world.asset), {"version": 1, **extra}, format="json")
        assert response.status_code == 400, extra
    for bad in (
        {"name": 123},
        {"version": "1", "name": "X"},
        {"version": True, "name": "X"},
        {"ip_addresses": "10.0.0.1"},
        {"environment": 5},
        {"kind": ["server"]},
    ):
        response = world.client.patch(detail(world.asset), {"version": 1, **bad}, format="json")
        assert response.status_code == 400, bad
    bulk = world.client.post(API, [base, base], format="json")
    assert bulk.status_code == 400
    asset = reload(world.asset)
    assert (asset.team_id, asset.status, asset.version, Asset.objects.count()) == (
        world.alpha.pk,
        "active",
        1,
        1,
    )
    assert not events("assets.asset_updated").exists()


# SEC-10 — status only through transitions (T-10, CWE-841)


def test_asset_status_changes_only_through_transitions(world):
    grant(world.manager, world.beta, *ASSET_CODES)  # so transfer reaches the state check
    client, asset = world.client, world.asset
    assert (
        client.patch(detail(asset), {"version": 1, "status": "retired"}, format="json").status_code
        == 400
    )
    assert client.post(detail(asset, "restore/"), {"version": 1}, format="json").status_code == 409
    response = client.post(detail(asset, "retire/"), {"version": 1}, format="json")
    assert response.status_code == 200 and response.json()["status"] == "retired"
    for path, body in (
        (detail(asset, "retire/"), {"version": 2}),
        (detail(asset, "transfer/"), {"version": 2, "team_id": str(world.beta.pk)}),
    ):
        response = client.post(path, body, format="json")
        assert response.status_code == 409 and response.json()["error"]["code"] == "conflict"
    assert (
        client.patch(detail(asset), {"version": 2, "name": "X"}, format="json").status_code == 409
    )
    response = client.post(detail(asset, "restore/"), {"version": 2}, format="json")
    assert response.status_code == 200 and response.json()["version"] == 3
    assert events("assets.asset_retired").count() == events("assets.asset_restored").count() == 1


# SEC-11 — version compared under lock, before no-op detection (T-11, CWE-362)


def test_stale_asset_version_is_rejected_without_change(world):
    grant(world.manager, world.beta, *ASSET_CODES)  # so transfer reaches the version check
    services.update_asset(world.principal, world.asset.pk, version=1, changes={"name": "Second"})
    updates = events("assets.asset_updated").count()
    for method, path, body in mutation_requests(world.asset, 1, team_id=world.beta.pk)[1:]:
        response = send(world.client, method, path, body)
        assert response.status_code == 409, path
        assert response.json()["error"]["message"] == views.STALE
    asset = reload(world.asset)
    assert (asset.name, asset.version, asset.team_id) == ("Second", 2, world.alpha.pk)
    assert events("assets.asset_updated").count() == updates


def test_unchanged_patch_with_stale_version_returns_409(world):
    services.update_asset(world.principal, world.asset.pk, version=1, changes={"name": "Second"})
    same = {"name": "Second", "ip_addresses": ["10.0.0.5"]}
    assert (
        world.client.patch(detail(world.asset), {"version": 1, **same}, format="json").status_code
        == 409
    )
    response = world.client.patch(detail(world.asset), {"version": 2, **same}, format="json")
    assert response.status_code == 200 and response.json()["version"] == 2
    assert events("assets.asset_updated").count() == 1


# SEC-12 — one active name per team (T-12, CWE-694)


@pytest.mark.django_db(transaction=True)
def test_active_asset_name_is_unique_per_team_cwe_694():
    w = build_world()
    grant(w.manager, w.beta, *ASSET_CODES)
    body = {"team_id": str(w.alpha.pk), "name": "WEB 01", "kind": "server"}
    response = w.client.post(API, body, format="json")
    assert response.status_code == 409
    assert response.json()["error"]["message"] == views.NAME_TAKEN
    assert w.client.post(API, {**body, "team_id": str(w.beta.pk)}, format="json").status_code == 201
    other = services.create_asset(w.principal, team_id=w.alpha.pk, name="Other", kind="server")
    renamed = w.client.patch(detail(other), {"version": 1, "name": "web 01"}, format="json")
    assert renamed.status_code == 409
    services.retire_asset(w.principal, w.asset.pk, version=1)
    assert w.client.post(API, body, format="json").status_code == 201  # retired names are free

    barrier = threading.Barrier(2)

    def create():
        barrier.wait(5)
        return services.create_asset(w.principal, team_id=w.alpha.pk, name="Race", kind="server")

    first, second = in_thread("create-1", create), in_thread("create-2", create)
    for thread, _ in (first, second):
        thread.join(10)
    outcomes = sorted(
        type(result.get("error", result.get("value"))).__name__ for _, result in (first, second)
    )
    assert outcomes == ["Asset", "NameTaken"]
    assert Asset.objects.filter(team=w.alpha, name="Race").count() == 1


def test_restore_conflicts_with_active_asset_of_same_name(world):
    services.retire_asset(world.principal, world.asset.pk, version=1)
    newer = services.create_asset(
        world.principal, team_id=world.alpha.pk, name="WEB 01", kind="server"
    )
    response = world.client.post(detail(world.asset, "restore/"), {"version": 2}, format="json")
    assert response.status_code == 409
    assert response.json()["error"]["message"] == views.NAME_TAKEN
    old = reload(world.asset)
    assert (old.status, old.version) == ("retired", 2)
    assert reload(newer).status == "active" and not events("assets.asset_restored").exists()


def test_transfer_conflicts_with_destination_active_name(world):
    grant(world.manager, world.beta, *ASSET_CODES)
    services.create_asset(world.principal, team_id=world.beta.pk, name="web 01", kind="server")
    body = {"version": 1, "team_id": str(world.beta.pk)}
    response = world.client.post(detail(world.asset, "transfer/"), body, format="json")
    assert response.status_code == 409
    assert response.json()["error"]["message"] == views.NAME_TAKEN
    assert reload(world.asset).team_id == world.alpha.pk


def test_nfc_equivalent_names_collide_in_active_name_uniqueness(world):
    composed = services.create_asset(
        world.principal, team_id=world.alpha.pk, name="Caf\u00e9", kind="other"
    )
    assert reload(composed).name == "Caf\u00e9"
    for spelling in ("Cafe\u0301", "CAFE\u0301", "CAF\u00c9", "  caf\u00e9 "):
        response = world.client.post(
            API, {"team_id": str(world.alpha.pk), "name": spelling, "kind": "other"}, format="json"
        )
        assert response.status_code == 409, spelling


# SEC-13 — transfer needs transfer + view in both teams (T-13, CWE-863)


def test_transfer_requires_grants_in_source_and_destination(world):
    gamma = teams.create_team(OPERATOR, code="gamma", name="Gamma")  # inactive
    full = (VIEW, TRANSFER)
    cases = [
        ((VIEW,), full),
        ((TRANSFER,), full),
        (full, (VIEW,)),
        (full, (TRANSFER,)),
    ]
    for index, (source_codes, destination_codes) in enumerate(cases):
        user = make_user(f"mover{index}")
        grant(user, world.alpha, *source_codes)
        grant(user, world.beta, *destination_codes)
        body = {"version": 1, "team_id": str(world.beta.pk)}
        response = client_for(user).post(detail(world.asset, "transfer/"), body, format="json")
        assert response.status_code == 403, (source_codes, destination_codes)
    teams.add_member(OPERATOR, gamma.pk, world.manager.pk)
    messages = set()
    for team_id in (world.beta.pk, uuid.uuid4(), gamma.pk):
        body = {"version": 1, "team_id": str(team_id)}
        response = world.client.post(detail(world.asset, "transfer/"), body, format="json")
        assert response.status_code == 400
        messages.add(json.dumps(response.json()["error"]["details"]))
    assert len(messages) == 1
    same = world.client.post(
        detail(world.asset, "transfer/"),
        {"version": 1, "team_id": str(world.alpha.pk)},
        format="json",
    )
    assert same.status_code == 400
    assert (
        reload(world.asset).team_id == world.alpha.pk
        and not events("assets.asset_transferred").exists()
    )

    grant(world.manager, world.beta, *full)
    source_only = make_user("sourceonly")
    grant(source_only, world.alpha, *ASSET_CODES)
    destination = make_user("destination")
    grant(destination, world.beta, VIEW)
    assert client_for(destination).get(detail(world.asset)).status_code == 404
    body = {"version": 1, "team_id": str(world.beta.pk)}
    response = world.client.post(detail(world.asset, "transfer/"), body, format="json")
    assert response.status_code == 200 and response.json()["team"]["id"] == str(world.beta.pk)
    assert client_for(source_only).get(detail(world.asset)).status_code == 404
    assert client_for(destination).get(detail(world.asset)).status_code == 200
    event = events("assets.asset_transferred").get()
    assert event.changes == {
        "team_id": {"before": str(world.alpha.pk), "after": str(world.beta.pk)}
    }


@pytest.mark.django_db(transaction=True)
def test_transfer_serializes_with_destination_membership_removal():
    w = build_world()
    grant(w.manager, w.beta, VIEW, TRANSFER)
    blocked, result = race(
        "rbac-writer",
        lambda: teams.remove_member(OPERATOR, w.beta.pk, w.manager.pk),
        lambda: services.transfer_asset(w.principal, w.asset.pk, version=1, team_id=w.beta.pk),
    )
    assert blocked
    assert isinstance(result.get("error"), TeamUnavailable), result
    assert reload(w.asset).team_id == w.alpha.pk


# SEC-14 — mutation and audit commit together (T-14, CWE-778)


def test_failed_asset_audit_rolls_back_change(world):
    failing = mock.Mock(side_effect=AuditValidationError("audit rejected"))
    grant(world.manager, world.beta, *ASSET_CODES)
    requests = mutation_requests(world.asset, 1, team_id=world.beta.pk)
    restore = requests.pop(3)
    with mock.patch.object(rbac_events, "record_event", failing):
        for method, path, body in requests:
            assert send(world.client, method, path, body).status_code == 500, path
    asset = reload(world.asset)
    assert (asset.name, asset.version, asset.status, asset.team_id) == (
        "Web 01",
        1,
        "active",
        world.alpha.pk,
    )
    assert Asset.objects.count() == 1
    services.retire_asset(world.principal, world.asset.pk, version=1)
    with mock.patch.object(rbac_events, "record_event", failing):
        assert send(world.client, restore[0], restore[1], {"version": 2}).status_code == 500
    assert (reload(world.asset).status, reload(world.asset).version) == ("retired", 2)


# SEC-15 — exact audit allowlists; logs carry IDs only (T-15, CWE-532)


def test_asset_audit_and_logs_use_allowlists(world, caplog):
    caplog.set_level(logging.DEBUG)
    grant(world.manager, world.beta, *ASSET_CODES)
    canary = {
        "HTTP_AUTHORIZATION": "Bearer canary-token-6612",
        "HTTP_COOKIE": "x=canary-cookie-6612",
    }
    client = world.client
    created = client.post(
        API,
        {
            "team_id": str(world.alpha.pk),
            "name": "canary-name-6612",
            "kind": "server",
            "hostname": "canary-host-6612.example",
            "ip_addresses": ["192.0.2.66"],
            "os_product": "debian",
            "os_version": "canary-os-6612",
        },
        format="json",
        **canary,
    ).json()
    asset = SimpleNamespace(pk=created["id"])
    client.patch(detail(asset), {"version": 1, "criticality": "high"}, format="json", **canary)
    client.post(detail(asset, "retire/"), {"version": 2}, format="json", **canary)
    client.post(detail(asset, "restore/"), {"version": 3}, format="json", **canary)
    client.post(
        detail(asset, "transfer/"), {"version": 4, "team_id": str(world.beta.pk)}, format="json"
    )
    client.get(f"{API}?q=canary-search-6612")
    outsider = make_user("outsider")
    client_for(outsider).get(detail(asset))  # a denial
    allowlists = {
        "assets.asset_created": set(services.CREATED_FIELDS),
        "assets.asset_updated": set(services.MUTABLE_FIELDS),
        "assets.asset_retired": {"status"},
        "assets.asset_restored": {"status"},
        "assets.asset_transferred": {"team_id"},
    }
    recorded = AuditEvent.objects.filter(resource_id=created["id"])
    assert {event.action for event in recorded} == set(allowlists)
    for event in recorded:
        assert set(event.changes) <= allowlists[event.action], event.action
        assert event.metadata == {} and event.actor_id == world.manager.pk
        assert event.resource_type == "assets.asset" and event.outcome == "success"
        assert "version" not in event.changes
        assert "canary-token" not in json.dumps(event.changes) and "canary-cookie" not in str(event)
    assert recorded.get(action="assets.asset_updated").changes == {
        "criticality": {"before": None, "after": "high"}
    }
    logs = formatted_logs(caplog)
    for secret in (
        "canary-name",
        "canary-host",
        "canary-os",
        "192.0.2.66",
        "canary-search",
        "canary-token",
        "canary-cookie",
    ):
        assert secret not in logs, secret
    denial = next(r for r in caplog.records if r.getMessage() == "authorization_denied")
    assert (denial.operation, denial.actor_id) == ("read", str(outsider.pk))
    assert not hasattr(denial, "asset_id")


# SEC-16 — services validate every caller; the database backs them (T-16, CWE-20)


def test_asset_validation_is_enforced_by_service_and_database(world):
    invalid = [
        {"name": ""},
        {"name": "n" * 151},
        {"kind": "bogus"},
        {"hostname": "BAD HOST"},
        {"ip_addresses": ["10.0.0.1/24"]},
        {"ip_addresses": [f"10.0.1.{n}" for n in range(1, 18)]},
        {"environment": "prod"},
        {"criticality": "urgent"},
        {"os_version": "Linux\u202e"},
    ]
    for values in invalid:
        with pytest.raises(ValidationError) as caught:
            services.create_asset(
                world.principal, team_id=world.alpha.pk, **{"name": "X", "kind": "server", **values}
            )
        assert set(caught.value.message_dict) == set(values)
        with pytest.raises(ValidationError):
            services.update_asset(world.principal, world.asset.pk, version=1, changes=values)
    with pytest.raises(ValidationError):
        services.update_asset(world.principal, world.asset.pk, version=0, changes={"name": "X"})
    for bad_row, constraint in (
        ({"kind": "bogus"}, "asset_kind"),
        ({"hostname": "Bad Host"}, "asset_hostname"),
        ({"ip_addresses": [f"10.0.2.{n}" for n in range(1, 18)]}, "asset_ip_count"),
        ({"name": ""}, "asset_name_nonempty"),
        ({"status": "deleted"}, "asset_status"),
        ({"environment": "prod"}, "asset_environment"),
        ({"version": 0}, "asset_version"),
    ):
        with pytest.raises(IntegrityError, match=constraint), transaction.atomic():
            Asset.objects.create(team=world.alpha, **{"name": "Row", "kind": "server", **bad_row})
    assert Asset.objects.count() == 1


# SEC-17 — NFC, control/format characters, strict hostnames (T-17, CWE-451)


def test_asset_text_rejects_controls_and_bidi_overrides(world):
    base = {"team_id": str(world.alpha.pk), "kind": "server"}
    # A lone surrogate cannot be encoded by the test client; send the raw JSON escape instead.
    raw = json.dumps({**base, "name": "Web<S>Server"}).replace("<S>", "\\ud800")
    response = world.client.generic("POST", API, raw, content_type="application/json")
    assert response.status_code == 400 and "name" in response.json()["error"]["details"]
    for name in (
        "Web\u202eServer",
        "Web\u200bServer",
        "Web\u0000Server",
        "Web\nServer",
        "   ",
        "\u2066x",
    ):
        response = world.client.post(API, {**base, "name": name}, format="json")
        assert response.status_code == 400 and "name" in response.json()["error"]["details"], name
        response = world.client.post(
            API, {**base, "name": "Ok", "os_product": "debian", "os_version": name}, format="json"
        )
        assert response.status_code == 400 or name.strip() == "", name
    assert world.client.get(f"{API}?q=a%E2%80%AEb").status_code == 400
    created = world.client.post(API, {**base, "name": "  Web Server  "}, format="json").json()
    assert created["name"] == "Web Server"


def test_cross_script_confusable_names_remain_distinct_documented_residual(world):
    # Residual risk F-13 (accepted): NFC does not unify Latin "S" and Cyrillic "\u0405" (U+0405).
    base = {"team_id": str(world.alpha.pk), "kind": "server"}
    for name in ("Server", "\u0405erver"):
        assert world.client.post(API, {**base, "name": name}, format="json").status_code == 201
    names = [a["name"] for a in world.client.get(API).json()["results"]]
    assert "Server" in names and "\u0405erver" in names


# SEC-18 — canonical, deduplicated, exactly matched IPs (T-18, CWE-1289)


def test_ip_addresses_are_canonical_deduplicated_and_exactly_matched_cwe_1289(world):
    body = {
        "team_id": str(world.alpha.pk),
        "name": "Dual stack",
        "kind": "server",
        "ip_addresses": [
            "2001:db8:0:1:1:1:1:1",
            "::ffff:10.0.0.7",
            "2001:DB8:0:0:1:0:0:1",
            "10.0.0.7",
            "10.0.0.10",
        ],
    }
    created = world.client.post(API, body, format="json").json()
    expected = ["10.0.0.7", "10.0.0.10", "2001:db8::1:0:0:1", "2001:db8:0:1:1:1:1:1"]
    assert created["ip_addresses"] == expected
    asset = SimpleNamespace(pk=created["id"])
    assert world.client.get(detail(asset)).json()["ip_addresses"] == expected

    def found(query):
        return [a["name"] for a in world.client.get(f"{API}?{query}").json()["results"]]

    assert found("ip=10.0.0.7") == ["Dual stack"]
    assert found("ip=%3A%3Affff%3A10.0.0.7") == ["Dual stack"]  # ::ffff:10.0.0.7
    assert found("ip=2001%3ADB8%3A0%3A0%3A1%3A%3A1") == ["Dual stack"]  # 2001:DB8:0:0:1::1
    assert found("ip=10.0.0.5") == ["Web 01"]
    assert found("ip=10.0.0.70") == [] and found("ip=10.0.0.1") == []
    assert found("q=10.0.0.7") == []  # text search never matches addresses
    for bad in ("10.0.0", "10.0.0.0%2F24", "fe80%3A%3A1%25eth0", "127.0.0.1", "010.0.0.7"):
        assert world.client.get(f"{API}?ip={bad}").status_code == 400, bad
    for bad_list in (["10.0.0.5/32"], ["fe80::1%eth0"], [" 10.0.0.5"], ["::1"], [7]):
        response = world.client.patch(
            detail(asset), {"version": 1, "ip_addresses": bad_list}, format="json"
        )
        assert response.status_code == 400, bad_list
    reordered = list(reversed(body["ip_addresses"]))
    response = world.client.patch(
        detail(asset), {"version": 1, "ip_addresses": reordered}, format="json"
    )
    assert response.status_code == 200 and response.json()["version"] == 1  # a no-op
    assert not events("assets.asset_updated").exists()


# SEC-20 — allowlisted, bounded queries (T-20, CWE-400)


def test_asset_query_parameters_are_allowlisted_and_bounded(world):
    services.create_asset(world.principal, team_id=world.alpha.pk, name="50% off", kind="other")
    services.create_asset(world.principal, team_id=world.alpha.pk, name="500 off", kind="other")
    for query in (
        "user_id=1",
        "scope=organization",
        "ordering=name",
        "status=active&status=retired",
        "status=deleted",
        "team=not-a-uuid",
        "kind=bogus",
        "environment=prod",
        "criticality=x",
        f"q={'a' * 101}",
        "q=",
        "q=%20",
        "page=0",
        "page_size=-1",
        "q=a&q=b",
        "ip=10.0.0.1&ip=10.0.0.2",
    ):
        assert world.client.get(f"{API}?{query}").status_code == 400, query
    assert [a["name"] for a in world.client.get(f"{API}?q=%25").json()["results"]] == ["50% off"]
    assert [a["name"] for a in world.client.get(f"{API}?q=_").json()["results"]] == []
    response = world.client.get(f"{API}?page_size=1000")
    assert response.status_code == 200 and response.json()["count"] == 3
    assert len(world.client.get(f"{API}?page_size=2").json()["results"]) == 2
    assert world.client.get(f"{detail(world.asset)}?anything=1").status_code == 400


def test_asset_list_query_count_is_bounded(world):
    def queries():
        with CaptureQueriesContext(connection) as captured:
            assert world.client.get(f"{API}?page_size=100").status_code == 200
        return len(captured)

    one = queries()
    for index in range(24):
        services.create_asset(
            world.principal, team_id=world.alpha.pk, name=f"A{index}", kind="server"
        )
    assert queries() == one


# SEC-21 — CSRF on every mutation (T-21, CWE-352)


def browser_login(username="manager"):
    client = APIClient(enforce_csrf_checks=True)
    client.get("/api/v1/auth/csrf/")
    token = client.cookies["csrftoken"].value
    response = client.post(
        "/api/v1/auth/login/",
        {"username": username, "password": PASSWORD},
        format="json",
        HTTP_X_CSRFTOKEN=token,
    )
    assert response.status_code == 200
    return client


def test_asset_mutations_require_csrf_cwe_352(world):
    grant(world.manager, world.beta, *ASSET_CODES)
    client = browser_login()
    token = client.cookies["csrftoken"].value
    for method, path, body in mutation_requests(world.asset, 1, team_id=world.beta.pk):
        for header in ({}, {"HTTP_X_CSRFTOKEN": "x" * 64}):
            response = send(client, method, path, body, **header)
            assert response.status_code == 403, (path, header)
            assert response.json()["error"]["code"] == "permission_denied"
    assert reload(world.asset).version == 1 and Asset.objects.count() == 1
    response = send(
        client, "patch", detail(world.asset), {"version": 1, "name": "Csrf"}, HTTP_X_CSRFTOKEN=token
    )
    assert response.status_code == 200
    assert client.get(API).status_code == 200  # GET needs no token and changes nothing


# SEC-22 — no delete, replace or bulk (T-22, CWE-749)


def test_asset_delete_put_and_bulk_are_unavailable(world):
    client = browser_login()
    token = {"HTTP_X_CSRFTOKEN": client.cookies["csrftoken"].value}
    for method in ("delete", "put"):
        for path in (detail(world.asset), API):
            assert send(client, method, path, {"version": 1}, **token).status_code == 405
            assert send(client, method, path, {"version": 1}).status_code == 403
            assert send(APIClient(), method, path, {"version": 1}).status_code == 401
    bulk = [{"team_id": str(world.alpha.pk), "name": "B", "kind": "server"}]
    assert send(client, "post", API, bulk, **token).status_code == 400
    assert Asset.objects.count() == 1 and reload(world.asset).status == "active"


# SEC-23 — dependency failures fail closed (T-23, CWE-636)


def test_asset_dependency_errors_fail_closed(world):
    down = mock.Mock(side_effect=OperationalError("could not connect to server at 10.9.9.9"))
    for target, attribute in ((services, "can_access"), (rbac_events, "record_event")):
        with mock.patch.object(target, attribute, down):
            response = world.client.patch(
                detail(world.asset), {"version": 1, "name": "X"}, format="json"
            )
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "service_unavailable"
        assert "10.9.9.9" not in response.content.decode()
    with mock.patch("apps.assets.selectors.can_access", down):
        assert world.client.get(detail(world.asset)).status_code == 503
    assert reload(world.asset).name == "Web 01" and not events("assets.asset_updated").exists()


# SEC-24 — live RBAC state on every request; sessions preserved (T-24, CWE-863)


def test_asset_access_follows_live_rbac_state(world):
    client = browser_login()
    membership = Membership.objects.get(user=world.manager, team=world.alpha)
    assert client.get(detail(world.asset)).status_code == 200
    rbac.revoke_role(OPERATOR, membership.pk, world.role.pk)
    assert client.get(detail(world.asset)).status_code == 403
    assert client.get("/api/v1/auth/me/").status_code == 200  # the session survives
    rbac.assign_role(OPERATOR, membership.pk, world.role.pk)
    assert client.get(detail(world.asset)).status_code == 200
    teams.deactivate_team(OPERATOR, world.alpha.pk)
    assert client.get(detail(world.asset)).status_code == 404
    assert client.get(API).json()["count"] == 0
    preview = teams.preview_team_activation(OPERATOR, world.alpha.pk)
    teams.activate_team(OPERATOR, world.alpha.pk, preview.revision, preview.code)
    assert client.get(detail(world.asset)).status_code == 200
    teams.remove_member(OPERATOR, world.alpha.pk, world.manager.pk)
    assert client.get(detail(world.asset)).status_code == 404
    assert client.get("/api/v1/auth/me/").status_code == 200
    accounts.disable_user("manager")
    assert client.get(API).status_code == 401


# SEC-25 — services authorize and validate every caller (T-25, CWE-862)


def test_asset_services_authorize_and_validate_every_caller(world):
    outsider = make_user("outsider")
    grant(outsider, world.beta, *ASSET_CODES)
    viewer = make_user("viewer")
    grant(viewer, world.alpha, VIEW)
    for source in ("http", "command", "task", "sync"):
        with audit_source(source):
            with pytest.raises(AssetNotFound):
                services.update_asset(
                    UserPrincipal(outsider.pk), world.asset.pk, version=1, changes={"name": "X"}
                )
            with pytest.raises(AssetForbidden):
                services.retire_asset(UserPrincipal(viewer.pk), world.asset.pk, version=1)
            with pytest.raises(TeamUnavailable):
                services.create_asset(
                    UserPrincipal(outsider.pk), team_id=world.alpha.pk, name="X", kind="server"
                )
    with pytest.raises(ValidationError):
        services.update_asset(
            world.principal, world.asset.pk, version=1, changes={"status": "retired"}
        )
    source = inspect.getsource(services)
    for forbidden in (
        "request",
        "rest_framework",
        "serializer",
        "Source.",
        "current_context(",
        "is_staff",
        "is_superuser",
        "skip_auth",
    ):
        assert forbidden not in source, forbidden
    assert reload(world.asset).version == 1


# SEC-28 — targets resolved only by UUID (T-28, CWE-345)


def test_asset_mutations_resolve_targets_only_by_uuid(world):
    twin = services.create_asset(
        world.principal,
        team_id=world.alpha.pk,
        name="Twin",
        kind="server",
        hostname="web-01.example.com",
        ip_addresses=["10.0.0.5"],
    )
    for key in ("Web 01", "web-01.example.com", "10.0.0.5", str(world.asset.pk)[:8]):
        with pytest.raises(AssetNotFound):
            services.update_asset(world.principal, key, version=1, changes={"name": "X"})
    services.update_asset(world.principal, twin.pk, version=1, changes={"criticality": "high"})
    assert reload(world.asset).criticality is None and reload(twin).criticality == "high"
    for function in (
        services.update_asset,
        services.retire_asset,
        services.restore_asset,
        services.transfer_asset,
    ):
        assert list(inspect.signature(function).parameters)[:2] == ["principal", "asset_id"]
    routes = [str(p.pattern) for p in get_resolver("apps.assets.urls").url_patterns]
    assert all(route == "" or route.startswith("<uuid:pk>/") for route in routes)


# SEC-29 — ordered locks, bounded waits, fail closed (T-29, CWE-833)


@pytest.mark.django_db(transaction=True)
def test_opposite_transfers_do_not_deadlock():
    w = build_world()
    grant(w.manager, w.beta, *ASSET_CODES)
    left = services.create_asset(w.principal, team_id=w.alpha.pk, name="Left", kind="server")
    right = services.create_asset(w.principal, team_id=w.beta.pk, name="Right", kind="server")

    def move(asset, destination, barrier):
        barrier.wait(5)
        current = reload(asset)
        return services.transfer_asset(
            w.principal, asset.pk, version=current.version, team_id=destination
        )

    for round_number in range(5):
        barrier = threading.Barrier(2)
        forward = round_number % 2 == 0  # left and right always move in opposite directions
        to_left = w.beta.pk if forward else w.alpha.pk
        to_right = w.alpha.pk if forward else w.beta.pk
        a = in_thread("left", functools.partial(move, left, to_left, barrier))
        b = in_thread("right", functools.partial(move, right, to_right, barrier))
        for thread, result in (a, b):
            thread.join(15)
            assert "error" not in result, result
    assert events("assets.asset_transferred").count() == 10


@pytest.mark.django_db(transaction=True)
def test_asset_lock_timeout_fails_closed(monkeypatch, caplog):
    assert services.ASSET_LOCK_TIMEOUT == "5s"
    monkeypatch.setattr(services, "ASSET_LOCK_TIMEOUT", "300ms")  # same path, faster test
    w = build_world()
    held, release = threading.Event(), threading.Event()

    def hold():
        with transaction.atomic():
            Team.objects.select_for_update().get(pk=w.alpha.pk)
            held.set()
            assert release.wait(10)

    holder, _ = in_thread("holder", hold)
    try:
        assert held.wait(10)
        started = time.monotonic()
        response = w.client.patch(detail(w.asset), {"version": 1, "name": "X"}, format="json")
        elapsed = time.monotonic() - started
    finally:
        release.set()
        holder.join(10)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"
    assert elapsed < 3
    assert reload(w.asset).name == "Web 01" and not events("assets.asset_updated").exists()
    assert any(getattr(r, "reason", None) == "lock_timeout" for r in caplog.records)
    assert "teams_team" not in formatted_logs(caplog)


def test_asset_deadlock_fails_closed(world, caplog):
    def deadlock(*args, **kwargs):
        try:
            raise psycopg.errors.DeadlockDetected("deadlock detected")
        except psycopg.errors.DeadlockDetected as exc:
            raise OperationalError("deadlock detected") from exc

    with mock.patch.object(services, "_lock", deadlock):
        response = world.client.patch(
            detail(world.asset), {"version": 1, "name": "X"}, format="json"
        )
    assert response.status_code == 503
    assert reload(world.asset).name == "Web 01" and not events("assets.asset_updated").exists()
    assert any(getattr(r, "reason", None) == "deadlock" for r in caplog.records)


# SEC-30 — per-user write throttle, independent of reads (T-30, CWE-770)


def test_asset_mutations_are_rate_limited(world):
    noop = {"version": 1, "name": "Web 01"}
    statuses = [
        world.client.patch(detail(world.asset), noop, format="json").status_code for _ in range(61)
    ]
    assert statuses == [200] * 60 + [429]
    throttled = world.client.post(detail(world.asset, "retire/"), {"version": 1}, format="json")
    assert throttled.status_code == 429 and int(throttled["Retry-After"]) > 0
    assert reload(world.asset).status == "active"
    other = make_user("other")
    grant(other, world.alpha, *ASSET_CODES)
    assert client_for(other).patch(detail(world.asset), noop, format="json").status_code == 200


def test_asset_read_and_write_throttles_are_independent(world):
    for _ in range(70):
        assert world.client.get(API).status_code == 200
    noop = {"version": 1, "name": "Web 01"}
    statuses = [
        world.client.patch(detail(world.asset), noop, format="json").status_code for _ in range(61)
    ]
    assert statuses == [200] * 60 + [429]  # 70 reads consumed none of the write budget
    assert world.client.get(API).status_code == 200
    assert world.client.get(detail(world.asset)).status_code == 200


def test_asset_write_throttle_fails_closed_when_store_unavailable(world):
    unavailable = mock.Mock()
    unavailable.get.side_effect = RedisConnectionError("cache down")
    with mock.patch.object(SimpleRateThrottle, "cache", unavailable):
        response = world.client.patch(
            detail(world.asset), {"version": 1, "name": "X"}, format="json"
        )
    assert response.status_code == 503
    assert reload(world.asset).name == "Web 01"


# SEC-31 — only the identified name violation is a 409; nothing else leaks (T-31, CWE-209)


def test_only_active_name_violation_maps_to_409(world, monkeypatch):
    duplicate = {"team_id": str(world.alpha.pk), "name": "Web 01", "kind": "server"}
    assert world.client.post(API, duplicate, format="json").status_code == 409
    monkeypatch.setattr(services, "ACTIVE_NAME_CONSTRAINT", "some_other_constraint")
    assert world.client.post(API, duplicate, format="json").status_code == 500
    monkeypatch.undo()
    monkeypatch.setitem(services._CLEANERS, "kind", lambda value: value)  # bypass to reach the DB
    response = world.client.post(
        API, {**duplicate, "name": "Fresh", "kind": "bogus"}, format="json"
    )
    assert response.status_code == 500
    assert Asset.objects.count() == 1


def test_unrelated_integrity_errors_return_generic_500_without_database_details(
    world, monkeypatch, caplog
):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setitem(services._CLEANERS, "hostname", lambda value: value)
    body = {
        "team_id": str(world.alpha.pk),
        "name": "canary-name-4471",
        "kind": "server",
        "hostname": "BAD HOST canary-row-4471",
    }
    response = world.client.post(API, body, format="json")
    assert response.status_code == 500
    error = response.json()["error"]
    assert (error["code"], error["message"]) == ("server_error", "Internal server error.")
    text = response.content.decode()
    for leaked in ("asset_hostname", "Failing row", "canary", "INSERT", "assets_asset"):
        assert leaked not in text, leaked
    logs = formatted_logs(caplog)
    for leaked in ("Failing row", "canary-row", "canary-name", "INSERT INTO", "DETAIL"):
        assert leaked not in logs, leaked
    integrity = [r for r in caplog.records if r.getMessage() == "asset_integrity_error"]
    assert [(r.operation, r.constraint) for r in integrity] == [("create", "asset_hostname")]
    assert Asset.objects.count() == 1


def test_asset_error_responses_use_fixed_messages_cwe_209(world, caplog):
    """Responses come from fixed adapter text per error type, never from exception content; denial
    logs carry the asset ID the domain read from the database, never the request's value."""
    canary = "internal-detail-canary-5521"
    cases = [
        (StaleAsset(canary), 409, views.STALE),
        (NameTaken(canary), 409, views.NAME_TAKEN),
        (InvalidState(canary), 409, views.INVALID_STATE),
        (TeamUnavailable(canary), 400, None),
        (AssetForbidden(world.asset.pk), 403, None),
    ]
    for error, status, message in cases:
        with mock.patch.object(services, "update_asset", side_effect=error):
            response = world.client.patch(
                detail(world.asset), {"version": 1, "name": "X"}, format="json"
            )
        assert response.status_code == status, type(error).__name__
        assert canary not in response.content.decode()
        if message:
            assert response.json()["error"]["message"] == message
    body = world.client.post(
        API, {"team_id": str(uuid.uuid4()), "name": "X", "kind": "server"}, format="json"
    ).json()
    assert body["error"]["details"] == {"team_id": [views.TEAM_UNAVAILABLE]}
    denials = [r for r in caplog.records if r.getMessage() == "authorization_denied"]
    assert [getattr(r, "asset_id", None) for r in denials if r.operation == "update"] == [
        None,
        str(world.asset.pk),
    ]
    assert canary not in formatted_logs(caplog)


def test_request_keys_cannot_bind_adapter_parameters():
    """Request data reaches only the domain call, never the adapter's operation label."""
    assert list(inspect.signature(views.AssetAPIView.run).parameters) == [
        "self",
        "operation",
        "call",
    ]
    world = build_world()
    for key in ("operation", "function"):
        body = {"team_id": str(world.alpha.pk), "name": "X", "kind": "server", key: "create"}
        response = world.client.post(API, body, format="json")
        assert response.status_code == 400
        assert set(response.json()["error"]["details"]) == {key}
    with pytest.raises(
        ValidationError
    ) as caught:  # the service refuses it too, if it ever got there
        services.create_asset(
            world.principal, team_id=world.alpha.pk, name="X", kind="server", operation="create"
        )
    assert set(caught.value.message_dict) == {"operation"}
    assert Asset.objects.count() == 1


# Functional contract


def test_asset_crud_contract(world):
    client = world.client
    body = {
        "team_id": str(world.alpha.pk),
        "name": "Mail",
        "kind": "workstation",
        "hostname": "MAIL.Example.com",
        "ip_addresses": ["192.0.2.10"],
        "os_product": "debian",
        "os_version": "13",
        "environment": "production",
        "criticality": "critical",
    }
    response = client.post(API, body, format="json")
    assert response.status_code == 201
    asset = response.json()
    assert set(asset) == {
        "id",
        "team",
        "name",
        "kind",
        "hostname",
        "ip_addresses",
        "operating_system",
        "os_product",
        "os_version",
        "os_label",
        "environment",
        "criticality",
        "status",
        "version",
        "created_at",
        "updated_at",
    }
    os_fields = ("os_product", "os_version", "os_label", "operating_system")
    assert tuple(asset[key] for key in os_fields) == ("debian", "13", "Debian", "")
    assert asset["team"] == {"id": str(world.alpha.pk), "code": "alpha", "name": "Alpha"}
    assert (asset["hostname"], asset["status"], asset["version"]) == (
        "mail.example.com",
        "active",
        1,
    )
    page = client.get(API).json()
    assert set(page) == {"count", "next", "previous", "results"}
    assert [a["name"] for a in page["results"]] == ["Mail", "Web 01"]
    assert client.get(f"{API}?kind=workstation&criticality=critical").json()["count"] == 1
    target = SimpleNamespace(pk=asset["id"])
    updated = client.patch(
        detail(target), {"version": 1, "environment": None, "hostname": ""}, format="json"
    ).json()
    assert (updated["environment"], updated["hostname"], updated["version"]) == (None, "", 2)
    assert client.get(detail(target)).json() == updated
    unchanged = client.patch(detail(target), {"version": 2, "kind": "workstation"}, format="json")
    assert unchanged.status_code == 200 and unchanged.json()["version"] == 2
    assert events("assets.asset_updated").count() == 1
    assert client.patch(detail(target), {"version": 2}, format="json").status_code == 400


# SEC-27 — catalog extension without weakening the fail-closed action guard (T-27, CWE-863)


def test_asset_catalog_codes_resolve_only_their_own_permission():
    team = make_team("alpha")
    for code in ASSET_CODES:
        user = make_user(f"user-{code.split('.')[1]}")
        role = grant(user, team, code)
        assert [p.natural_key() for p in role.permissions.all()] == [SUPPORTED_PERMISSIONS[code]]
        assert catalog_action(code) == code.split(".")[1].split("_")[0]
        assert allowed(user, team, code)
        assert not [other for other in ASSET_CODES if other != code and allowed(user, team, other)]
        assert not allowed(user, team, "teams.view_team")
        entries = client_for(user).get("/api/v1/rbac/me/").json()["results"]
        assert [entry["permissions"] for entry in entries] == [[code]]


def test_catalog_action_mismatch_fails_closed():
    team = make_team("alpha")
    user = make_user("holder")
    grant(user, team, "teams.view_team", *ASSET_CODES)
    principal = UserPrincipal(user.pk)
    for code in ASSET_CODES:
        assert allowed(user, team, code)
        for action in ("view", "add", "change", "retire", "transfer", "delete", "*", ""):
            if action != catalog_action(code):
                assert not can_access(principal, code, team_id=team.pk, action=action)
        assert not allowed(user, team, code, scope_type="organization")
    # The default action is "view": a write code used without its action never authorizes.
    assert not can_access(principal, CHANGE, team_id=team.pk)
    assert not can_access(principal, "teams.view_team", team_id=team.pk, action="change")
    role = rbac.create_role(OPERATOR, code="probe", name="Probe")
    for unknown in ("assets.delete_asset", "assets.*", "*", "assets.view_assets"):
        with pytest.raises(RbacError, match="Unsupported permission"):
            rbac.grant_permission(OPERATOR, role.pk, unknown)
        assert not can_access(principal, unknown, team_id=team.pk)
    assert not role.permissions.exists()
