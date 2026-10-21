"""SPEC-0004 / TM-0004 adversarial acceptance contracts (SEC-01 through SEC-26)."""

import inspect
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from unittest.mock import patch

import pytest
from django.contrib.auth.models import Group, Permission
from django.contrib.sessions.models import Session
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import OperationalError, close_old_connections, connection
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from apps.accounts import services as accounts
from apps.accounts.models import User
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from apps.audit.types import Actor
from apps.rbac import catalog, events, policy
from apps.rbac import services as rbac
from apps.rbac.catalog import catalog_permissions
from apps.rbac.exceptions import AdministrationDenied, RbacError
from apps.rbac.models import Role, RoleAssignment
from apps.rbac.principals import UserPrincipal, infrastructure_operator
from apps.rbac.selectors import can_access
from apps.teams import services as teams
from apps.teams.models import Membership, Team

pytestmark = pytest.mark.django_db(transaction=True)
OPERATOR = infrastructure_operator()
PERMISSION = "teams.view_team"


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


def activate(team):
    preview = teams.preview_team_activation(OPERATOR, team.pk)
    return teams.activate_team(OPERATOR, team.pk, preview.revision, preview.code)


def allowed(user, team, **kwargs):
    return can_access(UserPrincipal(user.pk), PERMISSION, team_id=team.pk, **kwargs)


def configuration():
    return [
        list(model.objects.order_by("pk").values())
        for model in (Team, Membership, Role, RoleAssignment, Role.permissions.through)
    ]


def test_rbac_endpoints_require_session(rbac_setup):
    _, team, _, _, _ = rbac_setup
    for path in ("/api/v1/rbac/me/", "/api/v1/teams/", f"/api/v1/teams/{team.pk}/"):
        response = APIClient().get(path)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "not_authenticated"
    from django.conf import settings

    assert settings.REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] == [
        "apps.core.api.permissions.DenyAll"
    ]


def test_disabled_account_has_no_effective_access(rbac_setup):
    user, team, _, _, client = rbac_setup
    assert allowed(user, team)
    User.objects.filter(pk=user.pk).update(is_active=False)
    assert user.is_active  # Deliberately stale loaded identity.
    assert not allowed(user, team)
    for path in ("/api/v1/rbac/me/", "/api/v1/teams/", f"/api/v1/teams/{team.pk}/"):
        assert client.get(path).status_code == 401


def test_permission_from_team_a_cannot_authorize_team_b(rbac_setup):
    user, alpha, _, _, client = rbac_setup
    beta = teams.create_team(OPERATOR, code="beta", name="Beta")
    teams.add_member(OPERATOR, beta.pk, user.pk)
    activate(beta)
    assert allowed(user, alpha)
    assert not allowed(user, beta)
    assert client.get(f"/api/v1/teams/{beta.pk}/").status_code == 403
    assert [row["id"] for row in client.get("/api/v1/teams/").json()["results"]] == [str(alpha.pk)]


def test_team_identifier_swap_returns_404_cwe_639(rbac_setup):
    _, team, _, _, client = rbac_setup
    hidden = teams.create_team(OPERATOR, code="hidden", name="Hidden")
    activate(hidden)
    assert client.get(f"/api/v1/teams/{team.pk}/").status_code == 200
    hidden_response = client.get(f"/api/v1/teams/{hidden.pk}/")
    absent_response = client.get(f"/api/v1/teams/{uuid.uuid4()}/")
    assert hidden_response.status_code == absent_response.status_code == 404
    assert hidden_response.json()["error"]["message"] == absent_response.json()["error"]["message"]
    assert client.get("/api/v1/teams/not-a-uuid/").status_code == 404


def test_team_disclosure_policy_and_counts(rbac_setup):
    user, team, member, role, client = rbac_setup
    hidden = teams.create_team(OPERATOR, code="hidden", name="Hidden")
    activate(hidden)
    assert client.get("/api/v1/teams/").json()["count"] == 1
    rbac.revoke_role(OPERATOR, member.pk, role.pk)
    assert client.get("/api/v1/teams/").json()["count"] == 0
    assert client.get(f"/api/v1/teams/{team.pk}/").status_code == 403
    assert client.get(f"/api/v1/teams/{hidden.pk}/").status_code == 404
    assert not allowed(user, team)


def test_native_auth_privileges_do_not_bypass_rbac(rbac_setup):
    user, team, member, role, client = rbac_setup
    rbac.revoke_role(OPERATOR, member.pk, role.pk)
    permission = catalog_permissions().get()
    user.is_staff = user.is_superuser = True
    user.save()
    user.user_permissions.add(permission)
    group = Group.objects.create(name="admin")
    group.permissions.add(permission)
    user.groups.add(group)
    user._perm_cache = {PERMISSION}
    assert user.has_perm(PERMISSION)
    assert not allowed(user, team)
    assert client.get(f"/api/v1/teams/{team.pk}/").status_code == 403


@pytest.mark.parametrize(
    "principal", [True, {"is_operator": True}, Actor.system("trilha-operator"), None]
)
def test_external_claims_and_audit_source_cannot_create_operator_authority(principal):
    before = configuration()
    for source in ("command", "http", "task", "sync"):
        with audit_source(source), pytest.raises(AdministrationDenied):
            teams.create_team(principal, code="forged", name="Forged")
    assert configuration() == before


def test_user_context_cannot_administer_grants(rbac_setup):
    user, team, member, role, _ = rbac_setup
    principal = UserPrincipal(user.pk)
    calls = [
        lambda: teams.create_team(principal, code="evil", name="Evil"),
        lambda: teams.update_team(principal, team.pk, name="Evil"),
        lambda: teams.deactivate_team(principal, team.pk),
        lambda: teams.preview_team_activation(principal, team.pk),
        lambda: teams.activate_team(principal, team.pk, (), team.code),
        lambda: teams.add_member(principal, team.pk, user.pk),
        lambda: teams.remove_member(principal, team.pk, user.pk),
        lambda: rbac.create_role(principal, code="evil", name="Evil"),
        lambda: rbac.update_role(principal, role.pk, name="Evil"),
        lambda: rbac.grant_permission(principal, role.pk, PERMISSION),
        lambda: rbac.revoke_permission(principal, role.pk, PERMISSION),
        lambda: rbac.assign_role(principal, member.pk, role.pk),
        lambda: rbac.revoke_role(principal, member.pk, role.pk),
    ]
    before = configuration()
    success_count = AuditEvent.objects.filter(outcome="success").count()
    for call in calls:
        with pytest.raises(AdministrationDenied):
            call()
    assert configuration() == before
    assert AuditEvent.objects.filter(outcome="success").count() == success_count
    assert AuditEvent.objects.filter(action="rbac.administration_denied").count() == len(calls)


def concurrent_calls(call):
    barrier = threading.Barrier(2)

    def attempt():
        close_old_connections()
        try:
            with audit_source("command"):
                barrier.wait(timeout=10)
                try:
                    call()
                    return "success"
                except RbacError:
                    return "conflict"
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        return sorted(pool.map(lambda _: attempt(), range(2)))


def test_concurrent_membership_and_assignment_are_unique(user):
    team = teams.create_team(OPERATOR, code="race", name="Race")
    assert concurrent_calls(lambda: teams.add_member(OPERATOR, team.pk, user.pk)) == [
        "conflict",
        "success",
    ]
    member = Membership.objects.get(team=team, user=user)
    role = rbac.create_role(OPERATOR, code="race", name="Race")
    assert concurrent_calls(lambda: rbac.assign_role(OPERATOR, member.pk, role.pk)) == [
        "conflict",
        "success",
    ]
    assert Membership.objects.filter(team=team, user=user).count() == 1
    assert RoleAssignment.objects.filter(membership=member, role=role).count() == 1
    for action in ("teams.membership_created", "rbac.role_assigned"):
        assert AuditEvent.objects.filter(action=action).count() == 1


@pytest.mark.parametrize("change", ["permission", "assignment", "membership", "team", "account"])
def test_reused_actor_observes_committed_revocation(rbac_setup, change):
    user, team, member, role, _ = rbac_setup
    principal = UserPrincipal(user.pk)
    user._perm_cache = {PERMISSION}
    assert can_access(principal, PERMISSION, team_id=team.pk)
    if change == "permission":
        rbac.revoke_permission(OPERATOR, role.pk, PERMISSION)
    elif change == "assignment":
        rbac.revoke_role(OPERATOR, member.pk, role.pk)
    elif change == "membership":
        teams.remove_member(OPERATOR, team.pk, user.pk)
    elif change == "team":
        teams.deactivate_team(OPERATOR, team.pk)
    else:
        accounts.disable_user(user.username)
    assert not can_access(principal, PERMISSION, team_id=team.pk)


def test_rbac_change_preserves_session_but_changes_access(rbac_setup):
    user, team, member, role, _ = rbac_setup
    client = APIClient()
    client.force_login(user)
    original = list(Session.objects.values())
    cookie = client.cookies["sessionid"].value
    assert client.get(f"/api/v1/teams/{team.pk}/").status_code == 200
    rbac.revoke_role(OPERATOR, member.pk, role.pk)
    assert list(Session.objects.values()) == original
    assert client.get(f"/api/v1/teams/{team.pk}/").status_code == 403
    assert client.get("/api/v1/auth/me/").status_code == 200
    assert client.cookies["sessionid"].value == cookie
    rbac.assign_role(OPERATOR, member.pk, role.pk)
    assert client.get(f"/api/v1/teams/{team.pk}/").status_code == 200
    teams.deactivate_team(OPERATOR, team.pk)
    assert client.get(f"/api/v1/teams/{team.pk}/").status_code == 404
    activate(team)
    assert client.get(f"/api/v1/teams/{team.pk}/").status_code == 200
    assert list(Session.objects.values()) == original


def test_rbac_preserves_authentication_sensitive_session_revocation(rbac_setup):
    user, team, _, _, _ = rbac_setup
    client = APIClient()
    client.force_login(user)
    cookie = client.cookies["sessionid"].value
    accounts.disable_user(user.username)
    accounts.enable_user(user.username)
    user.refresh_from_db()
    user.set_password("replacement-passphrase-for-tests")
    user.save()
    assert allowed(user, team)  # Retained grant cannot revive old authentication.
    client.cookies["sessionid"] = cookie
    assert client.get("/api/v1/rbac/me/").status_code == 401
    assert client.get("/api/v1/auth/me/").status_code == 401


def test_failed_rbac_audit_rolls_back_change(rbac_setup, monkeypatch):
    user, team, member, role, _ = rbac_setup
    before = configuration()
    count = AuditEvent.objects.count()
    real = events.record_event

    def fail_after_revocation(**kwargs):
        real(**kwargs)
        raise RuntimeError("audit dependency failure")

    monkeypatch.setattr(events, "record_event", fail_after_revocation)
    for call in (
        lambda: teams.remove_member(OPERATOR, team.pk, user.pk),
        lambda: teams.deactivate_team(OPERATOR, team.pk),
        lambda: rbac.revoke_permission(OPERATOR, role.pk, PERMISSION),
        lambda: teams.create_team(OPERATOR, code="rollback", name="Rollback"),
        lambda: rbac.create_role(OPERATOR, code="rollback", name="Rollback"),
    ):
        with pytest.raises(RuntimeError):
            call()
        assert configuration() == before
        assert AuditEvent.objects.count() == count
    assert RoleAssignment.objects.filter(membership=member).exists()


def test_denied_administration_audit_survives_rollback(rbac_setup):
    user, team, _, _, _ = rbac_setup
    before = configuration()
    with pytest.raises(AdministrationDenied):
        teams.remove_member(UserPrincipal(user.pk), team.pk, user.pk)
    assert not connection.in_atomic_block
    event = AuditEvent.objects.get(action="rbac.administration_denied")
    assert event.outcome == "denied" and event.actor_id == user.pk
    assert event.metadata == {"operation": "remove_member", "reason": "not_allowed"}
    assert event.changes == {} and event.resource_id == ""
    assert configuration() == before


def test_rbac_audit_allowlists_and_secret_canaries(rbac_setup, caplog):
    user, team, _, role, _ = rbac_setup
    teams.update_team(OPERATOR, team.pk, name="Renamed")
    rbac.update_role(OPERATOR, role.pk, name="Renamed")
    teams.deactivate_team(OPERATOR, team.pk)
    activate(team)
    rbac.revoke_permission(OPERATOR, role.pk, PERMISSION)
    rbac.grant_permission(OPERATOR, role.pk, PERMISSION)
    teams.remove_member(OPERATOR, team.pk, user.pk)
    expected = {
        "teams.team_created": ({"code", "name", "is_active"}, set()),
        "teams.team_updated": ({"name"}, set()),
        "teams.team_deactivated": ({"is_active"}, set()),
        "teams.team_activated": ({"is_active"}, {"membership_count", "role_assignment_count"}),
        "teams.membership_created": ({"user_id", "team_id"}, set()),
        "teams.membership_removed": ({"user_id", "team_id"}, set()),
        "rbac.role_created": ({"code", "name"}, set()),
        "rbac.role_updated": ({"name"}, set()),
        "rbac.permission_granted": (set(), {"permission_code"}),
        "rbac.permission_revoked": (set(), {"permission_code"}),
        "rbac.role_assigned": (
            set(),
            {"membership_id", "user_id", "team_id", "role_id", "scope_type", "scope_id"},
        ),
        "rbac.role_revoked": (
            set(),
            {"membership_id", "user_id", "team_id", "role_id", "scope_type", "scope_id"},
        ),
    }
    for event in AuditEvent.objects.all():
        changes, metadata = expected[event.action]
        assert set(event.changes) == changes
        assert set(event.metadata) == metadata
        assert event.source == "command" and event.actor_label == "trilha-operator"
        if "scope_id" in event.metadata:
            assert event.metadata["scope_id"] == event.metadata["team_id"]
    stored = json.dumps(list(AuditEvent.objects.values()), default=str) + caplog.text
    assert user.password not in stored
    for excluded in (
        "expected_revision",
        "confirmation_code",
        "sessionid",
        "correct-horse-battery-staple",
    ):
        assert excluded not in stored


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_http_writes_cannot_mass_assign_grants(rbac_setup, method):
    _, team, _, _, client = rbac_setup
    before = configuration()
    for path in ("/api/v1/rbac/me/", "/api/v1/teams/", f"/api/v1/teams/{team.pk}/"):
        assert (
            getattr(client, method)(
                path, {"is_operator": True, "is_active": True, "roles": ["admin"]}, format="json"
            ).status_code
            == 405
        )
    assert configuration() == before


def test_unsupported_bulk_cannot_modify_grants(rbac_setup):
    _, team, _, _, client = rbac_setup
    before = configuration()
    assert (
        client.post("/api/v1/teams/bulk/", [{"team_id": str(team.pk)}], format="json").status_code
        == 404
    )
    assert client.post("/api/v1/rbac/assignments/", {"bulk": []}, format="json").status_code == 404
    assert configuration() == before


def test_team_pagination_and_query_counts_are_bounded(rbac_setup):
    user, _, _, role, client = rbac_setup

    def query_count():
        with CaptureQueriesContext(connection) as queries:
            response = client.get("/api/v1/rbac/me/?page_size=1000")
        assert response.status_code == 200
        return len(queries), response.json()

    small, _ = query_count()
    for number in range(25):
        team = teams.create_team(OPERATOR, code=f"team-{number:02}", name="Team")
        member = teams.add_member(OPERATOR, team.pk, user.pk)
        rbac.assign_role(OPERATOR, member.pk, role.pk)
        activate(team)
    large, result = query_count()
    assert small == large and large <= 6
    assert len(result["results"]) == result["count"] == 26
    assert len(client.get("/api/v1/teams/").json()["results"]) == 25
    assert len(client.get("/api/v1/teams/?page_size=1000").json()["results"]) <= 100


def test_rbac_dependency_errors_fail_closed(rbac_setup, monkeypatch):
    _, _, _, _, client = rbac_setup

    def unavailable(*args, **kwargs):
        raise OperationalError("internal database canary")

    monkeypatch.setattr("apps.rbac.policy.users", unavailable)
    response = client.get("/api/v1/rbac/me/")
    assert response.status_code == 503
    assert "internal database canary" not in response.content.decode()
    with patch(
        "apps.rbac.management.commands.rbac_create_role.create_role", side_effect=OperationalError
    ):
        with pytest.raises(CommandError):
            call_command("rbac_create_role", "blocked", name="Blocked", stdout=StringIO())
    assert not Role.objects.filter(code="blocked").exists()


def test_access_response_is_self_only(rbac_setup):
    user, team, member, role, client = rbac_setup
    other = User.objects.create_user(username="other")
    teams.add_member(OPERATOR, team.pk, other.pk)
    response = client.get("/api/v1/rbac/me/")
    assert response.status_code == 200
    row = response.json()["results"][0]
    assert set(row) == {"membership_id", "team", "roles", "permissions"}
    assert row["membership_id"] == str(member.pk)
    assert row["roles"] == [{"id": str(role.pk), "code": role.code, "name": role.name}]
    assert row["permissions"] == [PERMISSION]
    assert str(other.pk) not in response.content.decode()
    assert str(user.pk) not in response.content.decode()
    for query in (f"user_id={other.pk}", "scope=organization", "is_operator=true"):
        assert client.get("/api/v1/rbac/me/?" + query).status_code == 400


def test_reactivation_and_rejoining_have_distinct_grant_behavior(rbac_setup):
    user, team, member, role, _ = rbac_setup
    teams.deactivate_team(OPERATOR, team.pk)
    assert not allowed(user, team)
    activate(team)
    assert allowed(user, team)
    teams.remove_member(OPERATOR, team.pk, user.pk)
    new = teams.add_member(OPERATOR, team.pk, user.pk)
    assert new.pk != member.pk
    assert not RoleAssignment.objects.filter(membership=new).exists()
    assert not allowed(user, team)
    assert AuditEvent.objects.filter(action="rbac.role_revoked").count() == 1
    assert AuditEvent.objects.filter(action="teams.membership_removed").count() == 1
    rbac.assign_role(OPERATOR, new.pk, role.pk)
    User.objects.filter(pk=user.pk).update(is_active=False)
    teams.deactivate_team(OPERATOR, team.pk)
    activate(team)
    assert not allowed(user, team)


def test_reactivation_requires_confirmed_restoration_counts(rbac_setup, monkeypatch):
    _, team, _, _, _ = rbac_setup
    teams.deactivate_team(OPERATOR, team.pk)
    count = AuditEvent.objects.filter(action="teams.team_activated").count()
    preview = teams.preview_team_activation(OPERATOR, team.pk)
    with pytest.raises(RbacError):
        teams.activate_team(OPERATOR, team.pk, preview.revision, "")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(CommandError):
        call_command("teams_activate", "alpha", stdout=StringIO())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    for answer in ("yes", "wrong"):
        with patch("builtins.input", return_value=answer), pytest.raises(CommandError):
            call_command("teams_activate", "alpha", stdout=StringIO())
    with patch("builtins.input", side_effect=EOFError), pytest.raises(CommandError):
        call_command("teams_activate", "alpha", stdout=StringIO())
    assert AuditEvent.objects.filter(action="teams.team_activated").count() == count
    output = StringIO()

    def confirm(prompt):
        assert not connection.in_atomic_block
        assert prompt == "Type alpha to activate: "
        return "alpha"

    with patch("builtins.input", side_effect=confirm):
        call_command("teams_activate", "alpha", stdout=output)
    assert "1 memberships and 1 role assignments" in output.getvalue()
    assert "disabled accounts remain denied" in output.getvalue()
    event = AuditEvent.objects.filter(action="teams.team_activated").latest("occurred_at")
    assert event.metadata == {"membership_count": 1, "role_assignment_count": 1}


@pytest.mark.parametrize("change", ["membership", "assignment", "permission"])
def test_reactivation_aborts_after_configuration_changes(rbac_setup, change):
    user, team, member, role, _ = rbac_setup
    teams.deactivate_team(OPERATOR, team.pk)
    preview = teams.preview_team_activation(OPERATOR, team.pk)
    if change == "membership":
        teams.remove_member(OPERATOR, team.pk, user.pk)
        member = teams.add_member(OPERATOR, team.pk, user.pk)
        rbac.assign_role(OPERATOR, member.pk, role.pk)
    elif change == "assignment":
        rbac.revoke_role(OPERATOR, member.pk, role.pk)
        rbac.assign_role(OPERATOR, member.pk, role.pk)
    else:
        rbac.revoke_permission(OPERATOR, role.pk, PERMISSION)
        rbac.grant_permission(OPERATOR, role.pk, PERMISSION)
    count = AuditEvent.objects.filter(action="teams.team_activated").count()
    with pytest.raises(RbacError):
        teams.activate_team(OPERATOR, team.pk, preview.revision, team.code)
    team.refresh_from_db()
    assert not team.is_active
    assert AuditEvent.objects.filter(action="teams.team_activated").count() == count


def test_unknown_permission_and_scope_fail_closed(rbac_setup):
    user, team, _, role, _ = rbac_setup
    for code in ("*", "auth.change_user", "teams.delete_team", "bogus.view_team"):
        with pytest.raises(RbacError):
            rbac.grant_permission(OPERATOR, role.pk, code)
        assert not can_access(UserPrincipal(user.pk), code, team_id=team.pk)
    role.permissions.add(
        Permission.objects.get(codename="change_user", content_type__app_label="accounts")
    )
    assert not can_access(UserPrincipal(user.pk), "accounts.change_user", team_id=team.pk)
    for scope in ("organization", "location", "resource", "*"):
        assert not allowed(user, team, scope_type=scope)
    assert not allowed(user, team, action="delete")


def test_each_catalog_code_resolves_only_its_own_permission_cwe_863(rbac_setup, monkeypatch):
    user, team, _, role, client = rbac_setup
    natural = ("view_user", "accounts", "user")
    monkeypatch.setitem(catalog.SUPPORTED_PERMISSIONS, "accounts.view_user", natural)
    monkeypatch.setitem(catalog.PERMISSION_CODES, natural, "accounts.view_user")
    rbac.revoke_permission(OPERATOR, role.pk, PERMISSION)
    rbac.grant_permission(OPERATOR, role.pk, "accounts.view_user")
    assert [p.natural_key() for p in role.permissions.all()] == [natural]
    assert not allowed(user, team)
    assert client.get("/api/v1/rbac/me/").json()["results"][0]["permissions"] == [
        "accounts.view_user"
    ]


def test_domain_services_are_transport_independent_and_authorize_callers(rbac_setup):
    user, _, _, role, _ = rbac_setup
    with audit_source("http"):
        rbac.update_role(OPERATOR, role.pk, name="Shared service")
    assert AuditEvent.objects.get(action="rbac.role_updated").source == "http"
    with audit_source("command"), pytest.raises(AdministrationDenied):
        rbac.update_role(UserPrincipal(user.pk), role.pk, name="Denied")
    for module in (teams, rbac, policy):
        source = inspect.getsource(module)
        for forbidden in (
            "sys.stdin",
            "input(",
            "print(",
            "CommandError",
            "Source.COMMAND",
            "current_context(",
            "is_staff",
            "is_superuser",
        ):
            assert forbidden not in source
