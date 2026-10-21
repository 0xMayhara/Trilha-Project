import ast
import importlib
import threading
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.db import DataError, IntegrityError, close_old_connections, connection, transaction
from django.db.migrations.executor import MigrationExecutor

from apps.accounts.models import User
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from apps.rbac import services as rbac
from apps.rbac.exceptions import RbacError
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


def test_operator_can_provision_team_role_and_membership(user):
    output = StringIO()

    def command(*args, **kwargs):
        call_command(*args, stdout=output, **kwargs)

    command("teams_create", "operations", name="Operations")
    command("teams_update", "operations", name="Operations team")
    command("rbac_create_role", "reader", name="Reader")
    command("rbac_update_role", "reader", name="Shared reader")
    command("rbac_grant_permission", "reader", PERMISSION)
    command("teams_add_member", "operations", user.username)
    command("rbac_assign_role", "operations", user.username, "reader")
    for name, args in (
        ("teams_list", []),
        ("teams_members", ["operations"]),
        ("rbac_list_roles", []),
        ("rbac_list_permissions", []),
    ):
        command(name, *args)
    assert "operations" in output.getvalue() and PERMISSION in output.getvalue()
    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="operations"),
    ):
        command("teams_activate", "operations")
    team = Team.objects.get(code="operations")
    assert f"operations {team.pk} active=False Operations\n" in output.getvalue()
    assert can_access(UserPrincipal(user.pk), PERMISSION, team_id=team.pk)
    command("rbac_revoke_permission", "reader", PERMISSION)
    command("rbac_revoke_role", "operations", user.username, "reader")
    command("teams_remove_member", "operations", user.username)
    command("teams_deactivate", "operations")
    assert not can_access(UserPrincipal(user.pk), PERMISSION, team_id=team.pk)


def test_team_and_own_access_response_contracts(rbac_setup):
    user, team, member, role, client = rbac_setup
    extra_role = rbac.create_role(OPERATOR, code="alternate", name="Alternate")
    rbac.grant_permission(OPERATOR, extra_role.pk, PERMISSION)
    rbac.assign_role(OPERATOR, member.pk, extra_role.pk)
    response = client.get("/api/v1/rbac/me/")
    assert set(response.json()) == {"count", "next", "previous", "results"}
    row = response.json()["results"][0]
    assert [r["code"] for r in row["roles"]] == ["alternate", "reader"]
    assert row["permissions"] == [PERMISSION]
    assert set(row["team"]) == {"id", "code", "name"}
    detail = client.get(f"/api/v1/teams/{team.pk}/")
    assert detail.json() == row["team"]
    for path in ("/api/v1/teams/", "/api/v1/rbac/me/"):
        for query in (
            "page=0",
            "page=-1",
            "page_size=bad",
            "page=1&page=2",
            "sort=name",
            "page=" + "9" * 5000,
        ):
            assert client.get(path + "?" + query).status_code == 400
    assert client.get(f"/api/v1/teams/{team.pk}/?page=1").status_code == 400
    rbac.revoke_role(OPERATOR, member.pk, role.pk)
    rbac.revoke_role(OPERATOR, member.pk, extra_role.pk)
    row = client.get("/api/v1/rbac/me/").json()["results"][0]
    assert row["roles"] == row["permissions"] == []
    assert row["membership_id"] == str(member.pk)
    assert user.pk == member.user_id


def test_new_grants_require_enabled_account_and_allow_pending_setup(user):
    team = teams.create_team(OPERATOR, code="new", name="New")
    pending = User.objects.create_user(username="pending")
    assert not pending.has_usable_password()
    member = teams.add_member(OPERATOR, team.pk, pending.pk)
    role = rbac.create_role(OPERATOR, code="empty", name="Empty")
    rbac.assign_role(OPERATOR, member.pk, role.pk)
    User.objects.filter(pk=pending.pk).update(is_active=False)
    with pytest.raises(RbacError):
        rbac.assign_role(OPERATOR, member.pk, role.pk)
    with pytest.raises(RbacError):
        teams.add_member(OPERATOR, team.pk, pending.pk)
    rbac.revoke_role(OPERATOR, member.pk, role.pk)
    teams.remove_member(OPERATOR, team.pk, pending.pk)
    assert not Membership.objects.filter(user=pending).exists()


def test_activation_revision_tracks_permission_edges(rbac_setup):
    _, team, _, role, _ = rbac_setup
    teams.deactivate_team(OPERATOR, team.pk)
    preview = teams.preview_team_activation(OPERATOR, team.pk)
    rbac.revoke_permission(OPERATOR, role.pk, PERMISSION)
    with pytest.raises(RbacError):
        teams.activate_team(OPERATOR, team.pk, preview.revision, team.code)
    team.refresh_from_db()
    assert not team.is_active


def test_authorization_check_after_commit_uses_new_snapshot(rbac_setup):
    user, team, _, role, _ = rbac_setup
    principal = UserPrincipal(user.pk)
    admitted, committed = threading.Event(), threading.Event()

    def checks():
        close_old_connections()
        try:
            # Two statements in one READ COMMITTED transaction must see the new grant state.
            with transaction.atomic():
                before = can_access(principal, PERMISSION, team_id=team.pk)
                admitted.set()
                assert committed.wait(10)
                after = can_access(principal, PERMISSION, team_id=team.pk)
            return before, after
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(checks)
        try:
            assert admitted.wait(10)
            rbac.revoke_permission(OPERATOR, role.pk, PERMISSION)
        finally:
            committed.set()
        assert future.result(timeout=10) == (True, False)


def test_rbac_migrations_are_additive_and_empty_database_reversible():
    assert Team.objects.count() == Membership.objects.count() == Role.objects.count() == 0
    executor = MigrationExecutor(connection)
    original = executor.loader.graph.leaf_nodes()
    try:
        executor.migrate(
            [("teams", None)]
        )  # Django reverses dependent rbac first; audit untouched.
        tables = connection.introspection.table_names()
        assert "teams_team" not in tables and "rbac_role" not in tables
        assert "audit_auditevent" in tables and "accounts_user" in tables
    finally:
        MigrationExecutor(connection).migrate(original)
    assert Team.objects.count() == Membership.objects.count() == RoleAssignment.objects.count() == 0
    assert AuditEvent.objects.count() == 0


def test_rbac_uses_public_interfaces_without_circular_imports():
    root = Path(__file__).resolve().parents[1] / "apps"
    for module in (
        "apps.rbac.services",
        "apps.teams.services",
        "apps.rbac.selectors",
        "config.urls",
    ):
        importlib.import_module(module)
    for app in ("teams", "rbac"):
        for path in (root / app).rglob("*.py"):
            if "migrations" in path.parts:
                continue
            source = path.read_text()
            assert "AuditEvent" not in source
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert node.module != "apps.accounts.models"
                    if path.name in {"services.py", "selectors.py", "policy.py"}:
                        assert ".management" not in node.module
    for path in (root / "accounts").rglob("*.py"):
        assert "apps.rbac" not in path.read_text() and "apps.teams" not in path.read_text()


@pytest.mark.parametrize("code", ["", "A", "a" * 64, "team\n", "team;command", "téam", "a.b"])
def test_invalid_codes_fail_validation_and_database_checks(code):
    with pytest.raises(RbacError):
        teams.create_team(OPERATOR, code=code, name="Valid")
    with pytest.raises((IntegrityError, DataError)), transaction.atomic():
        Team.objects.create(code=code, name="Valid")


@pytest.mark.parametrize("name", ["", " ", "n" * 151, "bad\x00name", "bad\nname", "bad\ud800name"])
def test_invalid_labels_are_rejected(name):
    with pytest.raises(RbacError):
        teams.create_team(OPERATOR, code="valid", name=name)
    with pytest.raises(RbacError):
        rbac.create_role(OPERATOR, code="valid", name=name)
