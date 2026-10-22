"""SPEC-0005 / TM-0005 adversarial acceptance contracts (SEC-01 through SEC-31)."""

import uuid

import pytest
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.audit.context import audit_source
from apps.rbac import services as rbac
from apps.rbac.catalog import SUPPORTED_PERMISSIONS, catalog_action
from apps.rbac.exceptions import RbacError
from apps.rbac.principals import UserPrincipal, infrastructure_operator
from apps.rbac.selectors import can_access
from apps.teams import services as teams
from apps.teams.models import Membership

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
