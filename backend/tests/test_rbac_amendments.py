"""SPEC-0004 amendments made by SPEC-0010: typed administration errors and digest revisions."""

import re
import uuid

import pytest

from apps.accounts.models import User
from apps.audit.context import audit_source
from apps.rbac import services as rbac
from apps.rbac.exceptions import RbacConflict, RbacError, RbacInvalid, RbacNotFound
from apps.rbac.principals import infrastructure_operator
from apps.teams import services as teams

pytestmark = pytest.mark.django_db
OPERATOR = infrastructure_operator()


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


def test_administration_errors_are_typed_and_still_rbac_errors():
    role = rbac.create_role(OPERATOR, code="reader", name="Reader")
    team = teams.create_team(OPERATOR, code="alpha", name="Alpha")
    cases = [
        (lambda: rbac.update_role(OPERATOR, uuid.uuid4(), name="Missing"), RbacNotFound),
        (lambda: rbac.grant_permission(OPERATOR, role.pk, "unknown.code"), RbacInvalid),
        (lambda: teams.create_team(OPERATOR, code="Bad Code", name="Bad"), RbacInvalid),
        (lambda: teams.create_team(OPERATOR, code="alpha", name="Again"), RbacConflict),
        (lambda: rbac.update_role(OPERATOR, role.pk, name="Reader"), RbacConflict),
        (lambda: teams.deactivate_team(OPERATOR, team.pk), RbacConflict),
    ]
    for call, error in cases:
        with pytest.raises(error) as raised:
            call()
        assert isinstance(raised.value, RbacError)
        assert "SELECT" not in str(raised.value) and "constraint" not in str(raised.value).lower()


def test_activation_revision_is_an_opaque_digest():
    team = teams.create_team(OPERATOR, code="alpha", name="Alpha")
    first = teams.preview_team_activation(OPERATOR, team.pk).revision
    assert re.fullmatch(r"[0-9a-f]{64}", first)
    assert teams.preview_team_activation(OPERATOR, team.pk).revision == first  # deterministic
    role = rbac.create_role(OPERATOR, code="reader", name="Reader")
    user = User.objects.create(username="u")
    membership = teams.add_member(OPERATOR, team.pk, user.pk)
    rbac.assign_role(OPERATOR, membership.pk, role.pk)
    second = teams.preview_team_activation(OPERATOR, team.pk).revision
    assert second != first
    with pytest.raises(RbacConflict):
        teams.activate_team(OPERATOR, team.pk, first, "alpha")
    with pytest.raises(RbacConflict):
        teams.activate_team(OPERATOR, team.pk, second, "ALPHA")
    teams.activate_team(OPERATOR, team.pk, second, "alpha")
