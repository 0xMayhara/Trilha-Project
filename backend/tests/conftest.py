import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APIClient

USER_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


@pytest.fixture
def user(db):
    return get_user_model().objects.create_user(username="analyst", password=USER_PASSWORD)


@pytest.fixture
def rbac_setup(user):
    from apps.rbac import services as rbac
    from apps.rbac.principals import infrastructure_operator
    from apps.teams import services as teams

    OPERATOR = infrastructure_operator()
    PERMISSION = "teams.view_team"
    team = teams.create_team(OPERATOR, code="alpha", name="Alpha")
    membership = teams.add_member(OPERATOR, team.pk, user.pk)
    role = rbac.create_role(OPERATOR, code="reader", name="Reader")
    rbac.grant_permission(OPERATOR, role.pk, PERMISSION)
    rbac.assign_role(OPERATOR, membership.pk, role.pk)
    preview = teams.preview_team_activation(OPERATOR, team.pk)
    teams.activate_team(OPERATOR, team.pk, preview.revision, preview.code)
    client = APIClient()
    client.force_authenticate(user)
    return user, team, membership, role, client
