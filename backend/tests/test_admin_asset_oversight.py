"""SPEC-0010 SEC-23 / BR-12: Admin oversight of assets is read-only (SPEC-0005 amendment)."""

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from apps.assets import services
from apps.assets.models import Asset
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from apps.rbac import administration
from apps.rbac import services as rbac
from apps.rbac.principals import UserPrincipal
from apps.teams import services as teams
from tests.platform_support import OPERATOR, Browser, make_admin, make_user

pytestmark = pytest.mark.django_db
API = "/api/v1/assets/"
ASSET_CODES = (
    "assets.view_asset",
    "assets.add_asset",
    "assets.change_asset",
    "assets.retire_asset",
    "assets.transfer_asset",
)


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


def active_team(code):
    team = teams.create_team(OPERATOR, code=code, name=code.title())
    revision = teams.preview_team_activation(OPERATOR, team.pk).revision
    return teams.activate_team(OPERATOR, team.pk, revision, code)


def grant(user, team, *codes):
    membership = teams.add_member(OPERATOR, team.pk, user.pk)
    role = rbac.create_role(OPERATOR, code=f"r-{user.username}-{team.code}", name="Role")
    for code in codes:
        rbac.grant_permission(OPERATOR, role.pk, code)
    rbac.assign_role(OPERATOR, membership.pk, role.pk)


def asset_in(team, owner, name):
    return services.create_asset(UserPrincipal(owner.pk), team_id=team.pk, name=name, kind="server")


def test_admin_asset_oversight_is_read_only_cwe_863():
    alpha, beta = active_team("alpha"), active_team("beta")
    owner = make_user("owner")
    grant(owner, alpha, *ASSET_CODES)
    grant(owner, beta, *ASSET_CODES)
    in_alpha, in_beta = asset_in(alpha, owner, "Web 01"), asset_in(beta, owner, "Db 01")
    teams.deactivate_team(OPERATOR, beta.pk)  # oversight includes inactive teams' assets
    reader = make_user("reader")
    grant(reader, alpha, "assets.view_asset")
    make_admin("root")
    root = Browser().login("root")
    assert root.reauthenticate().status_code == 204

    listed = root.get(API).json()
    assert {row["id"] for row in listed["results"]} == {str(in_alpha.pk), str(in_beta.pk)}
    assert root.get(API, {"team": str(beta.pk)}).json()["count"] == 1
    assert root.get(f"{API}{in_beta.pk}/").status_code == 200
    reader_view = Browser(address="203.0.113.20").login("reader")
    assert {row["id"] for row in reader_view.get(API).json()["results"]} == {str(in_alpha.pk)}
    assert reader_view.get(f"{API}{in_beta.pk}/").status_code == 404

    # Admin status adds no mutation authority: outside the team 404, in scope without grants 403.
    before = list(Asset.objects.order_by("pk").values())
    events = AuditEvent.objects.filter(action__startswith="assets.").count()
    outside = [
        root.patch(f"{API}{in_alpha.pk}/", {"version": 1, "name": "X"}),
        root.post(f"{API}{in_alpha.pk}/retire/", {"version": 1}),
        root.post(f"{API}{in_alpha.pk}/transfer/", {"version": 1, "team_id": str(beta.pk)}),
    ]
    assert [r.status_code for r in outside] == [404, 404, 404]
    created = root.post(API, {"team_id": str(alpha.pk), "name": "New", "kind": "server"})
    assert created.status_code == 400
    admin_id = root.get("/api/v1/auth/me/").json()["id"]
    teams.add_member(OPERATOR, alpha.pk, admin_id)
    in_scope = root.patch(f"{API}{in_alpha.pk}/", {"version": 1, "name": "X"})
    assert in_scope.status_code == 403
    assert list(Asset.objects.order_by("pk").values()) == before
    assert AuditEvent.objects.filter(action__startswith="assets.").count() == events

    # A revoked Admin keeps only ordinary visibility.
    make_admin("deputy")  # another enabled Admin, so the revocation is allowed
    administration.revoke_admin(OPERATOR, admin_id)
    assert root.get(f"{API}{in_beta.pk}/").status_code == 404
    assert root.get(API).json()["count"] == 0  # a membership without grants shows nothing


def test_platform_admin_cannot_change_os_fields_cwe_863():
    # SPEC-0011 SEC-02: read oversight never becomes authority over OS classification.
    alpha = active_team("alpha")
    owner = make_user("owner")
    grant(owner, alpha, *ASSET_CODES)
    asset = asset_in(alpha, owner, "Web 01")
    make_admin("root")
    root = Browser().login("root")
    assert root.reauthenticate().status_code == 204
    assert root.get(f"{API}{asset.pk}/").status_code == 200
    body = {"version": 1, "os_product": "debian", "os_version": "12"}
    assert root.patch(f"{API}{asset.pk}/", body).status_code == 404
    teams.add_member(OPERATOR, alpha.pk, root.get("/api/v1/auth/me/").json()["id"])
    assert root.patch(f"{API}{asset.pk}/", body).status_code == 403
    assert Asset.objects.get(pk=asset.pk).os_product is None
    assert not AuditEvent.objects.filter(action="assets.asset_updated").exists()


def test_admin_asset_list_query_count_is_independent_of_size():
    alpha = active_team("alpha")
    owner = make_user("owner")
    grant(owner, alpha, *ASSET_CODES)
    make_admin("root")
    root = Browser().login("root")
    counts = []
    for name in ("One", "Two", "Three"):
        asset_in(alpha, owner, name)
        with CaptureQueriesContext(connection) as queries:
            assert root.get(API).status_code == 200
        counts.append(len(queries))
    assert counts[0] == counts[1] == counts[2]
