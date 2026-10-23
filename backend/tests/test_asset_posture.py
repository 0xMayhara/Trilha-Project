"""SPEC-0007 slice A: declared asset security posture (BR-25, SEC-33, AC-A1 to AC-A3)."""

import pytest
from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from rest_framework.test import APIClient

from apps.assets import services
from apps.assets.models import Asset, HardeningStatus, InternetExposure
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from apps.teams import services as teams
from tests.platform_support import OPERATOR, Browser, make_admin
from tests.platform_support import make_user as make_platform_user
from tests.test_admin_asset_oversight import active_team, asset_in
from tests.test_admin_asset_oversight import grant as grant_once
from tests.test_assets_security import (
    ADD,
    API,
    ASSET_CODES,
    CHANGE,
    VIEW,
    build_world,
    client_for,
    detail,
    events,
    grant,
    make_team,
    make_user,
    reload,
)

pytestmark = pytest.mark.django_db
CATALOG, POSTURE = ("assets", "0002_asset_os_catalog"), ("assets", "0003_asset_security_posture")
POSTURE_FIELDS = ("hardening_status", "internet_exposure")


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


@pytest.fixture
def world(db):
    return build_world()


def details(response):
    return set(response.json()["error"]["details"])


def posture(asset):
    return tuple(getattr(reload(asset), field) for field in POSTURE_FIELDS)


def test_posture_codes_have_no_assessed_or_unknown_value():
    # Null is the only "not assessed" / "unknown" state (BR-25): no code may stand in for it.
    assert HardeningStatus.values == ["hardened", "partially_hardened", "not_hardened"]
    assert InternetExposure.values == ["exposed", "not_exposed"]


# SEC-33 — exact codes or null; no default; SPEC-0005 versioning and audit kept (T-33, CWE-20)


def test_posture_fields_are_allowlisted_and_audited_cwe_20(world):
    client = world.client
    body = {"team_id": str(world.alpha.pk), "name": "Edge", "kind": "server"}
    created = client.post(
        API,
        {**body, "hardening_status": "partially_hardened", "internet_exposure": "exposed"},
        format="json",
    )
    assert created.status_code == 201
    assert (created.json()["hardening_status"], created.json()["internet_exposure"]) == (
        "partially_hardened",
        "exposed",
    )
    changes = events("assets.asset_created").get(resource_id=created.json()["id"]).changes
    assert changes["hardening_status"] == {"before": None, "after": "partially_hardened"}
    assert changes["internet_exposure"] == {"before": None, "after": "exposed"}

    plain = client.post(API, {**body, "name": "Plain"}, format="json").json()
    assert (plain["hardening_status"], plain["internet_exposure"]) == (None, None)
    assert posture(world.asset) == (None, None)

    invalid = [
        ("hardening_status", ""),
        ("hardening_status", "Hardened"),
        ("hardening_status", " hardened"),
        ("hardening_status", "not_assessed"),
        ("hardening_status", "unknown"),
        ("hardening_status", True),
        ("hardening_status", 1),
        ("hardening_status", ["hardened"]),
        ("internet_exposure", "yes"),
        ("internet_exposure", "no"),
        ("internet_exposure", "unknown"),
        ("internet_exposure", ""),
        ("internet_exposure", False),
        ("internet_exposure", {"value": "exposed"}),
    ]
    audit_count = AuditEvent.objects.count()
    for field, value in invalid:
        patched = client.patch(detail(world.asset), {"version": 1, field: value}, format="json")
        assert patched.status_code == 400, (field, value)
        assert details(patched) == {field}, (field, value)
        posted = client.post(API, {**body, "name": "Bad", field: value}, format="json")
        assert posted.status_code == 400, (field, value)
        assert details(posted) == {field}, (field, value)
    assert AuditEvent.objects.count() == audit_count
    assert not Asset.objects.filter(name="Bad").exists()
    assert posture(world.asset) == (None, None) and reload(world.asset).version == 1

    # Another field's change never fills posture in (no silent default).
    renamed = client.patch(detail(world.asset), {"version": 1, "name": "Web 01b"}, format="json")
    assert renamed.status_code == 200 and posture(world.asset) == (None, None)

    declared = {
        "version": 2,
        "hardening_status": "not_hardened",
        "internet_exposure": "not_exposed",
    }
    assert client.patch(detail(world.asset), declared, format="json").status_code == 200
    cleared = {"version": 3, "hardening_status": None, "internet_exposure": None}
    assert client.patch(detail(world.asset), cleared, format="json").status_code == 200
    recorded = events("assets.asset_updated").filter(resource_id=str(world.asset.pk))
    assert [event.changes for event in recorded.order_by("id")][1:] == [
        {
            "hardening_status": {"before": None, "after": "not_hardened"},
            "internet_exposure": {"before": None, "after": "not_exposed"},
        },
        {
            "hardening_status": {"before": "not_hardened", "after": None},
            "internet_exposure": {"before": "not_exposed", "after": None},
        },
    ]

    # Optimistic concurrency: a stale version changes nothing, even for the current values.
    for stale in ({"hardening_status": "hardened"}, {"hardening_status": None}):
        response = client.patch(detail(world.asset), {"version": 3, **stale}, format="json")
        assert response.status_code == 409
    assert posture(world.asset) == (None, None) and reload(world.asset).version == 4
    assert recorded.count() == 3


def test_not_assessed_and_unknown_stay_distinct_from_declared_values(world):
    # AC-A1: null is reported as null — never as "not_hardened" or "not_exposed", and vice versa.
    combinations = [
        (None, None),
        ("not_hardened", "not_exposed"),
        ("hardened", "exposed"),
        ("partially_hardened", None),
        (None, "not_exposed"),
    ]
    for number, (hardening, exposure) in enumerate(combinations):
        asset = services.create_asset(
            world.principal,
            team_id=world.alpha.pk,
            name=f"Host {number}",
            kind="server",
            hardening_status=hardening,
            internet_exposure=exposure,
        )
        assert posture(asset) == (hardening, exposure)
        shown = world.client.get(detail(asset)).json()
        assert (shown["hardening_status"], shown["internet_exposure"]) == (hardening, exposure)
    listed = {a["name"]: a for a in world.client.get(f"{API}?page_size=100").json()["results"]}
    assert listed["Host 0"]["hardening_status"] is None
    assert listed["Host 1"]["hardening_status"] == "not_hardened"
    assert listed["Host 0"]["internet_exposure"] is None
    assert listed["Host 1"]["internet_exposure"] == "not_exposed"


def test_posture_changes_keep_asset_authorization_cwe_862_cwe_639(world):
    body = {"version": 1, "hardening_status": "hardened", "internet_exposure": "exposed"}
    viewer = make_user("viewer")
    grant(viewer, world.alpha, VIEW)
    assert client_for(viewer).patch(detail(world.asset), body, format="json").status_code == 403
    outsider = make_user("outsider")
    grant(outsider, world.beta, *ASSET_CODES)
    outsider_client = client_for(outsider)
    assert outsider_client.patch(detail(world.asset), body, format="json").status_code == 404
    swapped = detail(type("Missing", (), {"pk": "00000000-0000-4000-8000-000000000000"}))
    assert world.client.patch(swapped, body, format="json").status_code == 404
    assert APIClient().patch(detail(world.asset), body, format="json").status_code == 401
    create = {
        "team_id": str(world.alpha.pk),
        "name": "Sneaky",
        "kind": "server",
        "hardening_status": "hardened",
    }
    assert outsider_client.post(API, create, format="json").status_code == 400  # not a member
    grant(viewer, world.alpha, CHANGE)  # change without add
    assert client_for(viewer).post(API, create, format="json").status_code == 403
    grant(viewer, world.alpha, ADD)
    assert client_for(viewer).post(API, create, format="json").status_code == 201
    assert posture(world.asset) == (None, None)
    assert not events("assets.asset_updated").exists()


def test_platform_admin_cannot_change_posture_fields_cwe_863():
    # SPEC-0010 SEC-23: oversight reads posture but never changes it without team grants.
    alpha = active_team("alpha")
    owner = make_platform_user("owner")
    grant_once(owner, alpha, *ASSET_CODES)
    asset = asset_in(alpha, owner, "Web 01")
    make_admin("root")
    root = Browser().login("root")
    assert root.reauthenticate().status_code == 204
    shown = root.get(f"{API}{asset.pk}/")
    assert shown.status_code == 200
    assert (shown.json()["hardening_status"], shown.json()["internet_exposure"]) == (None, None)
    body = {"version": 1, "hardening_status": "hardened", "internet_exposure": "not_exposed"}
    assert root.patch(f"{API}{asset.pk}/", body).status_code == 404
    teams.add_member(OPERATOR, alpha.pk, root.get("/api/v1/auth/me/").json()["id"])
    assert root.patch(f"{API}{asset.pk}/", body).status_code == 403
    assert posture(asset) == (None, None)
    assert not AuditEvent.objects.filter(action="assets.asset_updated").exists()


def test_posture_constraints_are_enforced_by_database_cwe_20():
    team = make_team("alpha")
    for values, constraint in (
        ({"hardening_status": "unknown"}, "asset_hardening_status"),
        ({"hardening_status": "not_assessed"}, "asset_hardening_status"),
        ({"hardening_status": ""}, "asset_hardening_status"),
        ({"hardening_status": "Hardened"}, "asset_hardening_status"),
        ({"internet_exposure": "unknown"}, "asset_internet_exposure"),
        ({"internet_exposure": "no"}, "asset_internet_exposure"),
        ({"internet_exposure": ""}, "asset_internet_exposure"),
    ):
        with pytest.raises(IntegrityError, match=constraint), transaction.atomic():
            Asset.objects.create(team=team, name="Row", kind="server", **values)
    Asset.objects.create(
        team=team, name="Ok", kind="server", hardening_status="hardened", internet_exposure=None
    )


# AC-A2 / NFR-05 — additive migration; existing and previous-release rows stay unassessed


def _migrate(target):
    # PostgreSQL refuses ALTER TABLE while deferred FK checks are pending: fire them first.
    connection.check_constraints()
    executor = MigrationExecutor(connection)
    executor.migrate([target])
    return executor.loader.project_state([target]).apps


def _restore():
    connection.check_constraints()
    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())


def _rows():
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, name, criticality, environment, version, updated_at"
            " FROM assets_asset ORDER BY id"
        )
        return cursor.fetchall()


def _columns():
    with connection.cursor() as cursor:
        description = connection.introspection.get_table_description(cursor, "assets_asset")
    return {column.name for column in description}


def test_posture_migration_is_additive_and_leaves_existing_rows_unassessed():
    team = make_team("alpha")
    try:
        previous = _migrate(CATALOG).get_model("assets", "Asset")
        previous.objects.create(
            team_id=team.pk, name="Legacy", kind="server", criticality="high", environment="staging"
        )
        before = _rows()
        _migrate(POSTURE)
        assert _rows() == before  # nothing rewritten: criticality, environment, version, time
        assert list(Asset.objects.values_list(*POSTURE_FIELDS)) == [(None, None)]
        Asset.objects.update(hardening_status="hardened", internet_exposure="exposed")
        _migrate(CATALOG)
        assert not set(POSTURE_FIELDS) & _columns()
        assert _rows() == before  # reversal drops only the declared posture
    finally:
        _restore()
    assert set(POSTURE_FIELDS) <= _columns()
    assert list(Asset.objects.values_list(*POSTURE_FIELDS)) == [(None, None)]


def test_previous_release_writes_stay_valid_and_unassessed(world):
    # The previous release's model has no posture columns; its inserts must keep working (NFR-05).
    previous = MigrationExecutor(connection).loader.project_state([CATALOG]).apps
    old_asset = previous.get_model("assets", "Asset").objects.create(
        team_id=world.alpha.pk, name="Old insert", kind="server", criticality="critical"
    )
    assert posture(old_asset) == (None, None)
    shown = world.client.get(detail(old_asset)).json()
    assert (shown["criticality"], shown["hardening_status"], shown["internet_exposure"]) == (
        "critical",
        None,
        None,
    )
