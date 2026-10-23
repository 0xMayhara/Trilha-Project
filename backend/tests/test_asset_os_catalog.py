"""SPEC-0011 / TM-0011: asset operating-system catalog (SEC-01 through SEC-14)."""

import re
import uuid
from types import SimpleNamespace

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.recorder import MigrationRecorder
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.assets import services, views
from apps.assets.models import OS_FAMILIES, OS_FAMILY, Asset, OsFamily, OsProduct
from apps.assets.validation import canonical_os_version
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from apps.rbac import events as rbac_events
from apps.rbac.permissions import ActiveSession
from tests.test_assets_security import (
    ADD,
    API,
    ASSET_CODES,
    CHANGE,
    VIEW,
    browser_login,
    build_world,
    client_for,
    detail,
    events,
    grant,
    make_team,
    make_user,
    reload,
    send,
)

pytestmark = pytest.mark.django_db
CATALOG_API = f"{API}os-catalog/"
INITIAL, CATALOG = ("assets", "0001_initial"), ("assets", "0002_asset_os_catalog")
# Golden list: codes are stable identifiers (BR-02, BR-03). Changing this list is a SPEC change.
CODES = [
    "cloudlinux",
    "rhel",
    "ubuntu_server",
    "ubuntu_desktop",
    "debian",
    "fedora",
    "rocky_linux",
    "almalinux",
    "centos",
    "oracle_linux",
    "sles",
    "other_linux",
    "windows_10",
    "windows_11",
    "windows_server_2008_r2",
    "windows_server_2012",
    "windows_server_2012_r2",
    "windows_server_2016",
    "windows_server_2019",
    "windows_server_2022",
    "windows_server_2025",
    "other_windows",
    "macos",
    "other",
]
LEGACY = [
    "Debian",
    "Ubuntu Server",
    "ubuntu_server",
    "Ubuntu 22.04 LTS",
    "win2k19",
    "CentOS 7",
    "Windows Server 2019",
    "Other / Unknown",
    "Caf\u00e9",
    "",
]


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


@pytest.fixture
def world(db):
    return build_world()


def errors_of(response):
    return set(response.json()["error"]["details"])


def test_os_catalog_codes_are_unique_stable_and_mapped_to_one_family():
    assert OsProduct.values == CODES
    assert len(set(OsProduct.values)) == len(CODES) <= 100
    assert all(re.fullmatch(r"[a-z0-9_]{1,32}", code) for code in OsProduct.values)
    assert all(label.strip() for label in OsProduct.labels)
    # Exactly one family per product: listed once overall, and every product is listed.
    assert sum(len(products) for products in OS_FAMILIES.values()) == len(OsProduct)
    assert set(OS_FAMILY) == set(OsProduct)
    assert set(OS_FAMILY.values()) == set(OsFamily)


def test_os_version_is_allowlisted_and_bounded_cwe_1286(world):
    for value, canonical in (
        ("", ""),
        ("24.04", "24.04"),
        ("22H2", "22H2"),
        ("9.4", "9.4"),
        ("10.0.19045", "10.0.19045"),
        ("SP1", "SP1"),
        ("24.04.1 LTS", "24.04.1 LTS"),
        ("  15.1  ", "15.1"),
        ("a" * 32, "a" * 32),
    ):
        assert canonical_os_version(value) == canonical
    for value in (
        "<script>",
        'a"b',
        "1.0\n2",
        "\u202e1",
        "\x001",
        "\uff11\uff12",
        "-1",
        "1.",
        "a" * 33,
        "caf\u00e9",
        None,
        12,
        ["1"],
    ):
        with pytest.raises(ValidationError):
            canonical_os_version(value)
        body = {"version": 1, "os_product": "debian", "os_version": value}
        response = world.client.patch(detail(world.asset), body, format="json")
        assert response.status_code == 400 and errors_of(response) == {"os_version"}, value
    assert reload(world.asset).version == 1


def test_os_constraints_are_enforced_by_database_cwe_20():
    team = make_team("alpha")
    for values, constraint in (
        ({"os_product": "windows_7"}, "asset_os_product"),
        ({"os_product": "Debian"}, "asset_os_product"),
        ({"os_version": "12"}, "asset_os_version"),
        ({"os_product": "debian", "os_version": "<b>"}, "asset_os_version"),
        ({"os_product": "debian", "os_version": "caf\u00e9"}, "asset_os_version"),
        ({"os_product": "debian", "os_version": "-1"}, "asset_os_version"),
    ):
        with pytest.raises(IntegrityError, match=constraint), transaction.atomic():
            Asset.objects.create(team=team, name="Row", kind="server", **values)
    Asset.objects.create(team=team, name="Ok", kind="server", os_product="debian", os_version="12")


def _migrate(target):
    # PostgreSQL refuses ALTER TABLE while deferred FK checks are pending: fire them first.
    connection.check_constraints()
    executor = MigrationExecutor(connection)
    executor.migrate([target])
    return executor.loader.project_state([target]).apps


def _rows():
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, operating_system, version, updated_at FROM assets_asset ORDER BY id"
        )
        return cursor.fetchall()


def test_os_migration_preserves_legacy_text_without_inference_cwe_221():
    team = make_team("alpha")
    try:
        old = _migrate(INITIAL).get_model("assets", "Asset")
        for number, text in enumerate(LEGACY):
            old.objects.create(
                team_id=team.pk, name=f"A{number}", kind="server", operating_system=text
            )
        before = _rows()
        _migrate(CATALOG)
        assert _rows() == before  # no row rewritten: text, version and updated_at unchanged
        assert sorted(r[1] for r in before) == sorted(LEGACY)
        # Never inferred, not even from an exact label or code.
        assert set(Asset.objects.values_list("os_product", "os_version")) == {(None, "")}
    finally:
        _migrate(CATALOG)


def test_os_migration_reverse_keeps_legacy_text_cwe_221():
    team = make_team("alpha")
    Asset.objects.create(team=team, name="A", kind="server", operating_system="CentOS 7")
    Asset.objects.filter(name="A").update(os_product="centos", os_version="7")
    before = _rows()
    try:
        _migrate(INITIAL)
        columns = {
            c.name
            for c in connection.introspection.get_table_description(
                connection.cursor(), "assets_asset"
            )
        }
        assert not {"os_product", "os_version"} & columns
        assert _rows() == before
    finally:
        _migrate(CATALOG)
    # Documented loss: a schema reversal drops classifications, never legacy text.
    assert list(Asset.objects.values_list("operating_system", "os_product", "os_version")) == [
        ("CentOS 7", None, "")
    ]


def test_os_catalog_endpoint_matches_model_catalog(world):
    page = world.client.get(f"{CATALOG_API}?page_size=100").json()
    assert (page["count"], page["next"], page["previous"]) == (len(CODES), None, None)
    assert [row["code"] for row in page["results"]] == CODES
    assert page["results"][2] == {
        "code": "ubuntu_server",
        "label": "Ubuntu Server",
        "family": "linux",
        "family_label": "Linux",
    }
    for row in page["results"]:
        product = OsProduct(row["code"])
        assert row == {
            "code": product.value,
            "label": product.label,
            "family": OS_FAMILY[product].value,
            "family_label": OS_FAMILY[product].label,
        }


def test_os_catalog_requires_session_and_is_read_only_cwe_862(world):
    assert views.OsCatalogView.permission_classes == (ActiveSession,)
    assert APIClient().get(CATALOG_API).status_code == 401
    User.objects.filter(pk=world.manager.pk).update(is_active=False)
    assert world.client.get(CATALOG_API).status_code == 401
    User.objects.filter(pk=world.manager.pk).update(is_active=True)
    for query in ("?q=x", "?team=x", "?page=1&page=2", "?page_size=0"):
        assert world.client.get(f"{CATALOG_API}{query}").status_code == 400, query
    client = browser_login()
    token = {"HTTP_X_CSRFTOKEN": client.cookies["csrftoken"].value}
    for method in ("post", "put", "patch", "delete"):
        assert send(client, method, CATALOG_API, {}, **token).status_code == 405, method
        assert send(client, method, CATALOG_API, {}).status_code == 403, method
    # Tenant-free reference data: a user without any asset grant reads the same list.
    page = client_for(make_user("nobody")).get(CATALOG_API).json()
    assert page["count"] == len(CODES)
    assert all(set(row) == {"code", "label", "family", "family_label"} for row in page["results"])


def test_asset_os_fields_round_trip_on_create_and_update(world):
    body = {
        "team_id": str(world.alpha.pk),
        "name": "Db",
        "kind": "server",
        "os_product": "ubuntu_server",
        "os_version": " 24.04 ",
    }
    created = world.client.post(API, body, format="json").json()
    os_fields = ("os_product", "os_version", "os_label", "operating_system")
    assert tuple(created[k] for k in os_fields) == ("ubuntu_server", "24.04", "Ubuntu Server", "")
    target = SimpleNamespace(pk=created["id"])
    for version, (change, expected) in enumerate(
        (
            ({"os_product": "debian"}, ("debian", "24.04", "Debian")),
            ({"os_version": "12"}, ("debian", "12", "Debian")),
            ({"os_product": None, "os_version": ""}, (None, "", None)),
        ),
        start=1,
    ):
        body = {"version": version, **change}
        updated = world.client.patch(detail(target), body, format="json").json()
        assert (updated["os_product"], updated["os_version"], updated["os_label"]) == expected
    assert world.client.get(detail(target)).json() == updated
    listed = {row["id"]: row for row in world.client.get(API).json()["results"]}
    assert listed[created["id"]]["os_label"] is None


def test_os_states_are_distinguishable_in_api(world):
    legacy = Asset.objects.create(
        team=world.alpha, name="Legacy", kind="server", operating_system="CentOS 7"
    )
    classified = Asset.objects.create(
        team=world.alpha,
        name="Classified",
        kind="server",
        operating_system="CentOS 7",
        os_product="centos",
        os_version="7",
    )
    os_fields = ("os_product", "os_version", "os_label", "operating_system")
    states = {
        state: tuple(world.client.get(detail(asset)).json()[k] for k in os_fields)
        for state, asset in (
            ("unspecified", world.asset),
            ("legacy", legacy),
            ("classified", classified),
        )
    }
    assert states == {
        "unspecified": (None, "", None, ""),
        "legacy": (None, "", None, "CentOS 7"),
        "classified": ("centos", "7", "CentOS", "CentOS 7"),
    }


def test_os_product_accepts_only_catalog_codes_cwe_20(world):
    base = {"team_id": str(world.alpha.pk), "name": "New", "kind": "server"}
    for value in (
        "Ubuntu Server",
        "UBUNTU_SERVER",
        " debian",
        "debian ",
        "",
        "windows_7",
        ["debian"],
        1,
        True,
        {"code": "debian"},
    ):
        response = world.client.post(API, {**base, "os_product": value}, format="json")
        assert response.status_code == 400 and errors_of(response) == {"os_product"}, value
        body = {"version": 1, "os_product": value}
        response = world.client.patch(detail(world.asset), body, format="json")
        assert response.status_code == 400 and errors_of(response) == {"os_product"}, value
    assert Asset.objects.count() == 1 and reload(world.asset).version == 1
    assert not events("assets.asset_updated").exists()


def test_os_version_requires_product_on_create_and_update_cwe_1288(world):
    base = {"team_id": str(world.alpha.pk), "name": "New", "kind": "server"}
    path = detail(world.asset)
    response = world.client.post(API, {**base, "os_version": "12"}, format="json")
    assert response.status_code == 400 and errors_of(response) == {"os_version"}
    response = world.client.patch(path, {"version": 1, "os_version": "12"}, format="json")
    assert response.status_code == 400 and errors_of(response) == {"os_version"}
    body = {"version": 1, "os_product": "debian", "os_version": "12"}
    assert world.client.patch(path, body, format="json").status_code == 200
    # Clearing the product alone would leave the stored version without one.
    response = world.client.patch(path, {"version": 2, "os_product": None}, format="json")
    assert response.status_code == 400 and errors_of(response) == {"os_version"}
    asset = reload(world.asset)
    assert (asset.os_product, asset.os_version, asset.version) == ("debian", "12", 2)
    body = {"version": 2, "os_product": None, "os_version": ""}
    cleared = world.client.patch(path, body, format="json").json()
    assert (cleared["os_product"], cleared["os_version"], cleared["version"]) == (None, "", 3)
    with pytest.raises(ValidationError):  # services enforce it for every caller
        services.create_asset(
            world.principal, team_id=world.alpha.pk, name="Svc", kind="server", os_version="1"
        )
    assert Asset.objects.count() == 1


def test_asset_writes_reject_legacy_os_and_derived_fields_cwe_915(world):
    base = {"team_id": str(world.alpha.pk), "name": "New", "kind": "server"}
    for extra in ({"operating_system": "Debian"}, {"os_label": "Debian"}, {"os_family": "linux"}):
        response = world.client.post(API, {**base, **extra}, format="json")
        assert response.status_code == 400 and errors_of(response) == set(extra), extra
        response = world.client.patch(detail(world.asset), {"version": 1, **extra}, format="json")
        assert response.status_code == 400 and errors_of(response) == set(extra), extra
        with pytest.raises(ValidationError):
            services.update_asset(world.principal, world.asset.pk, version=1, changes=extra)
    asset = reload(world.asset)
    assert (asset.operating_system, asset.os_product, asset.version) == ("", None, 1)
    assert Asset.objects.count() == 1 and not events("assets.asset_updated").exists()


def test_os_change_authorization_matrix_cwe_862_cwe_639(world):
    body = {"os_product": "debian", "os_version": "12"}
    viewer = make_user("viewer")
    grant(viewer, world.alpha, VIEW)
    outsider = make_user("outsider")
    grant(outsider, world.beta, VIEW, ADD, CHANGE)
    retired = services.create_asset(
        world.principal, team_id=world.alpha.pk, name="Old", kind="server"
    )
    services.retire_asset(world.principal, retired.pk, version=1)
    missing = SimpleNamespace(pk=uuid.uuid4())
    for client, asset, version, status in (
        (client_for(viewer), world.asset, 1, 403),  # in scope, no change permission
        (client_for(outsider), world.asset, 1, 404),  # another team's UUID
        (world.client, missing, 1, 404),  # nonexistent
        (world.client, retired, 2, 409),  # retired assets are not edited
        (APIClient(), world.asset, 1, 401),
    ):
        response = client.patch(detail(asset), {"version": version, **body}, format="json")
        assert response.status_code == status, (asset, status)
    assert client_for(outsider).get(detail(world.asset)).status_code == 404  # no OS disclosure
    create = {"team_id": str(world.alpha.pk), "name": "X", "kind": "server", **body}
    assert client_for(outsider).post(API, create, format="json").status_code == 400
    assert client_for(viewer).post(API, create, format="json").status_code == 403
    assert set(Asset.objects.values_list("os_product", flat=True)) == {None}
    assert not events("assets.asset_updated").exists()
    path = detail(world.asset)
    assert world.client.patch(path, {"version": 1, **body}, format="json").status_code == 200


def test_stale_os_update_returns_409_without_change_cwe_362(world):
    path = detail(world.asset)
    assert (
        world.client.patch(path, {"version": 1, "os_product": "debian"}, format="json").status_code
        == 200
    )
    for change in ({"os_product": "rhel"}, {"os_product": "debian"}, {"os_product": None}):
        response = world.client.patch(path, {"version": 1, **change}, format="json")
        assert response.status_code == 409, change
    asset = reload(world.asset)
    assert (asset.os_product, asset.version) == ("debian", 2)
    assert events("assets.asset_updated").count() == 1


def test_os_changes_are_audited_with_before_and_after_cwe_778(world):
    created = services.create_asset(
        world.principal,
        team_id=world.alpha.pk,
        name="Db",
        kind="server",
        os_product="rhel",
        os_version="9.4",
    )
    changes = events("assets.asset_created").get(resource_id=str(created.pk)).changes
    assert changes["os_product"] == {"before": None, "after": "rhel"}
    assert changes["os_version"] == {"before": None, "after": "9.4"}
    update = services.update_asset
    update(world.principal, created.pk, version=1, changes={"os_product": "rocky_linux"})
    update(world.principal, created.pk, version=2, changes={"os_version": "9.4"})  # no-op
    update(world.principal, created.pk, version=2, changes={"os_product": None, "os_version": ""})
    recorded = events("assets.asset_updated").filter(resource_id=str(created.pk)).order_by("id")
    assert [event.changes for event in recorded] == [
        {"os_product": {"before": "rhel", "after": "rocky_linux"}},
        {
            "os_product": {"before": "rocky_linux", "after": None},
            "os_version": {"before": "9.4", "after": ""},
        },
    ]
    assert not AuditEvent.objects.filter(changes__has_key="operating_system").exists()


def test_legacy_asset_remains_editable_without_classification(world):
    legacy = Asset.objects.create(
        team=world.alpha, name="Legacy", kind="server", operating_system="CentOS 7"
    )
    path = detail(legacy)
    assert (
        world.client.patch(path, {"version": 1, "name": "Legacy 2"}, format="json").status_code
        == 200
    )
    full_form = {
        "version": 2,
        "name": "Legacy 3",
        "kind": "server",
        "hostname": "",
        "ip_addresses": [],
        "os_product": None,
        "os_version": "",
        "environment": None,
        "criticality": None,
    }
    assert world.client.patch(path, full_form, format="json").status_code == 200
    asset = reload(legacy)
    assert (asset.name, asset.operating_system, asset.os_product, asset.os_version) == (
        "Legacy 3",
        "CentOS 7",
        None,
        "",
    )
    recorded = events("assets.asset_updated").filter(resource_id=str(legacy.pk))
    assert [set(event.changes) for event in recorded] == [{"name"}, {"name"}]


def test_classifying_legacy_asset_keeps_legacy_text(world):
    legacy = Asset.objects.create(
        team=world.alpha, name="Legacy", kind="server", operating_system="CentOS 7"
    )
    changes = {"os_product": "centos", "os_version": "7"}
    services.update_asset(world.principal, legacy.pk, version=1, changes=changes)
    services.retire_asset(world.principal, legacy.pk, version=2)
    services.restore_asset(world.principal, legacy.pk, version=3)
    grant(world.manager, world.beta, *ASSET_CODES)
    services.transfer_asset(world.principal, legacy.pk, version=4, team_id=world.beta.pk)
    asset = reload(legacy)
    assert (asset.operating_system, asset.os_product, asset.os_version, asset.team_id) == (
        "CentOS 7",
        "centos",
        "7",
        world.beta.pk,
    )
    new = services.create_asset(world.principal, team_id=world.alpha.pk, name="N", kind="server")
    assert new.operating_system == ""


def test_rollback_era_writes_stay_valid_preserved_and_identifiable_cwe_221(world):
    # The previous release's model knows no OS columns (SPEC-0011 Migration / Rollback).
    old = MigrationExecutor(connection).loader.project_state([INITIAL]).apps
    previous = old.get_model("assets", "Asset")
    inserted = previous.objects.create(
        team_id=world.alpha.pk, name="Old insert", kind="server", operating_system="Ubuntu 22.04"
    )
    fields = ("team_id", "name", "kind", "operating_system", "status")
    rbac_events.emit(world.principal, "assets.asset_created", reload(inserted), fields=fields)
    classified = services.create_asset(
        world.principal,
        team_id=world.alpha.pk,
        name="Classified",
        kind="server",
        os_product="ubuntu_server",
        os_version="24.04",
    )
    row = previous.objects.get(pk=classified.pk)
    before = {"operating_system": row.operating_system}
    row.operating_system, row.version = "Windows Server 2019", row.version + 1
    row.save(update_fields=["operating_system", "version", "updated_at"])
    rbac_events.emit(
        world.principal,
        "assets.asset_updated",
        reload(classified),
        before=before,
        fields=("operating_system",),
    )

    assert (reload(inserted).os_product, reload(inserted).os_version) == (None, "")
    patch = {"version": 2, "criticality": "high"}
    body = world.client.patch(detail(classified), patch, format="json").json()
    assert (body["os_product"], body["os_version"], body["operating_system"]) == (
        "ubuntu_server",
        "24.04",
        "Windows Server 2019",
    )
    # Reconciliation selection: legacy text written after 0002 is a previous-release write.
    applied = MigrationRecorder.Migration.objects.get(app=CATALOG[0], name=CATALOG[1]).applied
    written = (
        AuditEvent.objects.filter(
            resource_type="assets.asset",
            action__in=("assets.asset_created", "assets.asset_updated"),
            changes__has_key="operating_system",
            occurred_at__gt=applied,
        )
        .exclude(changes__operating_system__after="")
        .values_list("resource_id", flat=True)
    )
    found = Asset.objects.filter(pk__in=list(written)).values_list("pk", "os_product")
    assert {pk: product is not None for pk, product in found} == {
        inserted.pk: False,  # legacy, awaiting classification
        classified.pk: True,  # diverged: needs a human review
    }
