"""SPEC-0011 / TM-0011: asset operating-system catalog (SEC-01 through SEC-14)."""

import re

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor

from apps.assets.models import OS_FAMILIES, OS_FAMILY, Asset, OsFamily, OsProduct
from apps.assets.validation import canonical_os_version
from apps.audit.context import audit_source
from tests.test_assets_security import make_team

pytestmark = pytest.mark.django_db
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


def test_os_catalog_codes_are_unique_stable_and_mapped_to_one_family():
    assert OsProduct.values == CODES
    assert len(set(OsProduct.values)) == len(CODES) <= 100
    assert all(re.fullmatch(r"[a-z0-9_]{1,32}", code) for code in OsProduct.values)
    assert all(label.strip() for label in OsProduct.labels)
    # Exactly one family per product: listed once overall, and every product is listed.
    assert sum(len(products) for products in OS_FAMILIES.values()) == len(OsProduct)
    assert set(OS_FAMILY) == set(OsProduct)
    assert set(OS_FAMILY.values()) == set(OsFamily)


def test_os_version_is_allowlisted_and_bounded_cwe_1286():
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
