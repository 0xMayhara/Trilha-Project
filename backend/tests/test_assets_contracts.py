"""SPEC-0005 contracts: migration, validation canonical forms and module boundaries."""

import ast
import importlib
from pathlib import Path

import pytest
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor

from apps.assets.models import Asset
from apps.assets.validation import canonical_hostname, canonical_ip, canonical_ip_list
from apps.audit.context import audit_source
from apps.rbac.models import Role
from apps.rbac.principals import infrastructure_operator
from apps.teams import services as teams

pytestmark = pytest.mark.django_db
OPERATOR = infrastructure_operator()


@pytest.fixture
def team(db):
    with audit_source("command"):
        return teams.create_team(OPERATOR, code="alpha", name="Alpha")


def test_assets_migration_is_additive_and_empty_database_reversible():
    with connection.cursor() as cursor:
        cursor.execute("SHOW server_encoding")
        assert cursor.fetchone()[0] == "UTF8"  # IS NFC NORMALIZED requires it.
    asset_permissions = Permission.objects.filter(content_type__app_label="assets")
    assert sorted(asset_permissions.values_list("codename", flat=True)) == [
        "add_asset",
        "change_asset",
        "retire_asset",
        "transfer_asset",
        "view_asset",
    ]
    # Capabilities exist, but nobody holds them: no grant is seeded.
    assert not Role.permissions.through.objects.filter(permission__in=asset_permissions).exists()
    assert Asset.objects.count() == 0
    executor = MigrationExecutor(connection)
    original = executor.loader.graph.leaf_nodes()
    try:
        executor.migrate([("assets", None)])
        tables = connection.introspection.table_names()
        assert "assets_asset" not in tables
        assert {"teams_team", "rbac_role", "audit_auditevent", "accounts_user"} <= set(tables)
    finally:
        MigrationExecutor(connection).migrate(original)
    assert "assets_asset" in connection.introspection.table_names()


def test_database_rejects_non_nfc_asset_text(team):
    for field, constraint in (("name", "asset_name_nfc"), ("operating_system", "asset_os_nfc")):
        values = {"name": "Server", field: "Café"}
        with pytest.raises(IntegrityError, match=constraint), transaction.atomic():
            Asset.objects.create(team=team, kind="server", **values)
    Asset.objects.create(team=team, kind="server", name="Café", operating_system="Café")


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "fe80::1",
        "fd00::1",
        "8.8.8.8",
        "2001:4860::8888",
        "100.64.0.1",
        "192.0.2.1",
        "240.0.0.1",
        "0.1.2.3",
        "10.0.0.255",
    ],
)
def test_ip_class_policy_uses_explicit_predicates_only(value):
    # Accepted: private, link-local, ULA, public, and ranges that is_reserved/is_global reject.
    # 10.0.0.255 may be a subnet-directed broadcast; that cannot be known without a prefix.
    assert str(canonical_ip(value)) == value
    for rejected in (
        "0.0.0.0",  # noqa: S104 - rejection test data, not a bind address
        "::",
        "127.0.0.1",
        "127.255.255.254",
        "::1",
        "::ffff:127.0.0.1",
        "224.0.0.1",
        "239.255.255.250",
        "ff02::1",
        "255.255.255.255",
    ):
        with pytest.raises(ValidationError):
            canonical_ip(rejected)


def test_ip_canonical_forms_and_ordering():
    assert str(canonical_ip("::ffff:10.0.0.5")) == "10.0.0.5"
    assert str(canonical_ip("2001:DB8:0:0:1:0:0:1")) == "2001:db8::1:0:0:1"
    assert canonical_ip_list(["2001:db8:0:0:0:0:0:1", "2001:db8::1"]) == ["2001:db8::1"]
    assert canonical_ip_list(["10.0.0.10", "2001:db8::1", "10.0.0.9", "10.0.0.9"]) == [
        "10.0.0.9",
        "10.0.0.10",
        "2001:db8::1",
    ]
    for bad in ("010.0.0.5", "10.1", "10.0.0.5/32", "[::1]", "fe80::1%eth0", " 10.0.0.5", "x" * 46):
        with pytest.raises(ValidationError):
            canonical_ip(bad)
    for bad_list in ([f"10.0.0.{n}" for n in range(1, 18)], [1], "10.0.0.1"):
        with pytest.raises(ValidationError):
            canonical_ip_list(bad_list)


def test_hostname_requires_strict_dns_form():
    assert canonical_hostname("Web-01.Example.COM") == "web-01.example.com"
    assert canonical_hostname("xn--bcher-kva.example") == "xn--bcher-kva.example"
    assert canonical_hostname("") == ""
    for bad in (
        "web_01",
        "bücher.example",
        "example.com.",
        "-a.example",
        "a..b",
        "10.0.0.5",
        "a" * 64,
        ("a" * 63 + ".") * 4 + "a",
        " web",
        5,
    ):
        with pytest.raises(ValidationError):
            canonical_hostname(bad)


def test_assets_uses_public_interfaces_without_circular_imports():
    root = Path(__file__).resolve().parents[1] / "apps"
    for module in ("apps.assets.models", "apps.assets.validation", "config.urls"):
        importlib.import_module(module)
    for path in (root / "assets").rglob("*.py"):
        if "migrations" in path.parts:
            continue
        source = path.read_text()
        assert "AuditEvent" not in source
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module != "apps.accounts.models"
                assert not node.module.startswith("apps.integrations")
                assert not node.module.startswith(("apps.rbac.models", "apps.teams.models"))
    for app in ("rbac", "teams", "accounts", "audit", "core"):
        for path in (root / app).rglob("*.py"):
            assert "apps.assets" not in path.read_text(), path
