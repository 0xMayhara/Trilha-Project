"""SPEC-0007 slice B storage: finding and logbook constraints, append-only guards and trigger, and
the migrations on a populated database. Runtime-role privileges are proven in test_db_roles.py."""

import uuid

import psycopg.errors
import pytest
from django.db import IntegrityError, connection, transaction
from django.db.migrations.exceptions import IrreversibleError
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.assets.models import Asset
from apps.audit.context import audit_source
from apps.findings.models import Finding, FindingLogEntry, LogEntryImmutable
from tests.test_assets_security import make_team, make_user

pytestmark = pytest.mark.django_db

PREVIOUS = ("assets", "0003_asset_security_posture")


@pytest.fixture
def finding():
    with audit_source("command"):
        team = make_team("alpha")
    reporter = make_user("reporter")
    asset = Asset.objects.create(team=team, name="Web 01", kind="server")
    return Finding.objects.create(
        asset=asset,
        title="Outdated TLS",
        category="vulnerability",
        severity="high",
        reported_by=reporter,
        log_sequence=1,
    )


def entry(finding, **fields):
    values = {"finding": finding, "sequence": 1, "kind": "system", "event": "finding_created"}
    return FindingLogEntry(**{**values, **fields})


def violates(constraint, create):
    with pytest.raises(IntegrityError) as raised, transaction.atomic():
        create()
    assert raised.value.__cause__.diag.constraint_name == constraint


def test_finding_constraints_reject_invalid_rows(finding):
    def update(**fields):
        return lambda: Finding.objects.filter(pk=finding.pk).update(**fields)

    for constraint, fields in (
        ("finding_category", {"category": "other_thing"}),
        ("finding_severity", {"severity": "unknown"}),
        ("finding_status", {"status": "resolved"}),
        ("finding_title_nonempty", {"title": ""}),
        ("finding_title_nfc", {"title": "Cafe" + chr(0x301)}),
        ("finding_version", {"version": 0}),
        ("finding_log_sequence", {"log_sequence": -1}),
        ("finding_cve_count", {"cve_ids": [f"CVE-2024-{1000 + n}" for n in range(21)]}),
    ):
        violates(constraint, update(**fields))
    for bad in (
        ["cve-2024-1234"],
        ["CVE-2024-123"],
        ["CVE-2024-1234 "],
        ["CVE-2024-1234,CVE-2024-5678"],  # two IDs in one element
        ["CVE-2024-1234", ""],
        ["CVE-2024-1234", None],
        ["CVE-24-1234"],
        ["CVE-2024-" + "1" * 20],
    ):
        violates("finding_cve_ids", update(cve_ids=bad))
    Finding.objects.filter(pk=finding.pk).update(cve_ids=["CVE-2021-44228", "CVE-2024-3094"])


def test_logbook_constraints_reject_invalid_entries(finding):
    key = uuid.uuid4()
    actor = finding.reported_by
    entry(finding).save()
    violates("logentry_finding_sequence", lambda: entry(finding).save())
    comment = {"kind": "comment", "event": "", "actor": actor, "body": "Hi", "idempotency_key": key}
    for constraint, fields in (
        ("logentry_sequence", {"sequence": 0}),
        ("logentry_kind", {"kind": "note"}),
        ("logentry_system_shape", {"body": "text"}),
        ("logentry_system_shape", {"event": "Bad-Event"}),
        ("logentry_system_shape", {"event": ""}),
        ("logentry_system_shape", {"idempotency_key": key}),
        ("logentry_comment_shape", {**comment, "actor": None}),
        ("logentry_comment_shape", {**comment, "idempotency_key": None}),
        ("logentry_comment_shape", {**comment, "body": ""}),
        ("logentry_comment_shape", {**comment, "body": "x" * 4001}),
        ("logentry_comment_shape", {**comment, "event": "assigned"}),
        ("logentry_comment_shape", {**comment, "metadata": {"forged": True}}),
        ("logentry_redaction_complete", {"redacted_at": timezone.now()}),
        ("logentry_redaction_complete", {"redaction_reason": "secret"}),
        ("logentry_redaction_complete", {"redacted_at": timezone.now(), "redaction_reason": "x"}),
        (
            "logentry_redacted_blank",
            {
                "redacted_at": timezone.now(),
                "redaction_reason": "secret",
                "metadata": {"reason": "r"},
            },
        ),
    ):
        violates(
            constraint, lambda fields=fields: entry(finding, **{"sequence": 2, **fields}).save()
        )
    entry(finding, sequence=2, **comment).save()
    violates(
        "logentry_actor_idempotency",
        lambda: entry(finding, sequence=3, **comment).save(),
    )
    entry(finding, sequence=3, **{**comment, "idempotency_key": uuid.uuid4()}).save()


def test_logbook_entries_cannot_change_through_the_orm(finding):
    saved = entry(finding)
    saved.save()
    rows = FindingLogEntry.objects.filter(pk=saved.pk)
    saved.body = "forged"
    for attempt in (
        saved.save,
        saved.delete,
        lambda: rows.update(event="assigned"),
        rows.delete,
        lambda: FindingLogEntry.objects.bulk_update([saved], ["body"]),
        lambda: FindingLogEntry.objects.bulk_create(
            [entry(finding)],
            update_conflicts=True,
            unique_fields=["finding", "sequence"],
            update_fields=["event"],
        ),
        lambda: finding.log_entries.all().delete(),
    ):
        with pytest.raises(LogEntryImmutable):
            attempt()
    assert FindingLogEntry.objects.get(pk=saved.pk).event == "finding_created"


def _sql(statement, params):
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(statement, params)


def test_trigger_accepts_only_the_one_way_redaction_shape_for_the_owner(finding):
    key = uuid.uuid4()
    comment = entry(
        finding, kind="comment", event="", actor=finding.reported_by, body="token=abc",
        idempotency_key=key,
    )  # fmt: skip
    comment.save()
    redact = (
        "UPDATE findings_findinglogentry SET body = '', metadata = metadata - 'reason',"
        " redacted_at = now(), redaction_reason = 'secret' WHERE id = %s"
    )
    refused = [
        ("DELETE FROM findings_findinglogentry WHERE id = %s", [comment.pk]),
        ("UPDATE findings_findinglogentry SET body = 'reworded' WHERE id = %s", [comment.pk]),
        ("UPDATE findings_findinglogentry SET body = '' WHERE id = %s", [comment.pk]),  # no trace
        (redact.replace("redacted_at = now()", "redacted_at = now(), sequence = 9"), [comment.pk]),
        (redact.replace("body = ''", "body = 'x'"), [comment.pk]),
        (
            redact.replace(
                "redaction_reason = 'secret'", "redaction_reason = 'secret', actor_id = NULL"
            ),
            [comment.pk],
        ),
        (redact.replace("metadata - 'reason'", "'{\"x\": 1}'::jsonb"), [comment.pk]),
    ]
    for statement, params in refused:
        with pytest.raises(IntegrityError) as raised:
            _sql(statement, params)
        assert isinstance(raised.value.__cause__, psycopg.errors.RestrictViolation), statement
    _sql(redact, [comment.pk])  # the table owner may blank it once
    stored = FindingLogEntry.objects.get(pk=comment.pk)
    assert (stored.body, stored.redaction_reason, stored.sequence) == ("", "secret", 1)
    assert stored.idempotency_key == key and stored.actor_id == finding.reported_by_id
    with pytest.raises(IntegrityError):  # never a second time
        _sql(redact, [comment.pk])
    with pytest.raises(IntegrityError):
        _sql("DELETE FROM findings_findinglogentry WHERE id = %s", [comment.pk])


def _migrate(target):
    connection.check_constraints()
    executor = MigrationExecutor(connection)
    executor.migrate(target)
    return executor


def _latest():
    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())


def test_spec_0007_migrations_apply_on_populated_database_and_keep_rows():
    with audit_source("command"):
        team = make_team("alpha")
    try:
        _migrate([("findings", None)])  # empty tables: the reversal is allowed
        assert "findings_finding" not in connection.introspection.table_names()
        _migrate([PREVIOUS])
        Asset.objects.create(team=team, name="Web 01", kind="server", criticality="high")
        before = list(Asset.objects.values())
        _latest()
        assert list(Asset.objects.values()) == before
        asset = Asset.objects.get()
        finding = Finding.objects.create(
            asset=asset, title="T", category="other", severity="low", reported_by=make_user("u")
        )
        assert (finding.status, finding.version, finding.log_sequence) == ("open", 1, 0)
        with pytest.raises(IrreversibleError, match="park-tables"):
            _migrate([("findings", None)])
        assert Finding.objects.filter(pk=finding.pk).exists()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM pg_trigger WHERE tgname = 'findings_logentry_append_only'"
                " AND tgenabled = 'O'"
            )
            assert cursor.fetchone() == (1,)
    finally:
        _latest()
