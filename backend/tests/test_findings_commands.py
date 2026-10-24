"""SPEC-0007 BR-51 / SEC-48 and SEC-53: the emergency redaction and digest verification commands.
Role separation (owner credential only) is proven on a real PostgreSQL in test_db_roles.py."""

import io
import uuid

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection, transaction
from django.test import override_settings

from apps.audit.context import audit_source
from apps.audit.digests import content_digest
from apps.audit.models import AuditEvent
from apps.audit.services import record_event
from apps.audit.types import Actor, Resource
from apps.findings.models import Finding, FindingLogEntry
from apps.findings.services import DIGEST_CONTEXT
from tests.test_findings_api import build_world, client_for, detail, logbook

pytestmark = pytest.mark.django_db
SECRET = "pasted credential marker"  # synthetic: the text a user pasted by mistake


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


@pytest.fixture
def world(db):
    return build_world()


def comment(finding, user, body):
    """A comment as slice C will store it: next sequence under the row lock, keyed digest."""
    with transaction.atomic():
        locked = Finding.objects.select_for_update().get(pk=finding.pk)
        locked.log_sequence += 1
        locked.save(update_fields=["log_sequence"])
        entry = FindingLogEntry.objects.create(
            finding=locked,
            sequence=locked.log_sequence,
            kind="comment",
            actor=user,
            body=body,
            idempotency_key=uuid.uuid4(),
        )
        record_event(
            actor=Actor.user(user),
            action="findings.comment_added",
            resource=Resource.of(entry),
            metadata={
                "finding_id": str(locked.pk),
                "sequence": entry.sequence,
                "body_digest": content_digest(body, context=DIGEST_CONTEXT),
                "body_length": len(body),
            },
        )
    return entry


def run(name, *args):
    out = io.StringIO()
    call_command(name, *args, stdout=out)
    return out.getvalue()


def redact(finding, sequence, *extra, reason="secret", ticket="OPS-42"):
    args = ["--finding", str(finding.pk), "--sequence", str(sequence)]
    return run("redact_logbook_entry", *args, "--reason", reason, "--ticket", ticket, *extra)


def test_redaction_is_a_dry_run_by_default_and_blanks_one_way_with_execute(world, caplog):
    entry = comment(world.finding, world.reporter, SECRET)
    before = list(FindingLogEntry.objects.order_by("pk").values())
    dry = redact(world.finding, entry.sequence)
    assert f"entry {entry.pk} kind=comment author=reporter" in dry
    assert f"body_length={len(SECRET)}" in dry and "dry run" in dry
    assert list(FindingLogEntry.objects.order_by("pk").values()) == before
    caplog.set_level("INFO")
    done = redact(world.finding, entry.sequence, "--execute")
    assert done == f"redacted entry {entry.pk} (sequence {entry.sequence}, reason secret)\n"
    stored = FindingLogEntry.objects.get(pk=entry.pk)
    assert (stored.body, stored.redaction_reason, stored.actor_id) == (
        "",
        "secret",
        world.reporter.pk,
    )
    assert stored.redacted_at is not None and stored.idempotency_key == entry.idempotency_key
    notice = FindingLogEntry.objects.get(finding=world.finding, event="entry_redacted")
    assert (notice.kind, notice.actor_id, notice.sequence) == ("system", None, entry.sequence + 1)
    assert notice.metadata == {"sequence": entry.sequence, "redaction_reason": "secret"}
    assert Finding.objects.get(pk=world.finding.pk).log_sequence == entry.sequence + 1
    event = AuditEvent.objects.get(action="findings.logbook_entry_redacted")
    assert (event.actor_type, event.actor_label, event.source) == (
        "system",
        "trilha-operator",
        "command",
    )
    assert (event.resource_type, event.resource_id) == ("findings.findinglogentry", str(entry.pk))
    assert event.metadata == {
        "finding_id": str(world.finding.pk),
        "sequence": entry.sequence,
        "redaction_reason": "secret",
        "ticket": "OPS-42",
    }
    # The original comment event keeps its keyed digest only; nothing anywhere holds the secret.
    added = AuditEvent.objects.get(action="findings.comment_added")
    assert SECRET not in str(added.metadata) and "body_digest" in added.metadata
    assert SECRET not in dry + done + caplog.text
    # The API shows a placeholder, and polling clients learn of it from the notice.
    page = logbook(client_for(world.reporter), world.finding).json()["results"]
    shown = next(row for row in page if row["sequence"] == entry.sequence)
    assert (shown["body"], shown["redacted"], shown["redaction_reason"]) == (None, True, "secret")
    assert page[-1]["event"] == "entry_redacted"
    with pytest.raises(CommandError, match="already redacted"):
        redact(world.finding, entry.sequence, "--execute")


def _system_entry(finding, event, metadata):
    with transaction.atomic():
        locked = Finding.objects.select_for_update().get(pk=finding.pk)
        locked.log_sequence += 1
        locked.save(update_fields=["log_sequence"])
        return FindingLogEntry.objects.create(
            finding=locked,
            sequence=locked.log_sequence,
            kind="system",
            event=event,
            metadata=metadata,
        )


def test_redaction_blanks_only_free_text_override_reasons_among_system_entries(world):
    # Slice D and E entry shapes: a coded reason is not content; an override reason is.
    coded = _system_entry(world.finding, "work_stopped", {"reason": "reassigned"})
    with pytest.raises(CommandError, match="Only comments and override reasons"):
        redact(world.finding, coded.sequence, "--execute")
    assert FindingLogEntry.objects.get(pk=coded.pk).metadata == {"reason": "reassigned"}
    override = _system_entry(
        world.finding, "priority_overridden", {"level": "p3", "reason": "contact +55 11 9999"}
    )
    redact(world.finding, override.sequence, "--execute", reason="personal_data")
    stored = FindingLogEntry.objects.get(pk=override.pk)
    assert (stored.metadata, stored.body, stored.redaction_reason) == (
        {"level": "p3"},
        "",
        "personal_data",
    )


def test_redaction_refuses_invalid_requests_without_change(world):
    entry = comment(world.finding, world.reporter, "fine")
    before = (
        list(FindingLogEntry.objects.order_by("pk").values()),
        AuditEvent.objects.count(),
    )
    for args, message in (
        (["--finding", "nope", "--sequence", "2", "--reason", "secret", "--ticket", "T-1"], "UUID"),
        (["--finding", str(world.finding.pk), "--sequence", "9", "--reason", "secret",
          "--ticket", "T-1", "--execute"], "No logbook entry"),
        (["--finding", str(world.finding.pk), "--sequence", "1", "--reason", "secret",
          "--ticket", "T-1", "--execute"], "Only comments"),  # finding_created: nothing to blank
        (["--finding", str(world.finding.pk), "--sequence", str(entry.sequence), "--reason",
          "secret", "--ticket", "bad ticket; rm -rf", "--execute"], "ticket"),
    ):  # fmt: skip
        with pytest.raises(CommandError, match=message):
            run("redact_logbook_entry", *args)
    for missing in ("--ticket", "--reason"):
        args = ["--finding", str(world.finding.pk), "--sequence", "2", "--reason", "secret"]
        args += ["--ticket", "T-1"]
        index = args.index(missing)
        with pytest.raises(CommandError):
            run("redact_logbook_entry", *(args[:index] + args[index + 2 :]), "--execute")
    with pytest.raises(CommandError):
        redact(world.finding, entry.sequence, "--execute", reason="opinion")
    assert (
        list(FindingLogEntry.objects.order_by("pk").values()),
        AuditEvent.objects.count(),
    ) == before
    # No HTTP path exists for any of it (SEC-23).
    client = client_for(world.reporter)
    for method in ("patch", "put", "delete"):
        assert getattr(client, method)(detail(world.finding, "logbook/")).status_code == 405


def test_verify_logbook_digests_counts_outcomes_across_key_rotation(world):
    keys = {"k1": b"1" * 32, "k2": b"2" * 32}
    with override_settings(AUDIT_DIGEST_KEYS={"k1": keys["k1"]}, AUDIT_DIGEST_ACTIVE_KEY_ID="k1"):
        old = comment(world.finding, world.reporter, "signed with k1")
        world.client.patch(
            detail(world.finding), {"version": 1, "description": "k1 text"}, format="json"
        )
    with override_settings(AUDIT_DIGEST_KEYS=keys, AUDIT_DIGEST_ACTIVE_KEY_ID="k2"):
        comment(world.finding, world.reporter, "signed with k2")
        comment(world.beta_finding, world.keeper, "beta, k2")
        output = run("verify_logbook_digests")
        assert output.splitlines() == [
            "comments: valid=3 mismatch=0 unverifiable=0 redacted=0 missing=0",
            "descriptions: valid=1 mismatch=0 unverifiable=1 missing=0",
            "unverifiable: key test not configured",  # beta_finding was created under the test key
        ]
        one = run("verify_logbook_digests", "--finding", str(world.finding.pk))
        assert (
            one.splitlines()[0]
            == "comments: valid=2 mismatch=0 unverifiable=0 redacted=0 missing=0"
        )
        assert "signed with" not in output + one  # counts only
    # Retiring k1 makes its digests unverifiable, never mismatched.
    with override_settings(AUDIT_DIGEST_KEYS={"k2": keys["k2"]}, AUDIT_DIGEST_ACTIVE_KEY_ID="k2"):
        retired = run("verify_logbook_digests", "--finding", str(world.finding.pk))
        assert retired.splitlines() == [
            "comments: valid=1 mismatch=0 unverifiable=1 redacted=0 missing=0",
            "descriptions: valid=0 mismatch=0 unverifiable=1 missing=0",
            "unverifiable: key k1 not configured",
        ]
    # Tampering by the owner (raw SQL on the description) is a mismatch and a failing exit.
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE findings_finding SET description = 'forged' WHERE id = %s", [world.finding.pk]
        )
    with override_settings(AUDIT_DIGEST_KEYS=keys, AUDIT_DIGEST_ACTIVE_KEY_ID="k2"):
        with pytest.raises(CommandError, match="mismatches"):
            run("verify_logbook_digests", "--finding", str(world.finding.pk))
        redact(world.finding, old.sequence, "--execute")
        out = io.StringIO()
        with pytest.raises(CommandError):
            call_command("verify_logbook_digests", "--finding", str(world.finding.pk), stdout=out)
        assert out.getvalue().splitlines()[0] == (
            "comments: valid=1 mismatch=0 unverifiable=0 redacted=1 missing=0"
        )
    with pytest.raises(CommandError, match="UUID"):
        run("verify_logbook_digests", "--finding", "x")
