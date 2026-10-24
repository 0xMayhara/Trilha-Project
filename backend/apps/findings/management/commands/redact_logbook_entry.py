"""Owner-controlled emergency redaction of one logbook entry (SPEC-0007 BR-51, SEC-48).

Not a user feature: it runs on a recorded owner decision, with the schema-owner credential (the
`migrate` container), because only the table owner may attempt the one-way shape the trigger
accepts; the runtime role has no UPDATE privilege on the logbook. Without --execute it is a dry run.
It never prints or logs the content, nor its length after redaction. Rotate a leaked secret first:
redaction is not secure erasure (see the README runbook).

    python manage.py redact_logbook_entry --finding <uuid> --sequence <n> \\
        --reason secret|personal_data --ticket <ref> [--execute]"""

import logging
import re
import uuid

from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, connection, transaction

from apps.audit.context import audit_source
from apps.audit.services import record_event
from apps.audit.types import Actor, Resource
from apps.findings.models import Finding, FindingLogEntry, LogKind, RedactionReason
from apps.rbac.locking import bound_lock_waits

logger = logging.getLogger("apps.findings")
TICKET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._#/-]{0,63}")
# System entries whose "reason" is free text an actor typed (BR-51); others hold only codes.
REDACTABLE_EVENTS = frozenset(
    {"priority_overridden", "priority_override_revalidated", "priority_override_cleared"}
)
# Static SQL; the trigger findings_logentry_append_only accepts exactly this shape, once.
REDACT = (
    "UPDATE findings_findinglogentry SET body = '', metadata = metadata - 'reason',"
    " redacted_at = now(), redaction_reason = %s WHERE id = %s"
)


class Command(BaseCommand):
    help = "Blank one logbook entry on a recorded owner decision (dry run unless --execute)."

    def add_arguments(self, parser):
        parser.add_argument("--finding", required=True, help="finding UUID")
        parser.add_argument("--sequence", required=True, type=int, help="entry sequence")
        parser.add_argument("--reason", required=True, choices=RedactionReason.values)
        parser.add_argument("--ticket", required=True, help="reference of the owner decision")
        parser.add_argument("--execute", action="store_true", help="redact (default: dry run)")

    def handle(self, *args, **options):
        try:
            finding_id = uuid.UUID(options["finding"])
        except ValueError:
            raise CommandError("--finding must be a UUID.") from None
        if not TICKET.fullmatch(options["ticket"]):
            raise CommandError("--ticket must be a short reference (letters, digits, ._#/-).")
        sequence, reason, ticket = options["sequence"], options["reason"], options["ticket"]
        if not options["execute"]:
            entry = self._entry(finding_id, sequence)
            author = entry.actor.username if entry.actor else "-"
            self.stdout.write(
                f"dry run: entry {entry.pk} kind={entry.kind} author={author} "
                f"created={entry.created_at.isoformat()} body_length={len(entry.body)}; "
                "add --execute to redact"
            )
            return
        try:
            with audit_source("command"), transaction.atomic():
                bound_lock_waits("5s")
                finding = Finding.objects.select_for_update().get(pk=finding_id)
                entry = self._entry(finding_id, sequence)
                with connection.cursor() as cursor:
                    cursor.execute(REDACT, [reason, entry.pk])
                finding.log_sequence += 1
                finding.save(update_fields=["log_sequence"])
                FindingLogEntry(
                    finding=finding,
                    sequence=finding.log_sequence,
                    kind=LogKind.SYSTEM,
                    event="entry_redacted",
                    metadata={"sequence": sequence, "redaction_reason": reason},
                ).save()
                record_event(
                    actor=Actor.system("trilha-operator"),
                    action="findings.logbook_entry_redacted",
                    resource=Resource.of(entry),
                    metadata={
                        "finding_id": str(finding_id),
                        "sequence": sequence,
                        "redaction_reason": reason,
                        "ticket": ticket,
                    },
                )
        except (Finding.DoesNotExist, DatabaseError) as exc:
            # The database text may quote the row: report the refusal without it.
            raise CommandError("Redaction refused; nothing changed.") from exc
        logger.info(
            "logbook_entry_redacted",
            extra={
                "finding_id": str(finding_id),
                "entry_id": str(entry.pk),
                "sequence": sequence,
                "redaction_reason": reason,
                "ticket": ticket,
            },
        )
        self.stdout.write(f"redacted entry {entry.pk} (sequence {sequence}, reason {reason})")

    def _entry(self, finding_id, sequence):
        entry = (
            FindingLogEntry.objects.select_related("actor")
            .filter(finding_id=finding_id, sequence=sequence)
            .first()
        )
        if entry is None:
            raise CommandError("No logbook entry has that finding and sequence.")
        if entry.redacted_at is not None:
            raise CommandError("The entry is already redacted.")
        override = entry.event in REDACTABLE_EVENTS and "reason" in entry.metadata
        if entry.kind != LogKind.COMMENT and not override:
            raise CommandError("Only comments and override reasons can be redacted.")
        return entry
