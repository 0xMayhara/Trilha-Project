"""Read-only verification of the keyed audit content digests (SPEC-0007 SEC-53).

Comment digests (`findings.comment_added`) are checked against the stored comment; description
digests of each finding's latest create or update event against its current description. Counts
only: no content, digest or key is printed. A digest whose key is not in the ring is reported as
unverifiable, never as valid or mismatch. Exits non-zero on any mismatch or missing entry. Runs in
the backend container, the only one holding the key ring."""

import uuid
from collections import Counter

from django.core.management.base import BaseCommand, CommandError

from apps.audit.digests import MISMATCH, UNVERIFIABLE, VALID, verify_digest
from apps.audit.selectors import resource_events
from apps.findings.models import Finding, FindingLogEntry
from apps.findings.services import DIGEST_CONTEXT

BATCH = 500
OUTCOMES = (VALID, MISMATCH, UNVERIFIABLE)


def _by_text_id(model, ids):
    # Audit events reference resources by text; in_bulk keys are UUIDs.
    return {str(pk): row for pk, row in model.objects.in_bulk(ids).items()}


def _batches(rows):
    batch = []
    for row in rows:
        batch.append(row)
        if len(batch) == BATCH:
            yield batch
            batch = []
    if batch:
        yield batch


class Command(BaseCommand):
    help = "Verify audit content digests of findings and comments (read-only, counts only)."

    def add_arguments(self, parser):
        parser.add_argument("--finding", help="limit to one finding UUID")

    def handle(self, *args, **options):
        finding = options.get("finding")
        if finding:
            try:
                finding = str(uuid.UUID(finding))
            except ValueError:
                raise CommandError("--finding must be a UUID.") from None
        comments, descriptions, keys = Counter(), Counter(), set()

        def tally(counter, text, digest):
            outcome, key_id = verify_digest(text, digest, context=DIGEST_CONTEXT)
            counter[outcome] += 1
            if outcome == UNVERIFIABLE:
                keys.add(key_id)

        added = resource_events(
            actions=("findings.comment_added",),
            resource_type="findings.findinglogentry",
            metadata={"finding_id": finding} if finding else None,
        )
        for batch in _batches(added.values("resource_id", "metadata").iterator()):
            entries = _by_text_id(FindingLogEntry, [row["resource_id"] for row in batch])
            for row in batch:
                entry = entries.get(row["resource_id"])
                if entry is None:
                    comments["missing"] += 1
                elif entry.redacted_at is not None:
                    comments["redacted"] += 1  # content removed on purpose (BR-51)
                else:
                    tally(comments, entry.body, row["metadata"].get("body_digest"))

        changed = resource_events(
            actions=("findings.finding_created", "findings.finding_updated"),
            resource_type="findings.finding",
            resource_id=finding or None,
        )
        latest = {}  # oldest first, so the last digest seen per finding is the current one
        for row in changed.values("resource_id", "action", "changes", "metadata").iterator():
            if row["action"] == "findings.finding_created":
                latest[row["resource_id"]] = row["metadata"].get("description_digest")
            elif "description_digest" in row["changes"]:
                latest[row["resource_id"]] = row["changes"]["description_digest"].get("after")
        for batch in _batches(list(latest.items())):
            findings = _by_text_id(Finding, [finding_id for finding_id, _ in batch])
            for finding_id, digest in batch:
                current = findings.get(finding_id)
                if current is None:
                    descriptions["missing"] += 1
                else:
                    tally(descriptions, current.description, digest)

        for name, counter, extra in (
            ("comments", comments, ("redacted", "missing")),
            ("descriptions", descriptions, ("missing",)),
        ):
            counts = " ".join(f"{key}={counter[key]}" for key in (*OUTCOMES, *extra))
            self.stdout.write(f"{name}: {counts}")
        for key_id in sorted(keys):
            self.stdout.write(f"unverifiable: key {key_id} not configured")
        if any(counter[MISMATCH] or counter["missing"] for counter in (comments, descriptions)):
            raise CommandError("Digest verification found mismatches or missing records.")
