"""Append-only logbook enforced by PostgreSQL (SPEC-0007 Data Model, SEC-24, SEC-48; ADR-0003
pattern).

Every DELETE is refused. An UPDATE is refused unless it is the one-way emergency redaction of BR-51,
run by the table owner (the runtime role holds no UPDATE privilege and cannot even try): the entry is
not yet redacted, the content is blanked, `redacted_at` and `redaction_reason` are set, and nothing
else changes. A second redaction of the same entry is refused.

Reversible only while both tables are empty (fresh databases and tests): reversing further would
drop findings and their logbook. With rows present the reversal refuses, and a code rollback below
this release parks the tables instead (deploy/postgres/park-tables.sh)."""

from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError

CREATE_FUNCTION = """
CREATE FUNCTION findings_logentry_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
        AND current_user = (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = TG_RELID)
        AND OLD.redacted_at IS NULL
        AND NEW.redacted_at IS NOT NULL
        AND NEW.redaction_reason IS NOT NULL
        AND NEW.body = ''
        AND NEW.metadata = OLD.metadata - 'reason'
        AND NEW.id = OLD.id
        AND NEW.finding_id = OLD.finding_id
        AND NEW.sequence = OLD.sequence
        AND NEW.kind = OLD.kind
        AND NEW.event = OLD.event
        AND NEW.actor_id IS NOT DISTINCT FROM OLD.actor_id
        AND NEW.idempotency_key IS NOT DISTINCT FROM OLD.idempotency_key
        AND NEW.created_at = OLD.created_at
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'finding log entries are append-only'
        USING ERRCODE = 'restrict_violation';
END;
$$;
"""

CREATE_TRIGGER = """
CREATE TRIGGER findings_logentry_append_only
    BEFORE UPDATE OR DELETE ON findings_findinglogentry
    FOR EACH ROW EXECUTE FUNCTION findings_logentry_append_only();
"""


DROP = [
    "DROP TRIGGER findings_logentry_append_only ON findings_findinglogentry;",
    "DROP FUNCTION findings_logentry_append_only();",
]


def refuse_unless_empty(apps, schema_editor):
    for model in ("Finding", "FindingLogEntry"):
        if apps.get_model("findings", model).objects.exists():
            raise IrreversibleError(
                "Findings exist: reversing would destroy them. Park the tables instead "
                "(deploy/postgres/park-tables.sh)."
            )


class Migration(migrations.Migration):
    dependencies = [
        ("findings", "0001_initial"),
    ]

    operations = [
        migrations.RunSQL(sql=[CREATE_FUNCTION, CREATE_TRIGGER], reverse_sql=DROP),
        # Reversed first: nothing is dropped while a row exists.
        migrations.RunPython(migrations.RunPython.noop, reverse_code=refuse_unless_empty),
    ]
