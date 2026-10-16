"""Append-only audit table enforced by PostgreSQL (SPEC-0002 SEC-03, ADR-0003).

Irreversible on purpose (SEC-04): rolling back the audit app would drop the table and destroy the
audit trail, so `migrate audit zero` raises IrreversibleError instead.
"""

from django.db import migrations

CREATE_FUNCTION = """
CREATE FUNCTION audit_auditevent_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only'
        USING ERRCODE = 'restrict_violation';
END;
$$;
"""

CREATE_TRIGGER = """
CREATE TRIGGER audit_auditevent_append_only
    BEFORE UPDATE OR DELETE ON audit_auditevent
    FOR EACH ROW EXECUTE FUNCTION audit_auditevent_append_only();
"""


class Migration(migrations.Migration):
    dependencies = [
        ("audit", "0001_initial"),
    ]

    operations = [
        migrations.RunSQL(sql=[CREATE_FUNCTION, CREATE_TRIGGER]),
    ]
