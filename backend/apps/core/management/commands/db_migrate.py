"""Migrate as the schema owner, then apply the runtime role's grants (SPEC-0013 FR-02).

The `migrate` service runs this instead of `migrate`. Concurrent runs (podman-compose re-runs the
finished job for each dependent service) serialize on an advisory lock held on a connection of its
own, because `migrate` may recycle Django's connection. A run whose grants already match the policy
changes nothing; otherwise one transaction revokes and re-grants under a bounded lock wait."""

import logging
import time

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, connections, transaction

from apps.core import db_privileges

logger = logging.getLogger(__name__)
LOCK_KEY = 0x5452494C  # "TRIL"


class Command(BaseCommand):
    help = "Apply migrations, then the runtime role's grants from the privilege policy."

    def handle(self, *args, **options):
        runtime = settings.POSTGRES_RUNTIME_USER
        if not db_privileges.ROLE_NAME.fullmatch(runtime):
            raise CommandError("Set POSTGRES_RUNTIME_USER to the runtime role's name.")
        started = time.monotonic()
        lock = connections.create_connection("default")
        try:
            with lock.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_lock(%s)", [LOCK_KEY])
            call_command("migrate", interactive=False, verbosity=options["verbosity"])
            changed = self._grant(runtime)
        finally:
            lock.close()  # ends that session, which releases the advisory lock
        outcome = "db_grants_applied" if changed else "db_grants_unchanged"
        logger.info(
            outcome,
            extra={
                "runtime_role": runtime,
                "tables": len(db_privileges.TABLE_PRIVILEGES),
                "duration_ms": round((time.monotonic() - started) * 1000),
            },
        )
        self.stdout.write(f"{outcome}: runtime role {runtime}")

    def _grant(self, runtime):
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout = '5s'")
            reasons = db_privileges.refusal_reasons(cursor, runtime)
            if reasons:
                logger.error("db_grants_refused", extra={"reasons": reasons})
                raise CommandError("Runtime grants refused: " + "; ".join(reasons))
            if not db_privileges.drift(cursor, runtime):
                return False
            db_privileges.apply(cursor, runtime)
            if remaining := db_privileges.drift(cursor, runtime):
                logger.error("db_grants_refused", extra={"reasons": remaining})
                raise CommandError(
                    "Runtime grants do not match the policy: " + "; ".join(remaining)
                )
            return True
