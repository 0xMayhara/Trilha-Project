"""Readiness probe for container healthchecks. Runs inside the container, so readiness is never
exposed over HTTP (SPEC-0001 Scope 7). The backend and the worker also refuse to report ready while
connected as anything but the restricted runtime role (SPEC-0013 SEC-11), or while an integrity
check fails, such as an unregistered transfer participant (SPEC-0007 SEC-19)."""

import logging

from django.conf import settings
from django.core import checks
from django.core.cache import cache
from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from apps.core.db_privileges import runtime_role_failures

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Exit with a non-zero status unless the database and cache are reachable."

    def handle(self, *args, **options) -> None:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                failures = (
                    runtime_role_failures(cursor) if settings.DB_REQUIRE_RESTRICTED_ROLE else []
                )
            cache.get("readiness-probe")
        except Exception as exc:
            logger.warning("Readiness check failed", extra={"error_type": type(exc).__name__})
            raise CommandError("Not ready.") from None
        if failures:
            logger.warning("database_role_check_failed", extra={"checks": failures})
            raise CommandError("Not ready.")
        if errors := [m.id for m in checks.run_checks(tags=["trilha_integrity"]) if m.is_serious()]:
            logger.warning("integrity_check_failed", extra={"checks": errors})
            raise CommandError("Not ready.")
        self.stdout.write("ready")
