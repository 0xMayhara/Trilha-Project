"""Readiness probe for container healthchecks. Runs inside the container, so readiness is never
exposed over HTTP (SPEC-0001 Scope 7)."""

import logging

from django.core.cache import cache
from django.core.management.base import BaseCommand, CommandError
from django.db import connection

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Exit with a non-zero status unless the database and cache are reachable."

    def handle(self, *args, **options) -> None:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            cache.get("readiness-probe")
        except Exception as exc:
            logger.warning("Readiness check failed", extra={"error_type": type(exc).__name__})
            raise CommandError("Not ready.") from None
        self.stdout.write("ready")
