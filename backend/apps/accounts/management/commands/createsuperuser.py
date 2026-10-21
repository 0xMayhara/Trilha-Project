"""Replaces Django's createsuperuser, which changes accounts without an audit event
(SPEC-0003 BR-10).

apps.accounts is listed before django.contrib.auth in INSTALLED_APPS, so this command wins.
"""

import sys

from django.core.management.base import BaseCommand, CommandError

MESSAGE = "createsuperuser is disabled in Trilha: use 'manage.py accounts_create_user' (audited)."


class Command(BaseCommand):
    help = MESSAGE

    def run_from_argv(self, argv):
        # Refuse before parsing, whatever options were given.
        self.stderr.write(MESSAGE)
        sys.exit(1)

    def handle(self, *args, **options):
        raise CommandError(MESSAGE)
