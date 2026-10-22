"""Grants platform Admin authority, the only path to the first Admin (SPEC-0010 BR-15)."""

from django.core.management.base import BaseCommand

from apps.rbac.administration import grant_admin
from apps.rbac.management.adapters import account_command, account_id


class Command(BaseCommand):
    help = "Grant platform Admin authority to an enabled account (audited)."

    def add_arguments(self, parser):
        parser.add_argument("username")

    @account_command
    def handle(self, principal, options):
        grant_admin(principal, account_id(options["username"]))
        self.stdout.write(f"Granted Admin authority to {options['username']}.")
