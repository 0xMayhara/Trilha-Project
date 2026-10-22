"""Revokes platform Admin authority; at least one other enabled Admin must remain (BR-06)."""

from django.core.management.base import BaseCommand

from apps.rbac.administration import revoke_admin
from apps.rbac.management.adapters import account_command, account_id


class Command(BaseCommand):
    help = "Revoke platform Admin authority (audited). Another enabled Admin must remain."

    def add_arguments(self, parser):
        parser.add_argument("username")

    @account_command
    def handle(self, principal, options):
        revoke_admin(principal, account_id(options["username"]))
        self.stdout.write(f"Revoked Admin authority from {options['username']}.")
