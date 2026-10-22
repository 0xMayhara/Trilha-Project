"""Disables an account and removes its password, ending every session (SPEC-0003 BR-05).

Runs the SPEC-0010 `disable_account` use case: an Admin's grant is removed with the account, and the
last enabled Admin cannot be disabled (BR-06)."""

from django.core.management.base import BaseCommand

from apps.accounts.management.output import report
from apps.rbac.administration import disable_account
from apps.rbac.management.adapters import account_command, account_id


class Command(BaseCommand):
    help = "Disable an account. Its password is removed and every session ends."

    def add_arguments(self, parser):
        parser.add_argument("username")

    @account_command
    def handle(self, principal, options):
        user = disable_account(principal, account_id(options["username"]))
        report("accounts_disable_user", user, self.stdout)
        self.stdout.write(f"Disabled {user.username}; all of its sessions have ended.")
