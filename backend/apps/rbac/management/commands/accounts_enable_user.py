"""Re-enables an account and prints a setup link; no previous password returns (SPEC-0003 BR-05).

Runs the SPEC-0010 `enable_account` use case: Admin authority is never restored (BR-06d)."""

from django.core.management.base import BaseCommand

from apps.accounts.management.output import report
from apps.rbac.administration import enable_account
from apps.rbac.management.adapters import account_command, account_id


class Command(BaseCommand):
    help = "Enable an account and print a one-time link to set a new password."

    def add_arguments(self, parser):
        parser.add_argument("username")

    @account_command
    def handle(self, principal, options):
        user, link = enable_account(principal, account_id(options["username"]))
        report("accounts_enable_user", user, self.stdout, link)
