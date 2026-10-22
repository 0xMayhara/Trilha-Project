"""Creates an account without a password and prints its one-time setup link (SPEC-0003).

Runs the SPEC-0010 `create_account` use case with the operator principal, so the CLI and the web UI
share one path; events keep the `accounts-cli` label."""

from django.core.management.base import BaseCommand

from apps.accounts.management.output import report
from apps.rbac.administration import create_account
from apps.rbac.management.adapters import account_command


class Command(BaseCommand):
    help = "Create an account (lowercase ASCII username) and print its one-time setup link."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("--first-name", default="")
        parser.add_argument("--last-name", default="")
        parser.add_argument("--email", default="")

    @account_command
    def handle(self, principal, options):
        user, link = create_account(
            principal,
            username=options["username"],
            first_name=options["first_name"],
            last_name=options["last_name"],
            email=options["email"],
        )
        report("accounts_create_user", user, self.stdout, link)
