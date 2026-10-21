"""Creates an account without a password and prints its one-time setup link (SPEC-0003)."""

from django.core.management.base import BaseCommand, CommandError

from apps.accounts import services
from apps.accounts.management.output import report
from apps.audit.context import audit_source


class Command(BaseCommand):
    help = "Create an account (lowercase ASCII username) and print its one-time setup link."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("--first-name", default="")
        parser.add_argument("--last-name", default="")
        parser.add_argument("--email", default="")

    def handle(self, *args, **options):
        try:
            with audit_source("command"):
                user, link = services.create_user(
                    options["username"],
                    first_name=options["first_name"],
                    last_name=options["last_name"],
                    email=options["email"],
                )
        except services.AccountError as exc:
            raise CommandError(str(exc)) from None
        report("accounts_create_user", user, self.stdout, link)
