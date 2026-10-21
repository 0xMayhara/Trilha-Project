"""Re-enables an account and prints a setup link; no previous password returns (SPEC-0003 BR-05)."""

from django.core.management.base import BaseCommand, CommandError

from apps.accounts import services
from apps.accounts.management.output import report
from apps.audit.context import audit_source


class Command(BaseCommand):
    help = "Enable an account and print a one-time link to set a new password."

    def add_arguments(self, parser):
        parser.add_argument("username")

    def handle(self, *args, **options):
        try:
            with audit_source("command"):
                user, link = services.enable_user(options["username"])
        except services.AccountError as exc:
            raise CommandError(str(exc)) from None
        report("accounts_enable_user", user, self.stdout, link)
