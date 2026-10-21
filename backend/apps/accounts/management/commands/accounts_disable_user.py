"""Disables an account and removes its password, ending every session (SPEC-0003 BR-05)."""

from django.core.management.base import BaseCommand, CommandError

from apps.accounts import services
from apps.accounts.management.output import report
from apps.audit.context import audit_source


class Command(BaseCommand):
    help = "Disable an account. Its password is removed and every session ends."

    def add_arguments(self, parser):
        parser.add_argument("username")

    def handle(self, *args, **options):
        try:
            with audit_source("command"):
                user = services.disable_user(options["username"])
        except services.AccountError as exc:
            raise CommandError(str(exc)) from None
        report("accounts_disable_user", user, self.stdout)
        self.stdout.write(f"Disabled {user.username}; all of its sessions have ended.")
