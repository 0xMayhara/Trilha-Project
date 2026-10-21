"""Prints a one-time link to set (or reset) an active account's password (SPEC-0003)."""

from django.core.management.base import BaseCommand, CommandError

from apps.accounts import services
from apps.accounts.management.output import report
from apps.accounts.models import User
from apps.audit.context import audit_source


class Command(BaseCommand):
    help = "Print a one-time link that lets the account's owner set a new password."

    def add_arguments(self, parser):
        parser.add_argument("username")

    def handle(self, *args, **options):
        try:
            with audit_source("command"):
                link = services.issue_password_link(options["username"])
        except services.AccountError as exc:
            raise CommandError(str(exc)) from None
        user = User.objects.get(username=options["username"])
        report("accounts_password_link", user, self.stdout, link)
