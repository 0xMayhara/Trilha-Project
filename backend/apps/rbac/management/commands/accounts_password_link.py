"""Prints a one-time link to set (or reset) an active account's password (SPEC-0003).

Runs the SPEC-0010 `issue_password_link` use case with the operator principal."""

from django.core.management.base import BaseCommand

from apps.accounts.management.output import report
from apps.accounts.selectors import users
from apps.rbac.administration import issue_password_link
from apps.rbac.management.adapters import account_command, account_id


class Command(BaseCommand):
    help = "Print a one-time link that lets the account's owner set a new password."

    def add_arguments(self, parser):
        parser.add_argument("username")

    @account_command
    def handle(self, principal, options):
        user_id = account_id(options["username"])
        link = issue_password_link(principal, user_id)
        report("accounts_password_link", users().get(pk=user_id), self.stdout, link)
