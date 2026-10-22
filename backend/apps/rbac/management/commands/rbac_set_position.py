"""Sets or clears an account's operational position (SPEC-0010 BR-04). Positions grant nothing."""

from django.core.management.base import BaseCommand

from apps.rbac.administration import set_position
from apps.rbac.management.adapters import account_command, account_id
from apps.rbac.models import Position

NONE = "none"


class Command(BaseCommand):
    help = "Set the operational position of an account: analyst, engineer or none (audited)."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("position", choices=[*Position.values, NONE])

    @account_command
    def handle(self, principal, options):
        position = None if options["position"] == NONE else options["position"]
        set_position(principal, account_id(options["username"]), position)
        self.stdout.write(f"Set the position of {options['username']} to {options['position']}.")
