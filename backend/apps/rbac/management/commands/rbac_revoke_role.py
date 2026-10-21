from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import membership_id, operator_command, role_id
from apps.rbac.services import revoke_role


class Command(BaseCommand):
    help = "Revoke role through the audited domain service."

    def add_arguments(self, parser):
        parser.add_argument("team_code")
        parser.add_argument("username")
        parser.add_argument("role_code")

    @operator_command
    def handle(self, principal, options):
        result = revoke_role(
            principal,
            membership_id(options["team_code"], options["username"]),
            role_id(options["role_code"]),
        )
        self.stdout.write(f"Completed revoke_role for {options['role_code']}: {result}")
