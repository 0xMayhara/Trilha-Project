from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command, role_id
from apps.rbac.services import revoke_permission


class Command(BaseCommand):
    help = "Revoke permission through the audited domain service."

    def add_arguments(self, parser):
        parser.add_argument("role_code")
        parser.add_argument("permission_code")

    @operator_command
    def handle(self, principal, options):
        result = revoke_permission(
            principal, role_id(options["role_code"]), options["permission_code"]
        )
        self.stdout.write(f"Completed revoke_permission for {options['role_code']}: {result}")
