from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command, role_id
from apps.rbac.services import grant_permission


class Command(BaseCommand):
    help = "Grant permission through the audited domain service."

    def add_arguments(self, parser):
        parser.add_argument("role_code")
        parser.add_argument("permission_code")

    @operator_command
    def handle(self, principal, options):
        result = grant_permission(
            principal, role_id(options["role_code"]), options["permission_code"]
        )
        self.stdout.write(f"Completed grant_permission for {options['role_code']}: {result}")
