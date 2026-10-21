from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command, role_id
from apps.rbac.services import update_role


class Command(BaseCommand):
    help = "Update role through the audited domain service."

    def add_arguments(self, parser):
        parser.add_argument("role_code")
        parser.add_argument("--name", required=True)

    @operator_command
    def handle(self, principal, options):
        result = update_role(principal, role_id(options["role_code"]), name=options["name"])
        self.stdout.write(f"Completed update_role for {options['role_code']}: {result}")
