from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command
from apps.rbac.services import create_role


class Command(BaseCommand):
    help = "Create role through the audited domain service."

    def add_arguments(self, parser):
        parser.add_argument("code")
        parser.add_argument("--name", required=True)

    @operator_command
    def handle(self, principal, options):
        result = create_role(principal, code=options["code"], name=options["name"])
        self.stdout.write(f"Completed create_role for {options['code']}: {result}")
