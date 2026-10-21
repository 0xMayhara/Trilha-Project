from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command
from apps.teams.services import create_team


class Command(BaseCommand):
    help = "Create team through the audited domain service."

    def add_arguments(self, parser):
        parser.add_argument("code")
        parser.add_argument("--name", required=True)

    @operator_command
    def handle(self, principal, options):
        result = create_team(principal, code=options["code"], name=options["name"])
        self.stdout.write(f"{result.code} {result.pk} active={result.is_active} {result.name}")
