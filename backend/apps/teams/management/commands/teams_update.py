from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command, team_id
from apps.teams.services import update_team


class Command(BaseCommand):
    help = "Update team through the audited domain service."

    def add_arguments(self, parser):
        parser.add_argument("team_code")
        parser.add_argument("--name", required=True)

    @operator_command
    def handle(self, principal, options):
        result = update_team(principal, team_id(options["team_code"]), name=options["name"])
        self.stdout.write(f"{result.code} {result.pk} active={result.is_active} {result.name}")
