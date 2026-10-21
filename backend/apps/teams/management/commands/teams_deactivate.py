from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command, team_id
from apps.teams.services import deactivate_team


class Command(BaseCommand):
    help = "Deactivate team through the audited domain service."

    def add_arguments(self, parser):
        parser.add_argument("team_code")

    @operator_command
    def handle(self, principal, options):
        result = deactivate_team(principal, team_id(options["team_code"]))
        self.stdout.write(f"Completed deactivate_team for {options['team_code']}: {result}")
