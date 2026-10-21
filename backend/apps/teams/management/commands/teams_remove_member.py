from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command, team_id, user_id
from apps.teams.services import remove_member


class Command(BaseCommand):
    help = "Remove member through the audited domain service."

    def add_arguments(self, parser):
        parser.add_argument("team_code")
        parser.add_argument("username")

    @operator_command
    def handle(self, principal, options):
        result = remove_member(
            principal, team_id(options["team_code"]), user_id(options["username"])
        )
        self.stdout.write(f"Completed remove_member for {options['team_code']}: {result}")
