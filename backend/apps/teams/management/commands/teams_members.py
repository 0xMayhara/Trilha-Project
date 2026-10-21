from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command, team_id
from apps.rbac.policy import require_administration
from apps.teams.selectors import memberships


class Command(BaseCommand):
    help = "Inspect memberships of a configured team."

    def add_arguments(self, parser):
        parser.add_argument("team_code")

    @operator_command
    def handle(self, principal, options):
        require_administration(principal, "inspect_configuration")
        for member in memberships().filter(team_id=team_id(options["team_code"])).order_by("pk"):
            self.stdout.write(f"{member.pk} user={member.user_id} team={member.team_id}")
