from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command
from apps.rbac.policy import require_administration
from apps.teams.selectors import teams


class Command(BaseCommand):
    help = "Inspect configured teams, including inactive teams."

    @operator_command
    def handle(self, principal, options):
        require_administration(principal, "inspect_configuration")
        for team in teams().order_by("code").iterator():
            self.stdout.write(f"{team.code} {team.pk} active={team.is_active} {team.name}")
