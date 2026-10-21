import sys

from django.core.management.base import BaseCommand, CommandError

from apps.rbac.management.adapters import operator_command, team_id
from apps.teams.services import activate_team, preview_team_activation


class Command(BaseCommand):
    help = "Activate a team after reviewing and explicitly confirming retained grants."

    def add_arguments(self, parser):
        parser.add_argument("team_code")

    @operator_command
    def handle(self, principal, options):
        preview = preview_team_activation(principal, team_id(options["team_code"]))
        self.stdout.write(f"Team {preview.code} ({preview.team_id}): {preview.name}")
        self.stdout.write(
            f"Restoring {preview.membership_count} memberships and "
            f"{preview.role_assignment_count} role assignments."
        )
        self.stdout.write("Counts include retained configuration; disabled accounts remain denied.")
        if not sys.stdin.isatty():
            raise CommandError("Interactive terminal confirmation is required.")
        try:
            confirmation = input(f"Type {preview.code} to activate: ")
        except (EOFError, KeyboardInterrupt):
            raise CommandError("Activation cancelled.") from None
        if confirmation != preview.code:
            raise CommandError("Activation cancelled.")
        activate_team(principal, preview.team_id, preview.revision, confirmation)
        self.stdout.write(f"Activated {preview.code} ({preview.team_id}).")
