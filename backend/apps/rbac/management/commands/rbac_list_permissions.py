from django.core.management.base import BaseCommand

from apps.rbac.catalog import SUPPORTED_PERMISSIONS
from apps.rbac.management.adapters import operator_command
from apps.rbac.policy import require_administration


class Command(BaseCommand):
    help = "Inspect the supported native permission catalog."

    @operator_command
    def handle(self, principal, options):
        require_administration(principal, "inspect_configuration")
        for code in sorted(SUPPORTED_PERMISSIONS):
            self.stdout.write(code)
