from django.core.management.base import BaseCommand

from apps.rbac.management.adapters import operator_command
from apps.rbac.policy import require_administration
from apps.rbac.selectors import roles


class Command(BaseCommand):
    help = "Inspect reusable roles and their shared permission definitions."

    @operator_command
    def handle(self, principal, options):
        require_administration(principal, "inspect_configuration")
        for role in (
            roles()
            .order_by("code")
            .prefetch_related("permissions__content_type")
            .iterator(chunk_size=100)
        ):
            codes = sorted(
                f"{p.content_type.app_label}.{p.codename}" for p in role.permissions.all()
            )
            self.stdout.write(f"{role.code} {role.pk} {role.name}: {', '.join(codes)}")
