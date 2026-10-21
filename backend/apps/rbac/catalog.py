from functools import reduce
from operator import or_

from django.contrib.auth.models import Permission
from django.db.models import Q

SUPPORTED_PERMISSIONS = {"teams.view_team": ("view_team", "teams", "team")}
PERMISSION_CODES = {key: code for code, key in SUPPORTED_PERMISSIONS.items()}


def catalog_permissions(*codes):
    """Rows for the given supported codes (all when omitted); callers reject unknown codes first."""
    # Full natural keys avoid accidentally accepting the same codename on another model.
    keys = (SUPPORTED_PERMISSIONS[code] for code in codes or SUPPORTED_PERMISSIONS)
    return Permission.objects.filter(
        reduce(
            or_,
            (
                Q(codename=codename, content_type__app_label=app, content_type__model=model)
                for codename, app, model in keys
            ),
        )
    )
