from functools import reduce
from operator import or_

from django.contrib.auth.models import Permission
from django.db.models import Q

SUPPORTED_PERMISSIONS = {
    "teams.view_team": ("view_team", "teams", "team"),
    # SPEC-0005: asset actions are bound to the owning team's membership like every other code.
    "assets.view_asset": ("view_asset", "assets", "asset"),
    "assets.add_asset": ("add_asset", "assets", "asset"),
    "assets.change_asset": ("change_asset", "assets", "asset"),
    "assets.retire_asset": ("retire_asset", "assets", "asset"),
    "assets.transfer_asset": ("transfer_asset", "assets", "asset"),
    # SPEC-0007: bound to the membership of the finding's asset's current team.
    "findings.view_finding": ("view_finding", "findings", "finding"),
    "findings.add_finding": ("add_finding", "findings", "finding"),
    "findings.change_finding": ("change_finding", "findings", "finding"),
    "findings.comment_finding": ("comment_finding", "findings", "finding"),
    "findings.work_finding": ("work_finding", "findings", "finding"),
    "findings.override_priority": ("override_priority", "findings", "finding"),
}
PERMISSION_CODES = {key: code for code, key in SUPPORTED_PERMISSIONS.items()}


def catalog_action(code):
    """The one action a supported code authorizes: its native codename before the first "_"."""
    return SUPPORTED_PERMISSIONS[code][0].split("_", 1)[0]


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
