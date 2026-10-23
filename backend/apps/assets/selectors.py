"""Scoped asset reads. Every call builds fresh SQL from the RBAC selectors; nothing is cached."""

from django.db.models import Q

from apps.assets.exceptions import AssetForbidden, AssetNotFound
from apps.assets.models import OS_FAMILY, Asset, OsProduct
from apps.rbac.selectors import authorized_teams, can_access, is_platform_admin, scoped_teams

VIEW = "assets.view_asset"


def scoped_assets(principal):
    """Assets of the principal's eligible teams: the scope that separates 404 from 403."""
    return Asset.objects.filter(team__in=scoped_teams(principal))


def visible_assets(principal):
    """Assets the principal may view, through the same membership that grants the permission. A
    current platform Admin reads every team's assets (SPEC-0010 BR-12). This widens reads only:
    mutations scope through `scoped_assets`, unchanged (SEC-23)."""
    if is_platform_admin(principal):
        return Asset.objects.all()
    return Asset.objects.filter(team__in=authorized_teams(principal, VIEW))


def search_assets(
    principal,
    *,
    status,
    team_id=None,
    kind=None,
    environment=None,
    criticality=None,
    ip=None,
    q=None,
):
    """Filters run in SQL after scoping, so rows and counts never include hidden assets."""
    assets = visible_assets(principal).filter(status=status)
    if team_id is not None:
        assets = assets.filter(team_id=team_id)
    for field, value in (
        ("kind", kind),
        ("environment", environment),
        ("criticality", criticality),
    ):
        if value is not None:
            assets = assets.filter(**{field: value})
    if ip is not None:
        assets = assets.filter(ip_addresses__contains=[ip])  # exact address, never a prefix
    if q is not None:
        assets = assets.filter(Q(name__icontains=q) | Q(hostname__icontains=q))
    return assets.select_related("team").order_by("name", "id")


def os_catalog():
    """The OS catalog in display order with derived families (SPEC-0011). Constant: no query."""
    return [
        {
            "code": product.value,
            "label": product.label,
            "family": OS_FAMILY[product].value,
            "family_label": OS_FAMILY[product].label,
        }
        for product in OsProduct
    ]


def viewable_asset(principal, asset_id):
    if is_platform_admin(principal):
        try:
            return Asset.objects.select_related("team").get(pk=asset_id)
        except Asset.DoesNotExist:
            raise AssetNotFound from None
    try:
        asset = scoped_assets(principal).select_related("team").get(pk=asset_id)
    except Asset.DoesNotExist:
        raise AssetNotFound from None
    if not can_access(principal, VIEW, team_id=asset.team_id):
        raise AssetForbidden(asset.pk)
    return asset
