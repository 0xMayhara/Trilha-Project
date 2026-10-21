"""Each decision constructs fresh SQL; prefetched display data is never authoritative."""

from django.db.models import Exists, OuterRef, Prefetch

from apps.rbac.catalog import SUPPORTED_PERMISSIONS, catalog_permissions
from apps.rbac.models import Role, RoleAssignment
from apps.rbac.principals import UserPrincipal
from apps.teams.selectors import memberships, teams


def eligible_memberships(principal):
    if not isinstance(principal, UserPrincipal):
        return memberships().none()
    return memberships().filter(
        user_id=principal.user_id, user__is_active=True, team__is_active=True
    )


def scoped_teams(principal):
    return teams().filter(Exists(eligible_memberships(principal).filter(team_id=OuterRef("pk"))))


def authorized_teams(principal, permission="teams.view_team", *, scope_type="team", action="view"):
    if permission not in SUPPORTED_PERMISSIONS or scope_type != "team" or action != "view":
        return teams().none()
    grants = RoleAssignment.objects.filter(
        membership__in=eligible_memberships(principal),
        membership__team_id=OuterRef("pk"),
        role__permissions__in=catalog_permissions(permission),
    )
    return teams().filter(Exists(grants))


def can_access(principal, permission, *, team_id, scope_type="team", action="view"):
    return (
        authorized_teams(principal, permission, scope_type=scope_type, action=action)
        .filter(pk=team_id)
        .exists()
    )


def own_access(principal):
    grants = (
        RoleAssignment.objects.select_related("role")
        .order_by("role__code")
        .prefetch_related(
            Prefetch(
                "role__permissions",
                queryset=catalog_permissions().select_related("content_type"),
                to_attr="display_permissions",
            )
        )
    )
    return (
        eligible_memberships(principal)
        .select_related("team")
        .order_by("team__code", "team_id")
        .prefetch_related(
            Prefetch("role_assignments", queryset=grants, to_attr="display_assignments")
        )
    )


def roles():
    return Role.objects.all()


def assignments():
    return RoleAssignment.objects.all()
