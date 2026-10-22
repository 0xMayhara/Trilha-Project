"""Admin-only reads (SPEC-0010 BR-12): every user, team, membership, role, the catalog and the audit
trail. Each call authorizes first with fresh SQL, before any lookup, so non-Admins learn nothing
about which IDs exist (SEC-19). Reads take no locks and are logged, never audited (BR-16)."""

from django.db.models import BooleanField, Count, F, OuterRef, Prefetch, Q, Subquery, Value
from django.db.models.functions import Coalesce

from apps.accounts.selectors import users
from apps.audit.selectors import search_events
from apps.rbac.catalog import SUPPORTED_PERMISSIONS, catalog_action, catalog_permissions
from apps.rbac.policy import require_admin_read
from apps.rbac.selectors import assignments, roles
from apps.teams.selectors import memberships, teams

DIRECTORY = "read_directory"


def _users():
    return users().annotate(
        is_admin=Coalesce(
            F("platform_access__is_admin"), Value(False), output_field=BooleanField()
        ),
        position=F("platform_access__position"),
    )


def _members():
    grants = assignments().select_related("role").order_by("role__code", "pk")
    team_size = (
        memberships()
        .filter(team_id=OuterRef("team_id"))
        .values("team_id")
        .annotate(size=Count("pk"))
        .values("size")
    )
    return (
        memberships()
        .select_related("team", "user")
        .annotate(
            team_member_count=Subquery(team_size),
            user_position=F("user__platform_access__position"),
        )
        .prefetch_related(Prefetch("role_assignments", queryset=grants, to_attr="display_roles"))
    )


def user_directory(principal, *, q=None, is_active=None, is_admin=None, position=None):
    require_admin_read(principal, DIRECTORY)
    rows = _users()
    if q is not None:
        rows = rows.filter(
            Q(username__icontains=q)
            | Q(first_name__icontains=q)
            | Q(last_name__icontains=q)
            | Q(email__icontains=q)
        )
    if is_active is not None:
        rows = rows.filter(is_active=is_active)
    if is_admin is not None:
        rows = rows.filter(is_admin=is_admin)
    if position == "none":
        rows = rows.filter(position__isnull=True)
    elif position is not None:
        rows = rows.filter(position=position)
    return rows.order_by("username", "pk")


def user_detail(principal, user_id):
    """Raises the model's DoesNotExist for a missing user (adapters answer 404)."""
    user = user_directory(principal).get(pk=user_id)
    user.display_memberships = list(_members().filter(user_id=user.pk).order_by("team__code"))
    return user


def team_directory(principal, *, q=None, is_active=None):
    require_admin_read(principal, DIRECTORY)
    rows = teams().annotate(member_count=Count("memberships"))
    if q is not None:
        rows = rows.filter(Q(code__icontains=q) | Q(name__icontains=q))
    if is_active is not None:
        rows = rows.filter(is_active=is_active)
    return rows.order_by("code", "pk")


def team_detail(principal, team_id):
    return team_directory(principal).get(pk=team_id)


def team_members(principal, team_id):
    team = team_detail(principal, team_id)
    return _members().filter(team_id=team.pk).order_by("user__username", "pk")


def membership_detail(principal, membership_id):
    require_admin_read(principal, DIRECTORY)
    return _members().get(pk=membership_id)


def role_directory(principal, *, q=None):
    require_admin_read(principal, DIRECTORY)
    rows = roles().prefetch_related(
        Prefetch(
            "permissions",
            queryset=catalog_permissions().select_related("content_type"),
            to_attr="display_permissions",
        )
    )
    if q is not None:
        rows = rows.filter(Q(code__icontains=q) | Q(name__icontains=q))
    return rows.order_by("code", "pk")


def role_detail(principal, role_id):
    return role_directory(principal).get(pk=role_id)


def permission_catalog(principal):
    require_admin_read(principal, DIRECTORY)
    return [
        {"code": code, "action": catalog_action(code)} for code in sorted(SUPPORTED_PERMISSIONS)
    ]


def audit_search(principal, **filters):
    require_admin_read(principal, "search_audit")
    return search_events(**filters)
