"""Role/binding use cases and locked activation snapshots. No transport or session operations."""

from dataclasses import dataclass
from uuid import UUID

from apps.accounts.selectors import users
from apps.audit.changes import snapshot
from apps.rbac import events
from apps.rbac.catalog import SUPPORTED_PERMISSIONS, catalog_permissions
from apps.rbac.exceptions import RbacError
from apps.rbac.models import Role, RoleAssignment
from apps.rbac.policy import administrative
from apps.teams.selectors import memberships, teams
from apps.teams.validation import validate_code, validate_name


@administrative
def create_role(principal, *, code, name):
    validate_code(code)
    name = name.strip() if isinstance(name, str) else name
    validate_name(name)
    role = Role.objects.create(code=code, name=name)
    events.emit(principal, "rbac.role_created", role, fields=("code", "name"))
    return role


@administrative
def update_role(principal, role_id, *, name):
    role = Role.objects.select_for_update().get(pk=role_id)
    name = name.strip() if isinstance(name, str) else name
    validate_name(name)
    before = snapshot(role, ("name",))
    if role.name == name:
        raise RbacError("The role name is unchanged.")
    role.name = name
    role.save(update_fields=["name"])
    events.emit(principal, "rbac.role_updated", role, before=before, fields=("name",))
    return role


def _permission(code):
    if code not in SUPPORTED_PERMISSIONS:
        raise RbacError("Unsupported permission.")
    return catalog_permissions(code).get()


@administrative
def grant_permission(principal, role_id, permission_code):
    role = Role.objects.select_for_update().get(pk=role_id)
    permission = _permission(permission_code)
    if role.permissions.filter(pk=permission.pk).exists():
        raise RbacError("Permission already granted.")
    role.permissions.add(permission)
    events.emit(
        principal, "rbac.permission_granted", role, metadata={"permission_code": permission_code}
    )
    return role


@administrative
def revoke_permission(principal, role_id, permission_code):
    role = Role.objects.select_for_update().get(pk=role_id)
    permission = _permission(permission_code)
    if not role.permissions.filter(pk=permission.pk).exists():
        raise RbacError("Permission is not granted.")
    role.permissions.remove(permission)
    events.emit(
        principal, "rbac.permission_revoked", role, metadata={"permission_code": permission_code}
    )
    return role


def _locked_membership(membership_id):
    team_id = memberships().values_list("team_id", flat=True).get(pk=membership_id)
    teams().select_for_update().get(pk=team_id)
    return memberships().select_for_update().get(pk=membership_id, team_id=team_id)


def _binding_metadata(binding, membership):
    return {
        "membership_id": str(membership.pk),
        "user_id": str(membership.user_id),
        "team_id": str(membership.team_id),
        "role_id": str(binding.role_id),
        "scope_type": "team",
        "scope_id": str(membership.team_id),
    }


@administrative
def assign_role(principal, membership_id, role_id):
    role = Role.objects.select_for_update().get(pk=role_id)
    team_id = memberships().values_list("team_id", flat=True).get(pk=membership_id)
    teams().select_for_update().get(pk=team_id)
    user_id = memberships().values_list("user_id", flat=True).get(pk=membership_id)
    if not users().select_for_update().get(pk=user_id).is_active:
        raise RbacError("New grants require an enabled account.")
    membership = memberships().select_for_update().get(pk=membership_id, team_id=team_id)
    binding = RoleAssignment.objects.create(membership=membership, role=role)
    events.emit(
        principal, "rbac.role_assigned", binding, metadata=_binding_metadata(binding, membership)
    )
    return binding


@administrative
def revoke_role(principal, membership_id, role_id):
    membership = _locked_membership(membership_id)
    binding = RoleAssignment.objects.select_for_update().get(membership=membership, role_id=role_id)
    events.emit(
        principal, "rbac.role_revoked", binding, metadata=_binding_metadata(binding, membership)
    )
    binding_id = binding.pk
    binding.delete()
    return binding_id


@dataclass(frozen=True, slots=True)
class ActivationPreview:
    team_id: UUID
    code: str
    name: str
    membership_count: int
    role_assignment_count: int
    revision: tuple


def locked_activation_snapshot(team_id):
    """Caller holds an atomic block. Never lock a newly discovered Role after locking Team."""
    candidate_roles = set(
        RoleAssignment.objects.filter(membership__team_id=team_id).values_list("role_id", flat=True)
    )
    list(Role.objects.select_for_update().filter(pk__in=candidate_roles).order_by("pk"))
    team = teams().select_for_update().get(pk=team_id)
    member_rows = tuple(memberships().filter(team=team).order_by("pk").values_list("id", "user_id"))
    binding_rows = tuple(
        RoleAssignment.objects.filter(membership__team=team)
        .order_by("pk")
        .values_list("id", "membership_id", "role_id")
    )
    current_roles = {row[2] for row in binding_rows}
    if not current_roles <= candidate_roles:
        raise RbacError("Configuration changed; request a new activation preview.")
    permission_rows = tuple(
        Role.permissions.through.objects.filter(role_id__in=current_roles)
        .order_by("pk")
        .values_list("id", "role_id", "permission_id")
    )
    revision = (team.pk, team.is_active, member_rows, binding_rows, permission_rows)
    return team, ActivationPreview(
        team.pk, team.code, team.name, len(member_rows), len(binding_rows), revision
    )
