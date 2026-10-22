"""Team and membership transitions; every supported write locks Team and emits atomic audit."""

from apps.accounts.selectors import users
from apps.audit.changes import snapshot
from apps.rbac import events
from apps.rbac.exceptions import RbacConflict
from apps.rbac.policy import administrative
from apps.rbac.selectors import assignments
from apps.rbac.services import locked_activation_snapshot, revoke_role
from apps.teams.models import Membership, Team
from apps.teams.validation import validate_code, validate_name


@administrative
def create_team(principal, *, code, name):
    validate_code(code)
    name = name.strip() if isinstance(name, str) else name
    validate_name(name)
    team = Team.objects.create(code=code, name=name)
    events.emit(principal, "teams.team_created", team, fields=("code", "name", "is_active"))
    return team


@administrative
def update_team(principal, team_id, *, name):
    team = Team.objects.select_for_update().get(pk=team_id)
    name = name.strip() if isinstance(name, str) else name
    validate_name(name)
    before = snapshot(team, ("name",))
    if team.name == name:
        raise RbacConflict("unchanged", "The team name is unchanged.")
    team.name = name
    team.save(update_fields=["name"])
    events.emit(principal, "teams.team_updated", team, before=before, fields=("name",))
    return team


@administrative
def deactivate_team(principal, team_id):
    team = Team.objects.select_for_update().get(pk=team_id)
    if not team.is_active:
        raise RbacConflict("state", "Team is already inactive.")
    before = snapshot(team, ("is_active",))
    team.is_active = False
    team.save(update_fields=["is_active"])
    events.emit(principal, "teams.team_deactivated", team, before=before, fields=("is_active",))
    return team


@administrative
def preview_team_activation(principal, team_id):
    team, preview = locked_activation_snapshot(team_id)
    if team.is_active:
        raise RbacConflict("state", "Team is already active.")
    return preview


@administrative
def activate_team(principal, team_id, expected_revision, confirmation_code):
    team, preview = locked_activation_snapshot(team_id)
    if team.is_active or confirmation_code != team.code or expected_revision != preview.revision:
        raise RbacConflict(
            "state", "Activation requires matching confirmation and a current inactive preview."
        )
    before = snapshot(team, ("is_active",))
    team.is_active = True
    team.save(update_fields=["is_active"])
    events.emit(
        principal,
        "teams.team_activated",
        team,
        before=before,
        fields=("is_active",),
        metadata={
            "membership_count": preview.membership_count,
            "role_assignment_count": preview.role_assignment_count,
        },
    )
    return team


@administrative
def add_member(principal, team_id, user_id):
    team = Team.objects.select_for_update().get(pk=team_id)
    user = users().select_for_update().get(pk=user_id)
    if not user.is_active:
        raise RbacConflict("state", "New memberships require an enabled account.")
    membership = Membership.objects.create(team=team, user=user)
    events.emit(principal, "teams.membership_created", membership, fields=("user_id", "team_id"))
    return membership


@administrative
def remove_member(principal, team_id, user_id):
    team = Team.objects.select_for_update().get(pk=team_id)
    membership = Membership.objects.select_for_update().get(team=team, user_id=user_id)
    role_ids = list(
        assignments().filter(membership=membership).order_by("pk").values_list("role_id", flat=True)
    )
    for role_id in role_ids:
        revoke_role(principal, membership.pk, role_id)
    events.emit(
        principal,
        "teams.membership_removed",
        membership,
        before=snapshot(membership, ("user_id", "team_id")),
        fields=("user_id", "team_id"),
        removed=True,
    )
    membership_id = membership.pk
    membership.delete()
    return membership_id
