"""Platform administration use cases (SPEC-0010): Admin grants, positions and account
administration. Each runs through `administrative`, and the account use cases wrap the `accounts`
primitives inside the same transaction, so HTTP and CLI share one path and one set of guards
(BR-06, BR-17). Lock order: target User, then the Admin set last (ADR-0007 §7)."""

import uuid

from apps.accounts import services as accounts
from apps.accounts.selectors import users
from apps.audit.types import Actor
from apps.rbac import events
from apps.rbac.exceptions import RbacConflict, RbacInvalid, RbacNotFound
from apps.rbac.models import PlatformAccess, Position
from apps.rbac.policy import administrative, locked_admin_set
from apps.rbac.principals import UserPrincipal, is_infrastructure_operator

_ADMIN = ("is_admin",)
_POSITION = ("position",)


def _uuid(value):
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (TypeError, ValueError):
        raise RbacNotFound from None


def _is_self(principal, user_id):
    return isinstance(principal, UserPrincipal) and principal.user_id == user_id


def _account_actor(principal):
    # Operator account events keep their historical label (BR-17, SEC-34).
    if is_infrastructure_operator(principal):
        return accounts.CLI_ACTOR
    return Actor.user(users().get(pk=principal.user_id))


def _username(user_id):
    return users().values_list("username", flat=True).get(pk=user_id)


def _account_call(call):
    """Maps the primitives' errors to typed RBAC errors; messages are fixed server text."""
    try:
        return call()
    except accounts.AccountNotFound as exc:
        raise RbacNotFound from exc
    except accounts.AccountConflict as exc:
        raise RbacConflict(exc.reason, str(exc)) from exc
    except accounts.AccountError as exc:
        raise RbacInvalid(str(exc)) from exc


def _save(row):
    row.save(force_insert=row._state.adding)


def _clear_admin(principal, row, reason):
    row.is_admin = False
    _save(row)
    events.emit(
        principal,
        "rbac.admin_revoked",
        row,
        before={"is_admin": True},
        fields=_ADMIN,
        metadata={"reason": reason},
    )


def _require_other_enabled_admin(rows, user_id):
    """BR-06b, evaluated on the locked Admin set with a fresh read of account state."""
    admin_ids = [pk for pk, row in rows.items() if row.is_admin and pk != user_id]
    if not users().filter(pk__in=admin_ids, is_active=True).exists():
        raise RbacConflict("last_admin", "At least one other enabled Admin must remain.")


@administrative
def grant_admin(principal, user_id):
    user = users().select_for_update().get(pk=_uuid(user_id))
    if not user.is_active:
        raise RbacConflict("state", "Admin grants require an enabled account.")
    rows = locked_admin_set(principal, user.pk)
    row = rows.get(user.pk) or PlatformAccess(user_id=user.pk)
    if row.is_admin:
        raise RbacConflict("unchanged", "The account is already an Admin.")
    row.is_admin = True
    _save(row)
    events.emit(principal, "rbac.admin_granted", row, before={"is_admin": False}, fields=_ADMIN)
    return user


@administrative
def revoke_admin(principal, user_id):
    user_id = _uuid(user_id)
    if _is_self(principal, user_id):
        raise RbacConflict("self_target", "You cannot revoke your own Admin grant.")
    user = users().select_for_update().get(pk=user_id)
    rows = locked_admin_set(principal, user.pk)
    row = rows.get(user.pk)
    if row is None or not row.is_admin:
        raise RbacConflict("unchanged", "The account is not an Admin.")
    _require_other_enabled_admin(rows, user.pk)
    _clear_admin(principal, row, "explicit")
    return user


@administrative
def set_position(principal, user_id, position):
    if position is not None and position not in Position.values:
        raise RbacInvalid("Choose analyst, engineer or no position.")
    user = users().select_for_update().get(pk=_uuid(user_id))
    if position is not None and not user.is_active:
        raise RbacConflict("state", "Positions require an enabled account.")
    rows = locked_admin_set(principal, user.pk)
    row = rows.get(user.pk) or PlatformAccess(user_id=user.pk)
    if row.position == position:
        raise RbacConflict("unchanged", "The position is unchanged.")
    before = {"position": row.position}
    row.position = position
    _save(row)
    events.emit(principal, "rbac.position_changed", row, before=before, fields=_POSITION)
    return user


@administrative
def create_account(principal, *, username, first_name="", last_name="", email=""):
    return _account_call(
        lambda: accounts.create_user(
            username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            actor=_account_actor(principal),
        )
    )


@administrative
def update_account(principal, user_id, *, changes):
    username = _username(_uuid(user_id))
    return _account_call(
        lambda: accounts.update_profile(username, changes=changes, actor=_account_actor(principal))
    )


@administrative
def disable_account(principal, user_id):
    user_id = _uuid(user_id)
    if _is_self(principal, user_id):
        raise RbacConflict("self_target", "You cannot disable your own account.")
    username = _username(user_id)
    user = _account_call(lambda: accounts.disable_user(username, actor=_account_actor(principal)))
    rows = locked_admin_set(principal, user.pk)
    row = rows.get(user.pk)
    if row is not None and row.is_admin:
        # BR-06b/c: the disabled target is already excluded from the enabled count.
        _require_other_enabled_admin(rows, user.pk)
        _clear_admin(principal, row, "account_disabled")
    return user


@administrative
def enable_account(principal, user_id):
    username = _username(_uuid(user_id))
    user, link = _account_call(
        lambda: accounts.enable_user(username, actor=_account_actor(principal))
    )
    rows = locked_admin_set(principal, user.pk)
    row = rows.get(user.pk)
    if row is not None and row.is_admin:
        # Only reachable after a disable outside these use cases: enabling never restores Admin.
        _clear_admin(principal, row, "account_disabled")
    return user, link


@administrative
def issue_password_link(principal, user_id):
    username = _username(_uuid(user_id))
    return _account_call(
        lambda: accounts.issue_password_link(username, actor=_account_actor(principal))
    )
