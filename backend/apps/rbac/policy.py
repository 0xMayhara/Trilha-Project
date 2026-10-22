"""Administrative authority (SPEC-0004 SEC-08 as amended by SPEC-0010; ADR-0007).

`require_administration` is the single choke point. The infrastructure operator (CLI) passes. A user
principal passes only as a current enabled platform Admin, read with fresh SQL, and for every
mutation only with a step-up proof younger than the window. `administrative` runs each use case in
one transaction with bounded lock waits and, as the last lock acquisition, locks the Admin set and
re-checks the actor, so a revocation that commits first rolls the mutation back (SEC-04, SEC-28)."""

import logging
import time
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import IntegrityError, OperationalError, transaction
from django.db.models import Q

from apps.accounts.selectors import users
from apps.audit.models import Outcome
from apps.audit.services import record_event
from apps.audit.types import Actor
from apps.rbac.exceptions import (
    AdministrationDenied,
    RbacConflict,
    RbacInvalid,
    RbacNotFound,
    ReauthenticationRequired,
)
from apps.rbac.locking import bound_lock_waits, lock_failure
from apps.rbac.models import PlatformAccess
from apps.rbac.principals import UserPrincipal, is_infrastructure_operator
from apps.rbac.selectors import is_platform_admin

logger = logging.getLogger("apps.rbac")

STEP_UP_WINDOW_SECONDS = 600
ADMIN_LOCK_TIMEOUT = "5s"
# Code-defined Admin capabilities (BR-02). Later SPECs extend these lists explicitly.
READ_OPERATIONS = frozenset({"preview_team_activation", "inspect_configuration"})
ADMIN_OPERATIONS = READ_OPERATIONS | frozenset(
    {
        "create_team",
        "update_team",
        "deactivate_team",
        "activate_team",
        "add_member",
        "remove_member",
        "create_role",
        "update_role",
        "grant_permission",
        "revoke_permission",
        "assign_role",
        "revoke_role",
        "grant_admin",
        "revoke_admin",
        "set_position",
        "create_account",
        "update_account",
        "disable_account",
        "enable_account",
        "issue_password_link",
    }
)
# Reads that are logged, never audited (BR-16): directory, rosters, catalog, audit search.
ADMIN_READS = frozenset({"read_directory", "search_audit"})


def audit_actor(principal):
    if is_infrastructure_operator(principal):
        return Actor.system("trilha-operator")
    if isinstance(principal, UserPrincipal):
        return Actor.user(users().get(pk=principal.user_id))
    raise AdministrationDenied


def step_up_is_fresh(principal):
    """Compared with the server clock only; a future proof is refused, never trusted (SEC-10)."""
    verified_at = getattr(principal, "reauthenticated_at", None)
    if isinstance(verified_at, bool) or not isinstance(verified_at, int | float):
        return False
    return 0 <= time.time() - verified_at <= STEP_UP_WINDOW_SECONDS


def _actor_id(principal):
    return str(principal.user_id) if isinstance(principal, UserPrincipal) else None


def _record_denial(principal, operation):
    # Runs outside the rejected operation's transaction, so the record survives its rollback.
    if isinstance(principal, UserPrincipal) and users().filter(pk=principal.user_id).exists():
        with transaction.atomic():
            record_event(
                actor=audit_actor(principal),
                action="rbac.administration_denied",
                outcome=Outcome.DENIED,
                metadata={
                    "operation": operation
                    if operation in ADMIN_OPERATIONS
                    else "inspect_configuration",
                    "reason": "not_allowed",
                },
            )
    logger.warning(
        "authorization_denied",
        extra={"operation": operation, "actor_id": _actor_id(principal), "outcome": "denied"},
    )


def _refused(operation, principal, reason):
    logger.warning(
        "administration_refused",
        extra={"operation": operation, "actor_id": _actor_id(principal), "reason": reason},
    )


def _require_step_up(principal, operation):
    if is_infrastructure_operator(principal) or step_up_is_fresh(principal):
        return
    logger.warning(
        "reauthentication_required",
        extra={"operation": operation, "actor_id": _actor_id(principal)},
    )
    raise ReauthenticationRequired


def require_administration(principal, operation):
    if operation in ADMIN_OPERATIONS and (
        is_infrastructure_operator(principal) or is_platform_admin(principal)
    ):
        if operation not in READ_OPERATIONS:
            _require_step_up(principal, operation)
        return
    _record_denial(principal, operation)
    raise AdministrationDenied


def require_admin_read(principal, operation):
    """Admin-only reads: no audit row and no step-up (BR-07, BR-16)."""
    if operation in ADMIN_READS and is_platform_admin(principal):
        return
    raise AdministrationDenied


@dataclass(slots=True)
class _Boundary:
    principal: object
    operation: str
    admin_set_locked: bool = False


_boundary: ContextVar[_Boundary | None] = ContextVar("rbac_administrative_boundary", default=None)


def locked_admin_set(principal, target_id=None):
    """Commit-time authority step (SPEC-0010 Concurrency, step 3). Always the last lock class:
    every Admin row plus the target's row, in user-ID order, then the actor is re-verified. Returns
    the locked rows by user ID; callers evaluate the Admin guards against them."""
    condition = Q(is_admin=True) if target_id is None else Q(is_admin=True) | Q(pk=target_id)
    rows = {
        row.pk: row
        for row in PlatformAccess.objects.select_for_update().filter(condition).order_by("pk")
    }
    state = _boundary.get()
    if not is_infrastructure_operator(principal):
        if not is_platform_admin(principal):
            raise AdministrationDenied
        _require_step_up(principal, state.operation if state else "commit")
    if state is not None:
        state.admin_set_locked = True
    return rows


def administrative(function):
    operation = function.__name__

    @wraps(function)
    def invoke(principal, *args, **kwargs):
        outer = _boundary.get()
        if outer is not None and outer.principal is principal:
            # Nested call (e.g. remove_member -> revoke_role): authorized and locked once, at the
            # outermost boundary, so the Admin set is never locked before a later lock class (F-02).
            return function(principal, *args, **kwargs)
        require_administration(principal, operation)
        state = _Boundary(principal, operation)
        token = _boundary.set(state)
        try:
            with transaction.atomic():
                bound_lock_waits(ADMIN_LOCK_TIMEOUT)
                result = function(principal, *args, **kwargs)
                if operation not in READ_OPERATIONS and not state.admin_set_locked:
                    locked_admin_set(principal)
            return result
        except AdministrationDenied:
            _record_denial(principal, operation)  # the mutation has rolled back (SEC-04, SEC-24)
            raise
        except RbacConflict as exc:
            _refused(operation, principal, exc.reason)
            raise
        except ObjectDoesNotExist as exc:
            raise RbacNotFound from exc
        except IntegrityError as exc:
            cause = exc.__cause__
            # Unique violations are ordinary conflicts (a concurrent duplicate); others are errors.
            if getattr(cause, "sqlstate", None) != "23505":
                constraint = getattr(getattr(cause, "diag", None), "constraint_name", None)
                logger.error(
                    "admin_integrity_error",
                    extra={"operation": operation, "constraint": constraint},
                )
            _refused(operation, principal, "state")
            raise RbacConflict("state", "The request conflicts with the current state.") from exc
        except ValidationError as exc:
            raise RbacInvalid(" ".join(exc.messages)) from exc
        except OperationalError as exc:
            reason = lock_failure(exc)
            if reason is None:
                raise
            logger.warning(
                "admin_lock_unavailable",
                extra={"operation": operation, "actor_id": _actor_id(principal), "reason": reason},
            )
            # A fresh error without the database cause: the 503 handler logs no SQL or row data.
            raise OperationalError("Administrative lock unavailable.") from None
        finally:
            _boundary.reset(token)

    return invoke


def active_user(principal):
    return (
        isinstance(principal, UserPrincipal)
        and users().filter(pk=principal.user_id, is_active=True).exists()
    )
