from functools import wraps

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import IntegrityError, transaction

from apps.accounts.selectors import users
from apps.audit.models import Outcome
from apps.audit.services import record_event
from apps.audit.types import Actor
from apps.rbac.exceptions import AdministrationDenied, RbacError
from apps.rbac.principals import UserPrincipal, is_infrastructure_operator

ADMIN_OPERATIONS = frozenset(
    {
        "create_team",
        "update_team",
        "deactivate_team",
        "preview_team_activation",
        "activate_team",
        "add_member",
        "remove_member",
        "create_role",
        "update_role",
        "grant_permission",
        "revoke_permission",
        "assign_role",
        "revoke_role",
        "inspect_configuration",
    }
)


def audit_actor(principal):
    if is_infrastructure_operator(principal):
        return Actor.system("trilha-operator")
    if isinstance(principal, UserPrincipal):
        return Actor.user(users().get(pk=principal.user_id))
    raise AdministrationDenied


def require_administration(principal, operation):
    if operation in ADMIN_OPERATIONS and is_infrastructure_operator(principal):
        return
    # No mutation has begun. The denial commits independently of the rejected operation.
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
    raise AdministrationDenied


def administrative(function):
    @wraps(function)
    def invoke(principal, *args, **kwargs):
        require_administration(principal, function.__name__)
        try:
            with transaction.atomic():
                return function(principal, *args, **kwargs)
        except (IntegrityError, ObjectDoesNotExist) as exc:
            raise RbacError("The requested relationship is missing or already exists.") from exc
        except ValidationError as exc:
            raise RbacError("Invalid domain value.") from exc

    return invoke


def active_user(principal):
    return (
        isinstance(principal, UserPrincipal)
        and users().filter(pk=principal.user_id, is_active=True).exists()
    )
