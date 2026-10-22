"""Shared CLI plumbing only. Authority and business rules remain in domain services."""

from functools import wraps

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.management.base import CommandError
from django.db import DatabaseError

from apps.accounts.selectors import users
from apps.audit.context import audit_source
from apps.audit.exceptions import AuditError
from apps.rbac.exceptions import RbacError
from apps.rbac.principals import infrastructure_operator
from apps.rbac.selectors import roles
from apps.teams.selectors import memberships, teams


def operator_command(function):
    @wraps(function)
    def invoke(command, *args, **options):
        try:
            with audit_source("command"):
                function(command, infrastructure_operator(), options)
        except (RbacError, ObjectDoesNotExist, ValidationError, DatabaseError, AuditError) as exc:
            raise CommandError(
                "Operation refused or unavailable; no partial change committed."
            ) from exc

    return invoke


def account_command(function):
    """Account and Admin commands print the domain's fixed refusal message, as the SPEC-0003
    commands always did; other failures propagate unchanged."""

    @wraps(function)
    def invoke(command, *args, **options):
        try:
            with audit_source("command"):
                function(command, infrastructure_operator(), options)
        except RbacError as exc:
            raise CommandError(str(exc)) from None

    return invoke


def account_id(username):
    try:
        return user_id(username)
    except ObjectDoesNotExist:
        raise CommandError("No account has that username.") from None


def team_id(code):
    return teams().values_list("pk", flat=True).get(code=code)


def role_id(code):
    return roles().values_list("pk", flat=True).get(code=code)


def user_id(username):
    return users().values_list("pk", flat=True).get(username=username)


def membership_id(team_code, username):
    return (
        memberships()
        .values_list("pk", flat=True)
        .get(team_id=team_id(team_code), user_id=user_id(username))
    )
