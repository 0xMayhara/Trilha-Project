"""Account lifecycle and session authentication (SPEC-0003).

Management commands and API views call only these functions. Each change records its audit event
in the same transaction (SPEC-0002). Failed attempts are recorded in their own transaction after the
failed one has rolled back (SPEC-0002 BR-04).
"""

import re

from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from apps.accounts.models import User
from apps.audit.changes import field_changes, snapshot
from apps.audit.services import record_event
from apps.audit.types import Actor, Resource

CLI_ACTOR = Actor.system("accounts-cli")
# Lowercase ASCII only: no case or Unicode look-alikes of existing names (BR-02, SEC-17).
USERNAME_PATTERN = re.compile(r"^[a-z0-9._@+-]{1,150}\Z")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CREATED_FIELDS = ("username", "first_name", "last_name", "email", "is_active")
_ACTIVE_FIELD = ("is_active",)


class AccountError(Exception):
    """An operator request breaks a rule of SPEC-0003. The message is safe to print."""


def create_user(
    username: str, *, first_name: str = "", last_name: str = "", email: str = ""
) -> tuple[User, str]:
    """Creates an account without a usable password and returns it with a setup link."""
    if not USERNAME_PATTERN.match(username):
        raise AccountError("Usernames are 1-150 lowercase ASCII characters: a-z, 0-9 and . _ @ + -")
    if any(_CONTROL_CHARACTERS.search(value) for value in (first_name, last_name, email)):
        raise AccountError("Names and email must not contain control characters.")
    with transaction.atomic():
        if User.objects.filter(username__iexact=username).exists():
            raise AccountError("A user with that username already exists.")
        user = User(username=username, first_name=first_name, last_name=last_name, email=email)
        user.set_unusable_password()
        try:
            user.full_clean()
        except ValidationError as exc:
            raise AccountError(" ".join(exc.messages)) from None
        user.save()
        record_event(
            actor=CLI_ACTOR,
            action="accounts.user_created",
            resource=Resource.of(user),
            changes=field_changes({}, snapshot(user, _CREATED_FIELDS), _CREATED_FIELDS),
        )
        link = _issue_link(user)
    return user, link


def issue_password_link(username: str) -> str:
    """A setup link for an account without a password, or a reset link for an active one."""
    with transaction.atomic():
        user = _get_for_update(username)
        if not user.is_active:
            raise AccountError("The account is disabled; enable it to issue a new link.")
        return _issue_link(user)


def disable_user(username: str) -> User:
    """Disables the account and removes its password, which ends every session for good (BR-05)."""
    with transaction.atomic():
        user = _get_for_update(username)
        if not user.is_active:
            raise AccountError("The account is already disabled.")
        before = snapshot(user, _ACTIVE_FIELD)
        user.is_active = False
        # A new password hash invalidates every session hash, even after re-enabling.
        user.set_unusable_password()
        user.save(update_fields=["is_active", "password"])
        record_event(
            actor=CLI_ACTOR,
            action="accounts.user_disabled",
            resource=Resource.of(user),
            changes=field_changes(before, snapshot(user, _ACTIVE_FIELD), _ACTIVE_FIELD),
        )
    return user


def enable_user(username: str) -> tuple[User, str]:
    """Re-enables the account without any password; its owner sets one through the link."""
    with transaction.atomic():
        user = _get_for_update(username)
        if user.is_active:
            raise AccountError("The account is already enabled.")
        before = snapshot(user, _ACTIVE_FIELD)
        user.is_active = True
        # Never restore a previous password, even for an account disabled outside these services.
        user.set_unusable_password()
        user.save(update_fields=["is_active", "password"])
        record_event(
            actor=CLI_ACTOR,
            action="accounts.user_enabled",
            resource=Resource.of(user),
            changes=field_changes(before, snapshot(user, _ACTIVE_FIELD), _ACTIVE_FIELD),
        )
        link = _issue_link(user)
    return user, link


def _get_for_update(username: str) -> User:
    try:
        return User.objects.select_for_update().get(username=username)
    except User.DoesNotExist:
        raise AccountError("No account has that username.") from None


def _issue_link(user: User) -> str:
    purpose = "reset" if user.has_usable_password() else "setup"
    record_event(
        actor=CLI_ACTOR,
        action="accounts.password_link_issued",
        resource=Resource.of(user),
        metadata={"purpose": purpose},
    )
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    # uid and token only in the fragment, which browsers never send to a server (SEC-14).
    return f"{settings.TRILHA_BASE_URL}/set-password#uid={uid}&token={token}"
