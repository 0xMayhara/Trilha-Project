"""Account lifecycle and session authentication (SPEC-0003).

Management commands and API views call only these functions. Each change records its audit event
in the same transaction (SPEC-0002). Failed attempts are recorded in their own transaction after the
failed one has rolled back (SPEC-0002 BR-04).
"""

import logging
import re
import uuid
from typing import Any

from django.conf import settings
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from apps.accounts.models import User
from apps.audit.changes import field_changes, snapshot
from apps.audit.models import Outcome
from apps.audit.services import record_event
from apps.audit.types import Actor, Resource

logger = logging.getLogger("apps.accounts")

CLI_ACTOR = Actor.system("accounts-cli")
# Lowercase ASCII only: no case or Unicode look-alikes of existing names (BR-02, SEC-17).
USERNAME_PATTERN = re.compile(r"^[a-z0-9._@+-]{1,150}\Z")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CREATED_FIELDS = ("username", "first_name", "last_name", "email", "is_active")
_ACTIVE_FIELD = ("is_active",)


class AccountError(Exception):
    """An operator request breaks a rule of SPEC-0003. The message is safe to print."""


class InvalidCredentials(Exception):
    """Login failed. Callers answer every reason the same way (SEC-05)."""


class WrongCurrentPassword(Exception):
    """A password change gave the wrong current password (SEC-11)."""


class InvalidLink(Exception):
    """A set-password link is forged, expired, used, unknown or for a disabled account (SEC-13)."""

    def __init__(self, account: User | None = None) -> None:
        super().__init__()
        self.account = account


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


def log_in(request: Any, username: str, password: str) -> User:
    """Authenticates with ModelBackend and starts a session. login() rotates the session key and the
    CSRF token (BR-04, SEC-04)."""
    username = username.lower()
    user = authenticate(request, username=username, password=password)
    if user is None:
        _record_login_failure(username)
        raise InvalidCredentials
    with transaction.atomic():
        login(request, user)
        record_event(
            actor=Actor.user(user), action="accounts.login_succeeded", resource=Resource.of(user)
        )
    return user


def _record_login_failure(username: str) -> None:
    # One lookup whatever the outcome, so the failure path does the same work for unknown accounts
    # (SEC-05). The submitted username is never stored: it may be a mistyped password (SEC-20).
    account = User.objects.filter(username=username).first()
    if account is None:
        reason = "invalid_credentials"
    elif not account.is_active:
        reason = "inactive"
    elif not account.has_usable_password():
        reason = "no_usable_password"
    else:
        reason = "invalid_credentials"
    with transaction.atomic():
        record_event(
            actor=Actor.anonymous(),
            action="accounts.login_failed",
            resource=Resource.of(account) if account else None,
            outcome=Outcome.FAILURE,
            metadata={"reason": reason},
        )
    logger.warning(
        "login_failed",
        extra={"event": "login_failed", "user_id": str(account.pk) if account else None},
    )


def log_out(request: Any) -> None:
    """Deletes the server-side session (BR-08, SEC-08)."""
    user = request.user
    with transaction.atomic():
        record_event(
            actor=Actor.user(user), action="accounts.logged_out", resource=Resource.of(user)
        )
        logout(request)


def change_password(request: Any, current_password: str, new_password: str) -> None:
    """Keeps the current session with a new key and ends every other session (BR-06, SEC-11).
    Raises WrongCurrentPassword, or ValidationError when the new password fails the validators."""
    user = request.user
    try:
        with transaction.atomic():
            # Locked so that a concurrent change or link use cannot interleave.
            locked = User.objects.select_for_update().get(pk=user.pk)
            if not locked.check_password(current_password):
                raise WrongCurrentPassword
            validate_password(new_password, locked)
            locked.set_password(new_password)
            locked.save(update_fields=["password"])
            record_event(
                actor=Actor.user(locked),
                action="accounts.password_changed",
                resource=Resource.of(locked),
                metadata={"method": "self_service"},
            )
            update_session_auth_hash(request, locked)
    except WrongCurrentPassword:
        with transaction.atomic():
            record_event(
                actor=Actor.user(user),
                action="accounts.password_change_failed",
                resource=Resource.of(user),
                outcome=Outcome.FAILURE,
                metadata={"reason": "wrong_current"},
            )
        raise


def set_password_from_link(uid: str, token: str, new_password: str) -> None:
    """Sets the password of the account a valid link was issued for (BR-07, SEC-13). Every session
    of the account ends because its password hash changes. Raises InvalidLink, or ValidationError
    when the new password fails the validators."""
    try:
        with transaction.atomic():
            # The row lock makes a concurrent second use wait, then fail the token check: the
            # first use changed the password hash the token depends on.
            user = _user_for_link(uid)
            if (
                user is None
                or not user.is_active
                or not default_token_generator.check_token(user, token)
            ):
                raise InvalidLink(user)
            # After the link check: an invalid link never learns the password rules, and a
            # rejected password leaves the link usable.
            validate_password(new_password, user)
            method = "reset" if user.has_usable_password() else "setup"
            user.set_password(new_password)
            user.save(update_fields=["password"])
            record_event(
                actor=Actor.user(user),
                action="accounts.password_set",
                resource=Resource.of(user),
                metadata={"method": method},
            )
    except InvalidLink as exc:
        account = exc.account
        reason = "disabled" if account is not None and not account.is_active else "invalid_link"
        with transaction.atomic():
            record_event(
                actor=Actor.anonymous(),
                action="accounts.password_set_failed",
                resource=Resource.of(account) if account else None,
                outcome=Outcome.FAILURE,
                metadata={"reason": reason},
            )
        logger.warning("password_link_rejected", extra={"event": "password_link_rejected"})
        raise


def _user_for_link(uid: str) -> User | None:
    try:
        pk = uuid.UUID(urlsafe_base64_decode(uid).decode())
    except (ValueError, UnicodeDecodeError):
        return None
    return User.objects.select_for_update().filter(pk=pk).first()
