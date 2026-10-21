"""Shared output of the account commands (SPEC-0003 BR-13, SEC-14)."""

import logging

from django.conf import settings
from django.core.management.base import OutputWrapper

from apps.accounts.models import User

logger = logging.getLogger("apps.accounts")


def report(command: str, user: User, stdout: OutputWrapper, link: str | None = None) -> None:
    # The log line names the command and account only: the link is a one-time credential.
    logger.info(
        "account_command",
        extra={"event": "account_command", "command": command, "user_id": str(user.pk)},
    )
    if link is None:
        return
    minutes = settings.PASSWORD_RESET_TIMEOUT // 60
    stdout.write(link)
    stdout.write(
        f"Deliver this link only through an authorized internal channel. It works once and "
        f"expires in {minutes} minutes."
    )
