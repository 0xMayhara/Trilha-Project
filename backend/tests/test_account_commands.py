"""Account management commands (SPEC-0003 BR-01, BR-10, BR-13, SEC-14, SEC-18)."""

import logging
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest
from django.conf import settings
from django.core.management import CommandError, call_command, get_commands, load_command_class

from apps.accounts.models import User
from apps.audit.models import AuditEvent

BACKEND_DIR = Path(settings.BASE_DIR)
ACCOUNT_COMMANDS = (
    "accounts_create_user",
    "accounts_password_link",
    "accounts_disable_user",
    "accounts_enable_user",
)


def run(name: str, *args: str) -> str:
    stdout = StringIO()
    call_command(name, *args, stdout=stdout)
    return stdout.getvalue()


@pytest.mark.django_db
def test_create_user_command_prints_link_and_delivery_notice(caplog):
    with caplog.at_level(logging.INFO, logger="apps.accounts"):
        output = run("accounts_create_user", "alice", "--first-name", "Alice", "--email", "a@x.io")

    user = User.objects.get(username="alice")
    link, notice = output.strip().splitlines()
    assert link.startswith(f"{settings.TRILHA_BASE_URL}/set-password#uid=")
    assert "authorized internal channel" in notice and "60 minutes" in notice
    assert set(AuditEvent.objects.values_list("source", flat=True)) == {"command"}
    # The log names the command and account, never the link (SEC-14).
    (record,) = [r for r in caplog.records if getattr(r, "event", None) == "account_command"]
    assert (record.command, record.user_id) == ("accounts_create_user", str(user.pk))
    token = link.rsplit("token=", 1)[1]
    assert all(token not in str(vars(r)) for r in caplog.records)


@pytest.mark.django_db
def test_disable_enable_and_link_commands():
    run("accounts_create_user", "alice")

    assert "all of its sessions have ended" in run("accounts_disable_user", "alice")
    assert "/set-password#uid=" in run("accounts_enable_user", "alice")
    assert "/set-password#uid=" in run("accounts_password_link", "alice")
    assert list(AuditEvent.objects.order_by("id").values_list("action", flat=True)) == [
        "accounts.user_created",
        "accounts.password_link_issued",
        "accounts.user_disabled",
        "accounts.user_enabled",
        "accounts.password_link_issued",
        "accounts.password_link_issued",
    ]


@pytest.mark.django_db
@pytest.mark.parametrize(
    "args",
    [
        ("accounts_create_user", "Alice"),
        ("accounts_disable_user", "nobody"),
        ("accounts_enable_user", "nobody"),
        ("accounts_password_link", "nobody"),
    ],
)
def test_refused_commands_fail_without_changes(args):
    with pytest.raises(CommandError):
        run(*args)

    assert not User.objects.exists()
    assert not AuditEvent.objects.exists()


def test_account_commands_accept_no_password_argument_cwe_214():
    for name in ACCOUNT_COMMANDS:
        parser = load_command_class("apps.accounts", name).create_parser("manage.py", name)
        options = [opt for action in parser._actions for opt in action.option_strings]
        assert not [opt for opt in options if "pass" in opt.lower()], name


@pytest.mark.parametrize("builtin", ["createsuperuser", "changepassword"])
def test_builtin_account_commands_are_disabled_cwe_778(builtin):
    assert get_commands()[builtin] == "apps.accounts"
    with pytest.raises(CommandError, match="disabled"):
        call_command(builtin)

    # From the shell, with any options, the command refuses before touching the database.
    result = subprocess.run(
        [sys.executable, "manage.py", builtin, "--username", "root", "--noinput"],
        cwd=BACKEND_DIR,
        env={**os.environ, "DJANGO_SETTINGS_MODULE": "config.settings.test"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "disabled in Trilha" in result.stderr
