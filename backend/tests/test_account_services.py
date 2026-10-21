"""Account lifecycle services (SPEC-0003 BR-01..BR-05, BR-07, SEC-14, SEC-17..SEC-19)."""

from unittest import mock
from urllib.parse import parse_qs, urlsplit

import pytest
from django.contrib.auth.tokens import default_token_generator
from django.test import override_settings
from django.utils.http import urlsafe_base64_decode

from apps.accounts import services
from apps.accounts.models import User
from apps.accounts.services import AccountError
from apps.audit.context import audit_source
from apps.audit.exceptions import AuditValidationError
from apps.audit.models import AuditEvent

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def command_context():
    with audit_source("command"):
        yield


def link_parts(link: str) -> tuple[User, str]:
    fragment = parse_qs(urlsplit(link).fragment)
    user = User.objects.get(pk=urlsafe_base64_decode(fragment["uid"][0]).decode())
    return user, fragment["token"][0]


def actions() -> list[str]:
    return list(AuditEvent.objects.order_by("id").values_list("action", flat=True))


def test_create_user_records_events_and_returns_a_setup_link():
    user, link = services.create_user(
        "alice", first_name="Alice", last_name="Lima", email="alice@example.com"
    )

    assert user.is_active and not user.has_usable_password()
    assert not user.is_staff and not user.is_superuser
    assert actions() == ["accounts.user_created", "accounts.password_link_issued"]
    created, issued = AuditEvent.objects.order_by("id")
    assert created.actor_type == "system" and created.actor_label == "accounts-cli"
    assert created.source == "command"
    assert created.resource_type == "accounts.user" and created.resource_id == str(user.pk)
    assert created.changes == {
        "username": {"before": None, "after": "alice"},
        "first_name": {"before": None, "after": "Alice"},
        "last_name": {"before": None, "after": "Lima"},
        "email": {"before": None, "after": "alice@example.com"},
        "is_active": {"before": None, "after": True},
    }
    assert issued.metadata == {"purpose": "setup"}
    linked_user, token = link_parts(link)
    assert linked_user == user
    assert default_token_generator.check_token(user, token)


def test_created_users_have_no_staff_or_superuser_flag_cwe_269():
    user, _ = services.create_user("bob")

    assert (user.is_staff, user.is_superuser) == (False, False)


@pytest.mark.parametrize(
    "username",
    ["Alice", "álice", "al ice", "", "a" * 151, "alice\n", "alice/x"],
)
def test_create_user_rejects_non_ascii_or_uppercase_username_cwe_1007(username):
    with pytest.raises(AccountError):
        services.create_user(username)

    assert not User.objects.exists()
    assert not AuditEvent.objects.exists()


def test_create_user_rejects_case_insensitive_duplicate_cwe_178():
    User.objects.create_user(username="Alice", password=None)

    with pytest.raises(AccountError):
        services.create_user("alice")

    assert User.objects.count() == 1
    assert not AuditEvent.objects.exists()


@pytest.mark.parametrize(
    "fields",
    [{"first_name": "Al\x00ice"}, {"last_name": "Lima\r\nX"}, {"email": "not-an-email"}],
)
def test_create_user_rejects_invalid_names_and_email(fields):
    with pytest.raises(AccountError):
        services.create_user("alice", **fields)

    assert not User.objects.exists()


@override_settings(TRILHA_BASE_URL="https://trilha.corp.example")
def test_password_link_uses_configured_base_url_cwe_644():
    _, link = services.create_user("alice")

    assert link.startswith("https://trilha.corp.example/set-password#")


def test_password_link_carries_token_only_in_fragment_cwe_598():
    _, link = services.create_user("alice")

    parts = urlsplit(link)
    assert parts.path == "/set-password"
    assert parts.query == ""
    assert set(parse_qs(parts.fragment)) == {"uid", "token"}


def test_issue_password_link_is_a_reset_for_an_account_with_a_password():
    user, _ = services.create_user("alice")
    user.set_password("correct-horse-battery-staple")
    user.save()

    link = services.issue_password_link("alice")

    assert AuditEvent.objects.latest("id").metadata == {"purpose": "reset"}
    assert default_token_generator.check_token(*link_parts(link))


def test_disable_user_removes_the_password_atomically_and_records_the_change():
    user, _ = services.create_user("alice")
    user.set_password("correct-horse-battery-staple")
    user.save()

    services.disable_user("alice")

    user.refresh_from_db()
    assert not user.is_active
    assert not user.has_usable_password()
    event = AuditEvent.objects.latest("id")
    assert event.action == "accounts.user_disabled"
    assert event.changes == {"is_active": {"before": True, "after": False}}
    assert event.metadata == {}


def test_failed_audit_rolls_back_the_disable_cwe_778():
    user, _ = services.create_user("alice")
    user.set_password("correct-horse-battery-staple")
    user.save()

    with (
        mock.patch.object(services, "record_event", side_effect=AuditValidationError("boom")),
        pytest.raises(AuditValidationError),
    ):
        services.disable_user("alice")

    user.refresh_from_db()
    assert user.is_active
    assert user.check_password("correct-horse-battery-staple")


def test_enable_user_keeps_the_password_unusable_and_issues_a_setup_link():
    user, _ = services.create_user("alice")
    user.set_password("correct-horse-battery-staple")
    user.save()
    services.disable_user("alice")

    _, link = services.enable_user("alice")

    user.refresh_from_db()
    assert user.is_active
    assert not user.has_usable_password()
    assert actions()[-2:] == ["accounts.user_enabled", "accounts.password_link_issued"]
    assert AuditEvent.objects.latest("id").metadata == {"purpose": "setup"}
    assert default_token_generator.check_token(*link_parts(link))


def test_enable_user_never_restores_a_password_set_outside_the_services():
    user, _ = services.create_user("alice")
    User.objects.filter(pk=user.pk).update(is_active=False)
    user.refresh_from_db()
    user.set_password("old-password-kept-in-db")
    user.save()

    services.enable_user("alice")

    user.refresh_from_db()
    assert not user.has_usable_password()


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        (lambda: services.disable_user("alice"), "already disabled"),
        (lambda: services.issue_password_link("alice"), "disabled"),
    ],
)
def test_operations_refused_on_a_disabled_account_record_nothing(operation, message):
    services.create_user("alice")
    services.disable_user("alice")
    recorded = AuditEvent.objects.count()

    with pytest.raises(AccountError, match=message):
        operation()

    assert AuditEvent.objects.count() == recorded


def test_enable_refuses_an_active_account():
    services.create_user("alice")
    recorded = AuditEvent.objects.count()

    with pytest.raises(AccountError, match="already enabled"):
        services.enable_user("alice")

    assert AuditEvent.objects.count() == recorded


@pytest.mark.parametrize(
    "operation",
    [services.disable_user, services.enable_user, services.issue_password_link],
)
def test_unknown_username_is_refused(operation):
    with pytest.raises(AccountError, match="No account"):
        operation("nobody")
