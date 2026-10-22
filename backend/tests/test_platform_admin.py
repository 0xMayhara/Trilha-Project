"""SPEC-0010 domain and CLI contracts: platform Admin authority, guards, positions, step-up at the
service boundary, bootstrap and recovery (TM-0010). HTTP contracts: test_platform_admin_api.py."""

import ast
import logging
import threading
import time
from datetime import timedelta
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import psycopg.errors
import pytest
from django.contrib.auth.models import Group, Permission
from django.core.management import call_command, get_commands
from django.core.management.base import CommandError
from django.db import IntegrityError, OperationalError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.accounts import services as accounts
from apps.accounts.models import User
from apps.assets.selectors import visible_assets
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from apps.rbac import administration, directory, events, policy
from apps.rbac import services as rbac
from apps.rbac.exceptions import (
    AdministrationDenied,
    RbacConflict,
    RbacError,
    ReauthenticationRequired,
)
from apps.rbac.models import PlatformAccess, Role, RoleAssignment
from apps.rbac.principals import UserPrincipal, infrastructure_operator
from apps.rbac.selectors import authorized_teams, can_access, is_platform_admin
from apps.teams import services as teams
from apps.teams.models import Membership, Team

pytestmark = pytest.mark.django_db(transaction=True)
OPERATOR = infrastructure_operator()
PASSWORD = "correct-horse-battery-staple"
VIEW = "teams.view_team"


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


def make_user(username):
    return User.objects.create_user(username=username, password=PASSWORD)


def make_admin(username):
    user = make_user(username)
    administration.grant_admin(OPERATOR, user.pk)
    return user


def fresh(user):
    """A principal whose session re-authenticated just now."""
    return UserPrincipal(user.pk, reauthenticated_at=time.time())


def is_admin(user):
    return is_platform_admin(UserPrincipal(user.pk))


def admin_ids():
    return set(
        PlatformAccess.objects.filter(is_admin=True, user__is_active=True).values_list(
            "pk", flat=True
        )
    )


def configuration():
    models = (Team, Membership, Role, RoleAssignment, Role.permissions.through, PlatformAccess)
    rows = [list(model.objects.order_by("pk").values()) for model in models]
    rows.append(list(User.objects.order_by("pk").values("pk", "is_active", "password")))
    return rows


def events_of(action):
    return AuditEvent.objects.filter(action=action)


def in_thread(name, function):
    """Runs `function` on its own thread and database connection; captures result or error."""
    result = {}

    def target():
        try:
            with audit_source("command"):
                result["value"] = function()
        except Exception as exc:  # surfaced through `result` to the caller's assertion
            result["error"] = exc
        finally:
            connection.close()

    thread = threading.Thread(target=target, name=name)
    thread.start()
    return thread, result


class PauseWriter:
    """Pauses the first audited write of a named thread while its transaction holds its locks."""

    def __init__(self, thread_name):
        self.thread_name = thread_name
        self.paused, self.release = threading.Event(), threading.Event()
        self.original = events.record_event

    def __call__(self, **kwargs):
        event = self.original(**kwargs)
        if threading.current_thread().name == self.thread_name and not self.paused.is_set():
            self.paused.set()
            assert self.release.wait(10)
        return event

    def __enter__(self):
        self.patches = [
            mock.patch.object(events, "record_event", self),
            mock.patch.object(accounts, "record_event", self),
        ]
        for patch in self.patches:
            patch.start()
        return self

    def __exit__(self, *exc):
        self.release.set()
        for patch in self.patches:
            patch.stop()


def race(first, second):
    """Runs `first` until its first audit write (locks held), then `second` against it."""
    with PauseWriter("first") as pause:
        first_thread, first_result = in_thread("first", first)
        assert pause.paused.wait(10)
        second_thread, second_result = in_thread("second", second)
        time.sleep(0.5)
        blocked = second_thread.is_alive()
        pause.release.set()
        first_thread.join(10)
        second_thread.join(10)
    return blocked, first_result, second_result


def run(name, *args):
    stdout = StringIO()
    call_command(name, *args, stdout=stdout)
    return stdout.getvalue()


# SEC-03 — Admin authority only from the platform grant (T-03, CWE-269)


def test_admin_authority_only_from_platform_grant_cwe_269():
    root = make_user("admin")  # a privileged-sounding username grants nothing
    root.is_staff = root.is_superuser = True
    root.save()
    native = Permission.objects.all()
    root.user_permissions.add(*native)
    group = Group.objects.create(name="admins")
    group.permissions.add(*native)
    root.groups.add(group)
    PlatformAccess.objects.create(user=root, position="engineer")  # a position is not authority
    before = configuration()
    for source in ("http", "command", "task"):
        with audit_source(source):
            assert not is_admin(root)
            with pytest.raises(AdministrationDenied):
                teams.create_team(fresh(root), code="forged", name="Forged")
            with pytest.raises(AdministrationDenied):
                administration.grant_admin(fresh(root), root.pk)
    assert configuration() == before

    administration.grant_admin(OPERATOR, root.pk)
    assert is_admin(root)
    team = teams.create_team(fresh(root), code="granted", name="Granted")
    assert events_of("teams.team_created").get(resource_id=str(team.pk)).actor_id == root.pk

    User.objects.filter(pk=root.pk).update(is_active=False)  # bypassing the services on purpose
    assert not is_admin(root)
    with pytest.raises(AdministrationDenied):
        teams.update_team(fresh(root), team.pk, name="Disabled")


# SEC-04 — revocation applies to the next decision and rolls back an in-flight mutation (CWE-863)


def test_revoked_admin_loses_authority_on_next_check_cwe_863():
    alice, _bob = make_admin("alice"), make_admin("bob")
    blocked, first, second = race(
        lambda: teams.create_team(fresh(alice), code="inflight", name="In flight"),
        lambda: administration.revoke_admin(OPERATOR, alice.pk),
    )
    assert not blocked  # the revocation did not wait: the mutation had not reached the Admin set
    assert "error" not in second, second
    assert isinstance(first.get("error"), AdministrationDenied), first
    assert not Team.objects.filter(code="inflight").exists()
    assert not events_of("teams.team_created").exists()
    denial = events_of("rbac.administration_denied").get()
    assert denial.actor_id == alice.pk and denial.metadata["operation"] == "create_team"
    with pytest.raises(AdministrationDenied):
        teams.create_team(fresh(alice), code="next", name="Next")
    assert events_of("rbac.administration_denied").count() == 2


def test_admitted_admin_mutation_completes_before_a_revocation():
    alice, _bob = make_admin("alice"), make_admin("bob")
    team = teams.create_team(OPERATOR, code="alpha", name="Alpha")

    blocked, first, second = race(
        # set_position locks the Admin set before its audited write, where the race pauses it.
        lambda: administration.set_position(fresh(alice), alice.pk, "engineer"),
        lambda: administration.revoke_admin(OPERATOR, alice.pk),
    )
    assert blocked  # the revocation waited for the admitted mutation's Admin-set lock
    assert "error" not in first and "error" not in second, (first, second)
    assert PlatformAccess.objects.get(pk=alice.pk).position == "engineer"
    assert not is_admin(alice)
    with pytest.raises(AdministrationDenied):
        teams.update_team(fresh(alice), team.pk, name="Late")


# SEC-06 — no self-revocation and no self-disable (T-06, CWE-269)


def test_admin_cannot_revoke_or_disable_self_cwe_269(caplog):
    alice, _bob = make_admin("alice"), make_admin("bob")
    before = configuration()
    with caplog.at_level(logging.WARNING, logger="apps.rbac"):
        for call in (
            lambda: administration.revoke_admin(fresh(alice), alice.pk),
            lambda: administration.disable_account(fresh(alice), alice.pk),
            lambda: administration.disable_account(fresh(alice), str(alice.pk)),
        ):
            with pytest.raises(RbacConflict) as refused:
                call()
            assert refused.value.reason == "self_target"
    assert configuration() == before
    assert (
        not AuditEvent.objects.filter(outcome__in=["success", "denied"])
        .exclude(action="rbac.admin_granted")
        .exists()
    )
    reasons = [r.reason for r in caplog.records if r.getMessage() == "administration_refused"]
    assert reasons == ["self_target"] * 3


# SEC-07 — at least one enabled Admin under concurrency (T-07, CWE-362)


def test_concurrent_admin_revocations_keep_one_enabled_admin_cwe_362():
    alice, bob = make_admin("alice"), make_admin("bob")
    blocked, first, second = race(
        lambda: administration.revoke_admin(fresh(alice), bob.pk),
        lambda: administration.revoke_admin(fresh(bob), alice.pk),
    )
    assert blocked and "error" not in first, first
    # The loser's own grant was revoked first: it is denied, and its denial is audited.
    assert isinstance(second.get("error"), AdministrationDenied), second
    assert admin_ids() == {alice.pk}
    assert events_of("rbac.admin_revoked").count() == 1

    carol = make_admin("carol")
    blocked, first, second = race(
        lambda: administration.revoke_admin(OPERATOR, alice.pk),
        lambda: administration.disable_account(OPERATOR, carol.pk),
    )
    assert blocked and "error" not in first, first
    assert isinstance(second.get("error"), RbacConflict) and second["error"].reason == "last_admin"
    assert admin_ids() == {carol.pk}
    carol.refresh_from_db()
    assert carol.is_active

    with pytest.raises(RbacConflict) as refused:
        administration.revoke_admin(OPERATOR, carol.pk)  # the operator is bound too
    assert refused.value.reason == "last_admin"
    assert admin_ids() == {carol.pk}


def test_last_admin_count_ignores_disabled_admin_rows():
    alice, bob = make_admin("alice"), make_admin("bob")
    PlatformAccess.objects.filter(pk=bob.pk).update(is_admin=True)
    User.objects.filter(pk=bob.pk).update(is_active=False)  # a dormant row outside the services
    with pytest.raises(RbacConflict) as refused:
        administration.revoke_admin(OPERATOR, alice.pk)
    assert refused.value.reason == "last_admin"


# SEC-08 — disabling clears Admin; enabling never restores it (T-08, CWE-269)


def test_reenabled_account_does_not_regain_admin_cwe_269():
    alice, bob = make_admin("alice"), make_admin("bob")
    administration.disable_account(fresh(alice), bob.pk)
    access = PlatformAccess.objects.get(pk=bob.pk)
    assert not access.is_admin
    revoked = events_of("rbac.admin_revoked").get()
    disabled = events_of("accounts.user_disabled").get()
    assert revoked.metadata == {"reason": "account_disabled"}
    assert revoked.request_id == disabled.request_id and revoked.actor_id == alice.pk
    administration.enable_account(fresh(alice), bob.pk)
    assert not is_admin(bob) and not PlatformAccess.objects.get(pk=bob.pk).is_admin
    administration.grant_admin(fresh(alice), bob.pk)  # only an explicit, audited grant restores it
    assert is_admin(bob)

    # A grant left dormant by the bare SPEC-0003 primitive is still never revived on enable.
    carol = make_admin("carol")
    accounts.disable_user("carol")
    assert PlatformAccess.objects.get(pk=carol.pk).is_admin and not is_admin(carol)
    administration.enable_account(OPERATOR, carol.pk)
    assert not PlatformAccess.objects.get(pk=carol.pk).is_admin and not is_admin(carol)
    assert events_of("rbac.admin_revoked").filter(resource_id=str(carol.pk)).count() == 1


def test_admin_grants_require_an_enabled_account_and_are_not_repeated():
    alice = make_admin("alice")
    pending, _link = administration.create_account(fresh(alice), username="pending")
    administration.grant_admin(fresh(alice), pending.pk)  # a pending password is allowed
    for call, reason in (
        (lambda: administration.grant_admin(fresh(alice), pending.pk), "unchanged"),
        (lambda: administration.revoke_admin(fresh(alice), make_user("plain").pk), "unchanged"),
    ):
        with pytest.raises(RbacConflict) as refused:
            call()
        assert refused.value.reason == reason
    gone = make_user("gone")
    accounts.disable_user("gone")
    with pytest.raises(RbacConflict) as refused:
        administration.grant_admin(fresh(alice), gone.pk)
    assert refused.value.reason == "state"


# SEC-09 (service boundary) — every administrative mutation needs a fresh step-up proof (CWE-306)


def _mutations(principal, world):
    """One call per code-defined administrative mutation; fixtures are built beforehand."""
    team, role, member, user, extra = world
    return {
        "create_team": lambda: teams.create_team(principal, code="new", name="New"),
        "update_team": lambda: teams.update_team(principal, team.pk, name="Renamed"),
        "deactivate_team": lambda: teams.deactivate_team(principal, team.pk),
        "activate_team": lambda: teams.activate_team(principal, team.pk, "0" * 64, team.code),
        "add_member": lambda: teams.add_member(principal, team.pk, extra.joiner.pk),
        "remove_member": lambda: teams.remove_member(principal, team.pk, user.pk),
        "create_role": lambda: rbac.create_role(principal, code="new", name="New"),
        "update_role": lambda: rbac.update_role(principal, role.pk, name="Renamed"),
        "grant_permission": lambda: rbac.grant_permission(principal, role.pk, "assets.view_asset"),
        "revoke_permission": lambda: rbac.revoke_permission(principal, role.pk, VIEW),
        "assign_role": lambda: rbac.assign_role(principal, member.pk, extra.role.pk),
        "revoke_role": lambda: rbac.revoke_role(principal, member.pk, role.pk),
        "grant_admin": lambda: administration.grant_admin(principal, user.pk),
        "revoke_admin": lambda: administration.revoke_admin(principal, extra.admin.pk),
        "set_position": lambda: administration.set_position(principal, user.pk, "analyst"),
        "create_account": lambda: administration.create_account(principal, username="newbie"),
        "update_account": lambda: administration.update_account(
            principal, user.pk, changes={"first_name": "New"}
        ),
        "disable_account": lambda: administration.disable_account(principal, user.pk),
        "enable_account": lambda: administration.enable_account(principal, extra.disabled.pk),
        "issue_password_link": lambda: administration.issue_password_link(principal, user.pk),
    }


def _world():
    team = teams.create_team(OPERATOR, code="alpha", name="Alpha")
    user = make_user("member")
    member = teams.add_member(OPERATOR, team.pk, user.pk)
    role = rbac.create_role(OPERATOR, code="reader", name="Reader")
    rbac.grant_permission(OPERATOR, role.pk, VIEW)
    rbac.assign_role(OPERATOR, member.pk, role.pk)
    disabled = make_user("off")
    administration.disable_account(OPERATOR, disabled.pk)
    extra = SimpleNamespace(
        joiner=make_user("joiner"),
        role=rbac.create_role(OPERATOR, code="extra", name="Extra"),
        admin=make_admin("other"),
        disabled=disabled,
    )
    return team, role, member, user, extra


def test_every_administrative_mutation_requires_step_up_at_the_service_boundary(caplog):
    admin = make_admin("alice")
    world = _world()
    mutating = policy.ADMIN_OPERATIONS - policy.READ_OPERATIONS
    now = time.time()
    for proof in (None, now - 601, now + 30, True, "1"):
        principal = UserPrincipal(admin.pk, reauthenticated_at=proof)
        calls = _mutations(principal, world)
        assert set(calls) == mutating  # every code-defined mutation is exercised
        for name, call in calls.items():
            before = configuration()
            with pytest.raises(ReauthenticationRequired):
                call()
            assert configuration() == before, name
    assert not events_of("rbac.administration_denied").exists()
    assert any(r.getMessage() == "reauthentication_required" for r in caplog.records)
    # The same calls succeed with a fresh proof (each one on its own fixtures).
    calls = _mutations(fresh(admin), world)
    for name in ("create_team", "grant_permission", "assign_role", "set_position", "grant_admin"):
        calls[name]()
    # Reads need no proof (the team is still inactive).
    assert teams.preview_team_activation(UserPrincipal(admin.pk), world[0].pk).membership_count == 1
    policy.require_administration(UserPrincipal(admin.pk), "inspect_configuration")


def test_step_up_window_is_six_hundred_seconds(monkeypatch):
    admin = make_admin("alice")
    issued = 1_000_000.0
    principal = UserPrincipal(admin.pk, reauthenticated_at=issued)
    monkeypatch.setattr(policy.time, "time", lambda: issued + 600)
    teams.create_team(principal, code="edge", name="Edge")
    monkeypatch.setattr(policy.time, "time", lambda: issued + 600.5)
    with pytest.raises(ReauthenticationRequired):
        teams.create_team(principal, code="late", name="Late")
    assert policy.STEP_UP_WINDOW_SECONDS == 600


def test_step_up_expiring_before_commit_rolls_back(monkeypatch):
    admin = make_admin("alice")
    issued = time.time()
    clock = iter([issued + 10, issued + 601])  # admitted at the boundary, expired at commit time
    monkeypatch.setattr(policy.time, "time", lambda: next(clock))
    with pytest.raises(ReauthenticationRequired):
        teams.create_team(UserPrincipal(admin.pk, issued), code="late", name="Late")
    assert not Team.objects.filter(code="late").exists()


# SEC-17 — one position per user, even under concurrency (T-17, CWE-362)


def test_position_is_single_valued_under_concurrency_cwe_362():
    alice = make_admin("alice")
    target = make_user("target")
    blocked, first, second = race(
        lambda: administration.set_position(fresh(alice), target.pk, "analyst"),
        lambda: administration.set_position(OPERATOR, target.pk, "engineer"),
    )
    assert blocked and "error" not in first and "error" not in second, (first, second)
    assert PlatformAccess.objects.filter(pk=target.pk).count() == 1
    assert PlatformAccess.objects.get(pk=target.pk).position == "engineer"
    changes = [e.changes["position"] for e in events_of("rbac.position_changed").order_by("id")]
    assert changes == [
        {"before": None, "after": "analyst"},
        {"before": "analyst", "after": "engineer"},
    ]
    with pytest.raises(IntegrityError), transaction.atomic():
        PlatformAccess.objects.create(user=target, position="analyst")
    with pytest.raises(IntegrityError), transaction.atomic():
        PlatformAccess.objects.filter(pk=target.pk).update(position="admin")
    with pytest.raises(RbacConflict):
        administration.set_position(OPERATOR, target.pk, "engineer")
    with pytest.raises(RbacError):
        administration.set_position(OPERATOR, target.pk, "admin")
    administration.set_position(OPERATOR, target.pk, None)
    accounts.disable_user("target")
    with pytest.raises(RbacConflict):
        administration.set_position(OPERATOR, target.pk, "analyst")


# SEC-18 — a position grants nothing (T-18, CWE-269)


def test_position_grants_no_permission_cwe_269():
    team = teams.create_team(OPERATOR, code="alpha", name="Alpha")
    teams.activate_team(
        OPERATOR, team.pk, teams.preview_team_activation(OPERATOR, team.pk).revision, "alpha"
    )
    for position in ("analyst", "engineer"):
        user = make_user(position)
        administration.set_position(OPERATOR, user.pk, position)
        principal = UserPrincipal(user.pk, reauthenticated_at=time.time())
        assert not authorized_teams(principal).exists()
        assert not can_access(principal, VIEW, team_id=team.pk)
        assert not visible_assets(principal).exists()
        assert not is_platform_admin(principal)
        with pytest.raises(AdministrationDenied):
            teams.add_member(principal, team.pk, user.pk)


# SEC-24 — atomic audit; denials survive rollback (T-24, CWE-778)


def test_admin_mutations_are_audited_atomically_cwe_778(monkeypatch):
    alice, bob = make_admin("alice"), make_admin("bob")
    target = make_user("target")
    before = configuration()
    count = AuditEvent.objects.count()
    real = events.record_event

    def fail_after_write(**kwargs):
        real(**kwargs)
        raise RuntimeError("audit dependency failure")

    monkeypatch.setattr(events, "record_event", fail_after_write)
    for call in (
        lambda: administration.grant_admin(fresh(alice), target.pk),
        lambda: administration.set_position(fresh(alice), target.pk, "analyst"),
        lambda: administration.disable_account(fresh(alice), bob.pk),
    ):
        with pytest.raises(RuntimeError):
            call()
    monkeypatch.setattr(accounts, "record_event", fail_after_write)
    with pytest.raises(RuntimeError):
        administration.update_account(fresh(alice), target.pk, changes={"last_name": "X"})
    monkeypatch.undo()
    assert configuration() == before
    assert AuditEvent.objects.count() == count
    with pytest.raises(AdministrationDenied):
        administration.grant_admin(fresh(target), target.pk)
    assert not connection.in_atomic_block
    denial = events_of("rbac.administration_denied").get()
    assert denial.actor_id == target.pk and denial.metadata == {
        "operation": "grant_admin",
        "reason": "not_allowed",
    }


def test_admin_events_use_exact_allowlists():
    alice = make_admin("alice")
    target, _link = administration.create_account(fresh(alice), username="target")
    administration.update_account(fresh(alice), target.pk, changes={"email": "T@Example.COM"})
    administration.update_account(fresh(alice), target.pk, changes={"email": "T@example.com"})
    administration.set_position(fresh(alice), target.pk, "engineer")
    administration.grant_admin(fresh(alice), target.pk)
    administration.revoke_admin(fresh(alice), target.pk)
    administration.issue_password_link(fresh(alice), target.pk)
    administration.disable_account(fresh(alice), target.pk)
    administration.enable_account(fresh(alice), target.pk)
    expected = {
        "rbac.admin_granted": ({"is_admin"}, set()),
        "rbac.admin_revoked": ({"is_admin"}, {"reason"}),
        "rbac.position_changed": ({"position"}, set()),
        "accounts.user_created": (set(accounts._CREATED_FIELDS), set()),
        "accounts.user_updated": ({"email"}, set()),
        "accounts.password_link_issued": (set(), {"purpose"}),
        "accounts.user_disabled": ({"is_active"}, set()),
        "accounts.user_enabled": ({"is_active"}, set()),
    }
    recorded = AuditEvent.objects.filter(action__in=expected)
    assert {event.action for event in recorded} == set(expected)
    for event in recorded:
        changes, metadata = expected[event.action]
        assert set(event.changes) == changes and set(event.metadata) == metadata, event.action
    user_events = recorded.exclude(resource_id=str(alice.pk))
    assert {(e.actor_type, e.actor_id) for e in user_events} == {("user", alice.pk)}
    assert {e.resource_type for e in user_events} == {"accounts.user", "rbac.platformaccess"}
    # The second email update normalized to the same value: no write, no event (Semantics).
    assert events_of("accounts.user_updated").count() == 1
    assert events_of("accounts.user_updated").get().changes["email"]["after"] == "T@example.com"


# SEC-28 — nested calls lock the Admin set once, at the outer boundary (design review F-02)


def test_nested_administrative_calls_take_the_admin_set_lock_once():
    alice, _bob = make_admin("alice"), make_admin("bob")
    team, _role, member, user, _extra = _world()
    calls = []
    real = policy.locked_admin_set

    def spy(principal, target_id=None):
        calls.append(connection.in_atomic_block)
        return real(principal, target_id)

    with mock.patch.object(policy, "locked_admin_set", spy):
        teams.remove_member(fresh(alice), team.pk, user.pk)
    assert calls == [True]  # once, inside the outer transaction, after the role revocations
    assert not Membership.objects.filter(pk=member.pk).exists()
    assert events_of("rbac.role_revoked").get().actor_id == alice.pk
    assert not events_of("rbac.administration_denied").exists()


def test_admin_lock_timeout_and_deadlock_fail_closed_at_the_service(monkeypatch, caplog):
    alice = make_admin("alice")
    target = make_user("target")
    monkeypatch.setattr(policy, "ADMIN_LOCK_TIMEOUT", "300ms")
    held, release = threading.Event(), threading.Event()

    def hold():
        with transaction.atomic():
            list(PlatformAccess.objects.select_for_update().values_list("pk", flat=True))
            held.set()
            assert release.wait(10)

    holder, _ = in_thread("holder", hold)
    try:
        assert held.wait(10)
        started = time.monotonic()
        with pytest.raises(OperationalError) as failure:
            administration.set_position(fresh(alice), target.pk, "analyst")
        elapsed = time.monotonic() - started
    finally:
        release.set()
        holder.join(10)
    assert elapsed < 3 and failure.value.__cause__ is None
    assert not PlatformAccess.objects.filter(pk=target.pk).exists()
    assert any(getattr(r, "reason", None) == "lock_timeout" for r in caplog.records)

    def deadlock(*args, **kwargs):
        try:
            raise psycopg.errors.DeadlockDetected("deadlock detected")
        except psycopg.errors.DeadlockDetected as exc:
            raise OperationalError("deadlock detected") from exc

    with mock.patch.object(administration, "locked_admin_set", deadlock):
        with pytest.raises(OperationalError):
            administration.set_position(fresh(alice), target.pk, "analyst")
    assert any(getattr(r, "reason", None) == "deadlock" for r in caplog.records)
    assert not events_of("rbac.position_changed").exists()


# SEC-34 / BR-15 — CLI bootstrap and recovery under the same guards (T-34, CWE-863)


def test_cli_account_commands_enforce_admin_guards_cwe_863():
    run("accounts_create_user", "alice")
    run("rbac_grant_admin", "alice")
    alice = User.objects.get(username="alice")
    assert is_admin(alice)
    with pytest.raises(CommandError, match="already an Admin"):
        run("rbac_grant_admin", "alice")
    with pytest.raises(CommandError, match="At least one other enabled Admin must remain"):
        run("accounts_disable_user", "alice")
    with pytest.raises(CommandError, match="At least one other enabled Admin must remain"):
        run("rbac_revoke_admin", "alice")
    assert is_admin(alice) and User.objects.get(pk=alice.pk).is_active
    run("accounts_create_user", "bob")
    run("rbac_grant_admin", "bob")
    assert "all of its sessions have ended" in run("accounts_disable_user", "alice")
    assert not PlatformAccess.objects.get(pk=alice.pk).is_admin
    assert "/set-password#uid=" in run("accounts_enable_user", "alice")
    assert not is_admin(alice)
    account_events = AuditEvent.objects.filter(action__startswith="accounts.")
    assert {e.actor_label for e in account_events} == {"accounts-cli"}
    rbac_events = AuditEvent.objects.filter(action__startswith="rbac.")
    assert {e.actor_label for e in rbac_events} == {"trilha-operator"}
    assert set(AuditEvent.objects.values_list("source", flat=True)) == {"command"}
    revoked = events_of("rbac.admin_revoked").get()
    assert revoked.metadata == {"reason": "account_disabled"}
    with pytest.raises(CommandError, match="No account has that username"):
        run("rbac_grant_admin", "nobody")
    run("rbac_set_position", "bob", "engineer")
    run("rbac_set_position", "bob", "none")
    with pytest.raises(CommandError):
        run("rbac_set_position", "bob", "admin")
    for name in ("accounts_create_user", "accounts_password_link", "rbac_grant_admin"):
        assert get_commands()[name] == "apps.rbac"


def test_bootstrap_and_recovery_commands():
    assert not PlatformAccess.objects.exists()  # nothing seeded by migrations (SEC-33)
    run("accounts_create_user", "first")
    run("rbac_grant_admin", "first")
    # Recovery when the only Admin lost access: grant a new Admin, then retire the old one.
    run("accounts_create_user", "rescuer")
    run("rbac_grant_admin", "rescuer")
    run("rbac_revoke_admin", "first")
    assert admin_ids() == {User.objects.get(username="rescuer").pk}
    assert "/set-password#uid=" in run("accounts_password_link", "rescuer")
    assert list(events_of("rbac.admin_granted").values_list("actor_label", flat=True)) == [
        "trilha-operator",
        "trilha-operator",
    ]


# Data model — additive, reversible, nothing seeded


def test_platform_access_migration_is_additive_and_reversible():
    assert not PlatformAccess.objects.exists()
    executor = MigrationExecutor(connection)
    original = executor.loader.graph.leaf_nodes()
    try:
        executor.migrate([("rbac", "0001_initial")])
        tables = connection.introspection.table_names()
        assert "rbac_platformaccess" not in tables
        assert {"rbac_role", "teams_team", "accounts_user", "audit_auditevent"} <= set(tables)
    finally:
        MigrationExecutor(connection).migrate(original)
    assert "rbac_platformaccess" in connection.introspection.table_names()
    with connection.cursor() as cursor:
        constraints = connection.introspection.get_constraints(cursor, "rbac_platformaccess")
    assert constraints["platform_position"]["check"]
    assert not PlatformAccess.objects.exists() and not AuditEvent.objects.exists()


# Domain Model — module boundaries

DOMAIN_MODULES = {"services.py", "selectors.py", "policy.py", "administration.py"}


def test_admin_module_boundaries():
    root = Path(__file__).resolve().parents[1] / "apps"
    for path in (root / "accounts").rglob("*.py"):
        text = path.read_text()
        assert "apps.rbac" not in text and "apps.teams" not in text, path
    for app in ("rbac", "teams", "audit", "core", "accounts"):
        for path in (root / app).rglob("*.py"):
            if "migrations" in path.parts:
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert not node.module.startswith("apps.assets"), path
                    if app in {"rbac", "teams"}:
                        assert node.module != "apps.accounts.models", path
                    if path.name in DOMAIN_MODULES:
                        assert ".management" not in node.module, path
    for path in (root / "assets").rglob("*.py"):
        assert "apps.rbac.models" not in path.read_text(), path


# SEC-19 / SEC-20 (defense in depth) — the read selectors authorize too, before any lookup


def test_directory_selectors_authorize_before_any_lookup():
    admin, plain = make_admin("alice"), make_user("plain")
    team = teams.create_team(OPERATOR, code="alpha", name="Alpha")
    role = rbac.create_role(OPERATOR, code="reader", name="Reader")
    membership = teams.add_member(OPERATOR, team.pk, plain.pk)
    calls = {
        "user_directory": lambda p: list(directory.user_directory(p)),
        "user_detail": lambda p: directory.user_detail(p, plain.pk),
        "team_directory": lambda p: list(directory.team_directory(p)),
        "team_members": lambda p: list(directory.team_members(p, team.pk)),
        "membership_detail": lambda p: directory.membership_detail(p, membership.pk),
        "role_directory": lambda p: list(directory.role_directory(p)),
        "role_detail": lambda p: directory.role_detail(p, role.pk),
        "permission_catalog": directory.permission_catalog,
        "audit_search": lambda p: list(
            directory.audit_search(
                p, occurred_after=timezone.now() - timedelta(days=1), occurred_before=timezone.now()
            )
        ),
    }
    for name, call in calls.items():
        for principal in (UserPrincipal(plain.pk), OPERATOR):
            with pytest.raises(AdministrationDenied):
                call(principal)
        assert call(UserPrincipal(admin.pk)) is not None, name  # reads need no step-up
    assert not events_of("rbac.administration_denied").exists()  # reads are logged, not audited
