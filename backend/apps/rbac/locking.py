"""Bounded lock waits shared by mutations that follow the global lock order (SPEC-0005 F-21,
SPEC-0010 SEC-28). The only raw SQL is static; the timeout is a server constant bound as a parameter
and scoped to the caller's transaction, so no other code's lock behavior changes."""

from django.db import connection

from apps.accounts.selectors import users
from apps.rbac.selectors import assignments, roles
from apps.teams.selectors import teams

LOCK_FAILURES = {"55P03": "lock_timeout", "40P01": "deadlock"}


def lock_authority(principal, team_ids):
    """Locks the actor's authority rows in the global order (SPEC-0005 Concurrency, SPEC-0007
    BR-50): the roles assigned through the teams' memberships, the Team rows, then the User row,
    each in primary-key order. Every writer that can reduce that authority holds FOR UPDATE on one
    of them, so it commits before the caller's recheck or waits for the caller. Returns False when
    a role was assigned meanwhile; callers then refuse, because a Role is never locked after a Team.
    """
    team_ids = sorted(set(team_ids))

    def role_ids():
        return set(
            assignments()
            .filter(membership__user_id=principal.user_id, membership__team_id__in=team_ids)
            .values_list("role_id", flat=True)
        )

    candidates = role_ids()
    # Lock by primary key only: no row data (such as the password hash) is read into memory.
    for rows in (
        roles().filter(pk__in=candidates),
        teams().filter(pk__in=team_ids),
        users().filter(pk=principal.user_id),
    ):
        list(rows.select_for_update(no_key=True).order_by("pk").values_list("pk", flat=True))
    return role_ids() <= candidates


def bound_lock_waits(timeout):
    """The caller holds an atomic block; the setting ends with it."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('lock_timeout', %s, true)", [timeout])


def lock_failure(exc):
    """The reason of a lock timeout or deadlock, identified by SQLSTATE; None for other errors."""
    return LOCK_FAILURES.get(getattr(exc.__cause__, "sqlstate", None))
