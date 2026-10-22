"""Bounded lock waits shared by mutations that follow the global lock order (SPEC-0005 F-21,
SPEC-0010 SEC-28). The only raw SQL is static; the timeout is a server constant bound as a parameter
and scoped to the caller's transaction, so no other code's lock behavior changes."""

from django.db import connection

LOCK_FAILURES = {"55P03": "lock_timeout", "40P01": "deadlock"}


def bound_lock_waits(timeout):
    """The caller holds an atomic block; the setting ends with it."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('lock_timeout', %s, true)", [timeout])


def lock_failure(exc):
    """The reason of a lock timeout or deadlock, identified by SQLSTATE; None for other errors."""
    return LOCK_FAILURES.get(getattr(exc.__cause__, "sqlstate", None))
