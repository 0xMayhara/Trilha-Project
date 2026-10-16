"""Where an audit event comes from: the source (http, task, sync, command) and, for HTTP, the client
IP. Bound by the middleware, the Celery signals or audit_source(), never by the caller of
record_event() (SPEC-0002 BR-05, BR-06)."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from apps.audit.exceptions import AuditContextMissing
from apps.audit.models import Source

_source_var: ContextVar[Source | None] = ContextVar("audit_source", default=None)
_client_ip_var: ContextVar[str | None] = ContextVar("audit_client_ip", default=None)


@dataclass(frozen=True, slots=True)
class AuditContext:
    source: Source
    client_ip: str | None


def current_context() -> AuditContext:
    source = _source_var.get()
    if source is None:
        raise AuditContextMissing(
            "No audit context is bound; wrap commands and jobs in audit_source()."
        )
    return AuditContext(source=source, client_ip=_client_ip_var.get())


@contextmanager
def _bound(source: Source, client_ip: str | None) -> Iterator[None]:
    source_token = _source_var.set(source)
    client_ip_token = _client_ip_var.set(client_ip)
    try:
        yield
    finally:
        # Reset even when the wrapped code raises, so nothing leaks to the next request (SEC-19).
        _client_ip_var.reset(client_ip_token)
        _source_var.reset(source_token)


@contextmanager
def audit_source(source: Source | str) -> Iterator[None]:
    """Binds a source for management commands and sync jobs; restores the previous one on exit."""
    with _bound(Source(source), None):
        yield


@contextmanager
def http_context(client_ip: str | None) -> Iterator[None]:
    """Used only by AuditContextMiddleware."""
    with _bound(Source.HTTP, client_ip):
        yield


def bind_task_context() -> tuple[object, object]:
    """Used only by the Celery task_prerun handler; returns the tokens to restore afterwards."""
    return _source_var.set(Source.TASK), _client_ip_var.set(None)


def unbind_task_context(tokens: tuple[object, object] | None) -> None:
    """Used only by the Celery task_postrun handler."""
    if tokens is None:
        _source_var.set(None)
        _client_ip_var.set(None)
        return
    source_token, client_ip_token = tokens
    _client_ip_var.reset(client_ip_token)
    _source_var.reset(source_token)
