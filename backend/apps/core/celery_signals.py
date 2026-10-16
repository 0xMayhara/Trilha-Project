"""Carries the HTTP request ID into Celery tasks so logs correlate (SPEC-0001 SEC-14)."""

from typing import Any

from celery.signals import before_task_publish, task_postrun, task_prerun

from apps.core.request_context import get_request_id, parse_request_id, request_id_var

REQUEST_ID_HEADER = "request_id"


@before_task_publish.connect
def attach_request_id(headers: dict[str, Any] | None = None, **kwargs: Any) -> None:
    request_id = get_request_id()
    if headers is not None and request_id is not None:
        headers.setdefault(REQUEST_ID_HEADER, request_id)


@task_prerun.connect
def bind_request_id(task: Any = None, **kwargs: Any) -> None:
    request = getattr(task, "request", None)
    raw = getattr(request, REQUEST_ID_HEADER, None) or (
        (getattr(request, "headers", None) or {}).get(REQUEST_ID_HEADER)
    )
    # Broker messages are untrusted input: the header is validated like the HTTP one.
    request_id_var.set(parse_request_id(raw))


@task_postrun.connect
def unbind_request_id(**kwargs: Any) -> None:
    request_id_var.set(None)
