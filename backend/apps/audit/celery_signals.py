"""Binds source `task` for audit events recorded inside Celery tasks (SPEC-0002 BR-06, SEC-19)."""

from typing import Any

from celery.signals import task_postrun, task_prerun

from apps.audit.context import bind_task_context, unbind_task_context

_TOKENS_ATTRIBUTE = "_audit_context_tokens"


@task_prerun.connect
def bind_audit_task_context(task: Any = None, **kwargs: Any) -> None:
    tokens = bind_task_context()
    request = getattr(task, "request", None)
    if request is not None:
        setattr(request, _TOKENS_ATTRIBUTE, tokens)


@task_postrun.connect
def unbind_audit_task_context(task: Any = None, **kwargs: Any) -> None:
    # task_postrun is sent whether the task succeeded or raised. Restoring the previous values
    # (rather than clearing them) keeps an enclosing context intact when a task runs eagerly.
    request = getattr(task, "request", None)
    unbind_task_context(getattr(request, _TOKENS_ATTRIBUTE, None))
