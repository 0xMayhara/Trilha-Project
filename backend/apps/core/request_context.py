"""Per-request correlation ID shared by logs, error envelopes and tasks (SPEC-0001 SEC-14)."""

import uuid
from contextvars import ContextVar

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    return request_id_var.get()


def parse_request_id(raw: str | None) -> str:
    """Accept an incoming ID only if it is a UUID; anything else is replaced (CWE-117)."""
    if raw and len(raw) <= 36:
        try:
            return str(uuid.UUID(raw))
        except ValueError:
            pass
    return str(uuid.uuid4())
