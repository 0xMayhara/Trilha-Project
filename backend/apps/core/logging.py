"""Structured JSON logging with central redaction (SPEC-0001 SEC-13, CWE-532, CWE-117)."""

import json
import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from django.http import HttpRequest

from apps.core.request_context import get_request_id

REDACTED = "[REDACTED]"

SENSITIVE_KEY = re.compile(
    r"password|passwd|secret|token|authorization|cookie|session|api[_-]?key|private[_-]?key"
    r"|credential",
    re.IGNORECASE,
)

_RESERVED_ATTRIBUTES = frozenset(
    vars(logging.LogRecord("", logging.INFO, "", 0, "", None, None))
) | {"message", "asctime"}


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: REDACTED if isinstance(key, str) and SENSITIVE_KEY.search(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [redact(item) for item in value]
    if isinstance(value, HttpRequest):
        # Django passes the request object as log context; its repr includes the query string.
        return {"method": value.method, "path": value.path}
    return value


class JsonFormatter(logging.Formatter):
    """One JSON object per line. json.dumps escapes control characters, so untrusted values cannot
    forge additional log lines."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": get_request_id(),
        }
        extras = {
            key: value
            for key, value in vars(record).items()
            if key not in _RESERVED_ATTRIBUTES and not key.startswith("_")
        }
        payload.update(redact(extras))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=True)
