import logging
import time
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.utils.functional import SimpleLazyObject, empty

from apps.core.errors import error_response
from apps.core.http import client_ip
from apps.core.request_context import parse_request_id, request_id_var

access_logger = logging.getLogger("apps.access")

SECURITY_EVENT_STATUSES = frozenset({401, 403, 413, 429})

API_CONTENT_SECURITY_POLICY = "default-src 'none'; frame-ancestors 'none'"


class SecurityHeadersMiddleware:
    """Headers for API responses not covered by Django's SecurityMiddleware (SPEC-0001 SEC-05)."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        response.headers.setdefault("Content-Security-Policy", API_CONTENT_SECURITY_POLICY)
        response.headers.setdefault("Cache-Control", "no-store")
        return response


class MaxBodySizeMiddleware:
    """Rejects oversized bodies before parsing. DRF parsers read the raw stream and do not apply
    DATA_UPLOAD_MAX_MEMORY_SIZE themselves (SPEC-0001 SEC-11, CWE-400)."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        try:
            content_length = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            return error_response(400, "bad_request", "Invalid Content-Length header.")
        if content_length > settings.DATA_UPLOAD_MAX_MEMORY_SIZE:
            return error_response(413, "payload_too_large", "Request body is too large.")
        return self.get_response(request)


class RequestIdMiddleware:
    """Assigns the correlation ID used by logs, error envelopes and tasks (SPEC-0001 SEC-14)."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request_id = parse_request_id(request.META.get("HTTP_X_REQUEST_ID"))
        token = request_id_var.set(request_id)
        try:
            response = self.get_response(request)
        finally:
            request_id_var.reset(token)
        response["X-Request-ID"] = request_id
        return response


class AccessLogMiddleware:
    """One structured line per request. Logs the path without query string and never headers or
    bodies (SPEC-0001 SEC-13)."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        started = time.monotonic()
        response = self.get_response(request)
        status = response.status_code
        if status >= 500:
            level = logging.ERROR
        elif status in SECURITY_EVENT_STATUSES:
            level = logging.WARNING
        else:
            level = logging.INFO
        access_logger.log(
            level,
            "http_request",
            extra={
                "event": "http_request",
                "method": request.method,
                "path": request.path,
                "status": status,
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
                "user_id": _authenticated_user_id(request),
                "client_ip": client_ip(request),
            },
        )
        return response


def _authenticated_user_id(request: HttpRequest) -> str | None:
    # Only report a user that was already resolved; resolving it here would cost a session lookup.
    user = vars(request).get("user")
    if user is None or (isinstance(user, SimpleLazyObject) and user._wrapped is empty):
        return None
    return str(user.pk) if user.is_authenticated else None
