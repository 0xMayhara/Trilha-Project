from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse

from apps.core.errors import error_response

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
