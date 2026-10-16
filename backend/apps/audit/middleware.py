from collections.abc import Callable

from django.http import HttpRequest, HttpResponse

from apps.audit.context import http_context
from apps.core.http import client_ip


class AuditContextMiddleware:
    """Binds source `http` and the proxy-appended client IP for audit events (SPEC-0002 BR-06,
    SEC-09). The context is reset when the request ends, including on exceptions (SEC-19)."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        with http_context(client_ip(request)):
            return self.get_response(request)
