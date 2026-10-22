"""DRF exception handler producing the project error envelope (CLAUDE.md §17, SPEC-0001 SEC-10)."""

import logging
import math
from typing import Any

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.db import InterfaceError, OperationalError
from django.http import Http404
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework.views import set_rollback

from apps.core.errors import error_payload

logger = logging.getLogger(__name__)

_DEPENDENCY_UNAVAILABLE = (
    OperationalError,
    InterfaceError,
    RedisConnectionError,
    RedisTimeoutError,
)


class Conflict(exceptions.APIException):
    """A request that conflicts with current state: stale version, invalid transition, duplicate."""

    status_code = 409
    default_detail = "The request conflicts with the current state."
    default_code = "conflict"


_CODES: dict[type[exceptions.APIException], str] = {
    Conflict: "conflict",
    exceptions.ValidationError: "validation_error",
    exceptions.ParseError: "parse_error",
    exceptions.NotAuthenticated: "not_authenticated",
    exceptions.AuthenticationFailed: "not_authenticated",
    exceptions.PermissionDenied: "permission_denied",
    exceptions.NotFound: "not_found",
    exceptions.MethodNotAllowed: "method_not_allowed",
    exceptions.NotAcceptable: "not_acceptable",
    exceptions.UnsupportedMediaType: "unsupported_media_type",
    exceptions.Throttled: "throttled",
}

# Session authentication has no challenge scheme; this one keeps 401 responses RFC 9110 compliant.
_AUTHENTICATE_HEADER = 'Session realm="api"'


def exception_handler(exc: Exception, context: dict[str, Any]) -> Response:
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, DjangoPermissionDenied):
        exc = exceptions.PermissionDenied()

    set_rollback()

    if isinstance(exc, exceptions.APIException):
        return _api_exception_response(exc)
    if isinstance(exc, _DEPENDENCY_UNAVAILABLE):
        logger.exception("Dependency unavailable while handling request")
        return Response(
            error_payload("service_unavailable", "Service temporarily unavailable."), status=503
        )
    logger.exception("Unhandled exception while handling request")
    return Response(error_payload("server_error", "Internal server error."), status=500)


def _api_exception_response(exc: exceptions.APIException) -> Response:
    code = next((code for cls, code in _CODES.items() if isinstance(exc, cls)), "error")
    status = exc.status_code
    headers: dict[str, str] = {}
    details = None

    if isinstance(exc, exceptions.ValidationError):
        message = "Invalid input."
        details = exc.detail if isinstance(exc.detail, dict) else {"non_field_errors": exc.detail}
    elif isinstance(exc, exceptions.ParseError):
        message = "Malformed request body."
    else:
        message = str(exc.detail)

    if isinstance(exc, exceptions.NotAuthenticated | exceptions.AuthenticationFailed):
        status = 401
        headers["WWW-Authenticate"] = _AUTHENTICATE_HEADER
    if isinstance(exc, exceptions.Throttled) and exc.wait is not None:
        headers["Retry-After"] = str(math.ceil(exc.wait))

    return Response(error_payload(code, message, details), status=status, headers=headers)
