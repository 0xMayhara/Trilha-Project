"""JSON handlers for errors raised outside DRF views. Messages are generic by design (CWE-209)."""

from django.http import HttpRequest, JsonResponse

from apps.core.errors import error_response


def bad_request(request: HttpRequest, exception: Exception) -> JsonResponse:
    return error_response(400, "bad_request", "Bad request.")


def permission_denied(request: HttpRequest, exception: Exception) -> JsonResponse:
    return error_response(403, "permission_denied", "You do not have permission.")


def page_not_found(request: HttpRequest, exception: Exception) -> JsonResponse:
    return error_response(404, "not_found", "Not found.")


def server_error(request: HttpRequest) -> JsonResponse:
    return error_response(500, "server_error", "Internal server error.")


def csrf_failure(request: HttpRequest, reason: str = "") -> JsonResponse:
    return error_response(403, "csrf_failed", "CSRF verification failed.")
