"""Project error envelope shared by DRF and plain Django responses (CLAUDE.md §17)."""

from typing import Any

from django.http import JsonResponse

from apps.core.request_context import get_request_id


def error_payload(code: str, message: str, details: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    request_id = get_request_id()
    if request_id is not None:
        error["request_id"] = request_id
    return {"error": error}


def error_response(status: int, code: str, message: str, details: Any = None) -> JsonResponse:
    return JsonResponse(error_payload(code, message, details), status=status)
