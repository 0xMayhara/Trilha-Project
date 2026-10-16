from django.http import HttpRequest


def client_ip(request: HttpRequest) -> str | None:
    """Client address as seen by the single trusted proxy, which appends it as the last
    X-Forwarded-For entry (SPEC-0001 SEC-18). Matches DRF's NUM_PROXIES=1 behavior."""
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[-1].strip()
    return request.META.get("REMOTE_ADDR")
