from rest_framework.throttling import SimpleRateThrottle


class AdminWriteThrottle(SimpleRateThrottle):
    """Per-user budget for administrative mutations (SPEC-0010 SEC-22). Reads never consume it."""

    scope = "admin_write"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": request.user.pk}
