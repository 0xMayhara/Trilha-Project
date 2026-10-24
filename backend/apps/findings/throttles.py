from rest_framework.throttling import SimpleRateThrottle


class FindingWriteThrottle(SimpleRateThrottle):
    """Per-user budget for finding mutations (SPEC-0007 SEC-32). Reads never consume it."""

    scope = "finding_write"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": request.user.pk}
