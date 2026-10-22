from rest_framework.throttling import SimpleRateThrottle


class AssetWriteThrottle(SimpleRateThrottle):
    """Per-user budget for asset mutations (SEC-30). Reads never consume it."""

    scope = "asset_write"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": request.user.pk}
