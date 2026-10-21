"""Throttles for the authentication endpoints (SPEC-0003 BR-09, SEC-06, SEC-07).

DRF keeps the counters in the Django cache (Redis in deployments). Each check reads the counter and
then writes it, so concurrent requests can exceed a limit by a few attempts (TM-0003 R-B). A cache
error propagates and the request is answered 503; it is never served unthrottled (SPEC-0001).
"""

from django.utils.crypto import salted_hmac
from rest_framework.throttling import SimpleRateThrottle

from apps.core.http import client_ip


class _ClientAddressThrottle(SimpleRateThrottle):
    def get_cache_key(self, request, view):
        # The validated address appended by the proxy; every invalid one shares one bucket.
        ident = client_ip(request._request) or "invalid"
        return self.cache_format % {"scope": self.scope, "ident": ident}


class LoginAddressThrottle(_ClientAddressThrottle):
    scope = "login_ip"


class PasswordSetThrottle(_ClientAddressThrottle):
    scope = "password_set"


class LoginUsernameThrottle(SimpleRateThrottle):
    """Counts attempts per submitted username, whether or not the account exists."""

    scope = "login_username"

    def get_cache_key(self, request, view):
        data = request.data
        username = data.get("username") if isinstance(data, dict) else None
        if not isinstance(username, str):
            return None  # Rejected by the serializer; still counted per address.
        # A keyed hash: the submitted value may be a mistyped password (SEC-20).
        ident = salted_hmac(
            "apps.accounts.throttles.username", username.lower(), algorithm="sha256"
        ).hexdigest()
        return self.cache_format % {"scope": self.scope, "ident": ident}


class PasswordChangeThrottle(SimpleRateThrottle):
    scope = "password_change"

    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": request.user.pk}
