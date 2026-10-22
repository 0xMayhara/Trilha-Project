from datetime import UTC, datetime

from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.services import step_up_verified_at
from apps.rbac.permissions import ActiveSession
from apps.rbac.policy import STEP_UP_WINDOW_SECONDS, step_up_is_fresh
from apps.rbac.principals import session_principal
from apps.rbac.selectors import is_platform_admin, own_access, platform_access
from apps.rbac.serializers import AccessEntrySerializer


def request_principal(request):
    """The session principal with this session's own step-up proof (SEC-10). The proof is read
    from the server-side session only; request bodies, headers and cookies never supply it."""
    return session_principal(request.user, step_up_verified_at(request))


def validate_query(request, *, paginated=True, extra=()):
    """Rejects unknown or repeated keys. `extra` names single-valued keys the caller validates."""
    allowed = {"page", "page_size"} if paginated else set()
    if set(request.query_params) - allowed - set(extra):
        raise ValidationError({"query": ["Unsupported query parameter."]})
    for key in set(extra) & set(request.query_params):
        if len(request.query_params.getlist(key)) != 1:
            raise ValidationError({key: ["Expected one value."]})
    for key in allowed & set(request.query_params):
        values = request.query_params.getlist(key)
        value = values[0]
        if (
            len(values) != 1
            or len(value) > 10
            or not value.isascii()
            or not value.isdecimal()
            or int(value) < 1
        ):
            raise ValidationError({key: ["Expected one positive integer."]})


class OwnAccessView(ListAPIView):
    permission_classes = (ActiveSession,)
    serializer_class = AccessEntrySerializer

    def get_queryset(self):
        validate_query(self.request)
        return own_access(session_principal(self.request.user))


class PlatformSelfView(APIView):
    """The caller's own platform state, for the UI only (SPEC-0010 PlatformSelf)."""

    permission_classes = (ActiveSession,)

    def get(self, request):
        validate_query(request, paginated=False)
        principal = request_principal(request)
        until = None
        if step_up_is_fresh(principal):
            until = datetime.fromtimestamp(
                principal.reauthenticated_at + STEP_UP_WINDOW_SECONDS, tz=UTC
            )
        return Response(
            {
                "is_admin": is_platform_admin(principal),
                "position": platform_access(principal.user_id).position,
                "reauthenticated_until": until,
            }
        )
