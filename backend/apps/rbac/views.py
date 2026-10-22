from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView

from apps.rbac.permissions import ActiveSession
from apps.rbac.principals import session_principal
from apps.rbac.selectors import own_access
from apps.rbac.serializers import AccessEntrySerializer


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
