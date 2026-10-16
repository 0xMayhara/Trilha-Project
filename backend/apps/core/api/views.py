from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView


class LivenessView(APIView):
    """Public liveness probe. AllowAny is justified by SPEC-0001: the body is constant and the view
    performs no I/O (no session lookup, no throttle cache) and exposes no version data (SEC-19)."""

    authentication_classes = ()
    permission_classes = (AllowAny,)
    throttle_classes = ()

    def get(self, request: Request) -> Response:
        return Response({"status": "ok"})
