"""Test-only routes exercising the API baseline. Never part of the project URLconf."""

from django.db import OperationalError
from django.urls import path
from rest_framework import serializers
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from config.urls import handler400, handler403, handler404, handler500, urlpatterns

__all__ = ["handler400", "handler403", "handler404", "handler500", "urlpatterns"]


class AuthenticatedView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response({"ok": True})

    def post(self, request):
        return Response({"ok": True})


class NoPermissionsDeclaredView(APIView):
    def get(self, request):
        return Response({"ok": True})


class NameSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=5)


class ValidationView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        NameSerializer(data=request.data).is_valid(raise_exception=True)
        return Response({"ok": True})


class BoomView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        raise RuntimeError("internal detail: /etc/trilha/secret.conf password=hunter2")


class DatabaseDownView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        raise OperationalError("could not connect to server at 10.0.0.5")


class TwoPerMinuteThrottle(AnonRateThrottle):
    rate = "2/min"


class ThrottledView(APIView):
    authentication_classes = ()
    permission_classes = ()
    throttle_classes = (TwoPerMinuteThrottle,)

    def get(self, request):
        return Response({"ok": True})


class ItemsView(GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        page = self.paginate_queryset(list(range(150)))
        return self.get_paginated_response(page)


urlpatterns = [
    *urlpatterns,
    path("api/test/authenticated/", AuthenticatedView.as_view()),
    path("api/test/no-permissions/", NoPermissionsDeclaredView.as_view()),
    path("api/test/validation/", ValidationView.as_view()),
    path("api/test/boom/", BoomView.as_view()),
    path("api/test/db-down/", DatabaseDownView.as_view()),
    path("api/test/throttled/", ThrottledView.as_view()),
    path("api/test/items/", ItemsView.as_view()),
]
