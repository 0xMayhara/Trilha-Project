"""Session authentication endpoints (SPEC-0003). Thin adapters over apps.accounts.services."""

from django.core.exceptions import ValidationError as DjangoValidationError
from django.middleware.csrf import get_token
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts import services
from apps.accounts.serializers import (
    LoginSerializer,
    PasswordChangeSerializer,
    PasswordSetSerializer,
    UserSummarySerializer,
)
from apps.accounts.throttles import (
    LoginAddressThrottle,
    LoginUsernameThrottle,
    PasswordChangeThrottle,
    PasswordSetThrottle,
)
from apps.core.errors import error_payload


class CsrfEnforcedSessionAuthentication(SessionAuthentication):
    """DRF checks CSRF only once a session user exists. Login and password set are anonymous, so
    this also checks it for anonymous requests (login CSRF, SEC-03, CWE-352)."""

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            self.enforce_csrf(request)
        return result


def _validated(serializer_class, request: Request) -> dict:
    serializer = serializer_class(data=request.data)
    serializer.is_valid(raise_exception=True)
    return serializer.validated_data


class CsrfView(APIView):
    """AllowAny (SPEC-0003): sets the CSRF cookie the frontend sends back; returns no data."""

    authentication_classes = ()
    permission_classes = (AllowAny,)

    def get(self, request: Request) -> Response:
        get_token(request)
        return Response(status=204)


class LoginView(APIView):
    """AllowAny (SPEC-0003): the endpoint that authenticates. CSRF is still enforced."""

    authentication_classes = (CsrfEnforcedSessionAuthentication,)
    permission_classes = (AllowAny,)
    throttle_classes = (LoginAddressThrottle, LoginUsernameThrottle)

    def post(self, request: Request) -> Response:
        data = _validated(LoginSerializer, request)
        try:
            user = services.log_in(request, data["username"], data["password"])
        except services.InvalidCredentials:
            # One answer for every failure: unknown, wrong, disabled or no password (SEC-05).
            return Response(
                error_payload("invalid_credentials", "Invalid username or password."), status=400
            )
        return Response(UserSummarySerializer(user).data)


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request: Request) -> Response:
        services.log_out(request)
        return Response(status=204)


class MeView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request: Request) -> Response:
        return Response(UserSummarySerializer(request.user).data)


class PasswordChangeView(APIView):
    permission_classes = (IsAuthenticated,)
    throttle_classes = (PasswordChangeThrottle,)

    def post(self, request: Request) -> Response:
        data = _validated(PasswordChangeSerializer, request)
        try:
            services.change_password(request, data["current_password"], data["new_password"])
        except services.WrongCurrentPassword:
            raise ValidationError(
                {"current_password": ["The current password is incorrect."]}
            ) from None
        except DjangoValidationError as exc:
            raise ValidationError({"new_password": exc.messages}) from None
        return Response(status=204)


class PasswordSetView(APIView):
    """AllowAny (SPEC-0003): the link holder is not logged in; the one-time token is the
    authorization. CSRF is still enforced."""

    authentication_classes = (CsrfEnforcedSessionAuthentication,)
    permission_classes = (AllowAny,)
    throttle_classes = (PasswordSetThrottle,)

    def post(self, request: Request) -> Response:
        data = _validated(PasswordSetSerializer, request)
        try:
            services.set_password_from_link(data["uid"], data["token"], data["new_password"])
        except services.InvalidLink:
            return Response(
                error_payload("invalid_link", "This link is invalid or has expired."), status=400
            )
        except DjangoValidationError as exc:
            raise ValidationError({"new_password": exc.messages}) from None
        return Response(status=204)
