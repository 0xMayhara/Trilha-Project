"""Explicit request and response shapes of the authentication API (SPEC-0003 API Contract)."""

from rest_framework import serializers

from apps.accounts.models import User

# Bounds the hashing work per request (SEC-12, CWE-400).
PASSWORD_MAX_LENGTH = 1024


def _password_field() -> serializers.CharField:
    return serializers.CharField(max_length=PASSWORD_MAX_LENGTH, trim_whitespace=False)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, trim_whitespace=False)
    password = _password_field()


class PasswordChangeSerializer(serializers.Serializer):
    current_password = _password_field()
    new_password = _password_field()


class ReauthenticateSerializer(serializers.Serializer):
    password = _password_field()


class PasswordSetSerializer(serializers.Serializer):
    uid = serializers.CharField(max_length=64)
    token = serializers.CharField(max_length=128)
    new_password = _password_field()


class UserSummarySerializer(serializers.ModelSerializer):
    """The only account data the API returns (SEC-15)."""

    class Meta:
        model = User
        fields = ("id", "username", "first_name", "last_name")
        read_only_fields = fields
