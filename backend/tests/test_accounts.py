"""Account model (SPEC-0003 SEC-17)."""

import uuid

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError


@pytest.mark.django_db
def test_user_primary_key_is_uuid():
    user = get_user_model().objects.create_user(username="alice", password="x" * 16)

    assert isinstance(user.pk, uuid.UUID)


# Escapes keep look-alikes visible: accented a, Cyrillic a, zero-width space, and a space.
@pytest.mark.parametrize("username", ["\u00e1lice", "\u0430lice", "alice\u200b", "al ice"])
def test_username_must_be_ascii_cwe_1007(username):
    user = get_user_model()(username=username)

    with pytest.raises(ValidationError) as raised:
        user.clean_fields(exclude=["password"])

    assert "username" in raised.value.message_dict


def test_ascii_username_is_valid():
    get_user_model()(username="alice.b-1@x").clean_fields(exclude=["password"])
