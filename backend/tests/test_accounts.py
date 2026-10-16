import uuid

import pytest
from django.contrib.auth import get_user_model


@pytest.mark.django_db
def test_user_primary_key_is_uuid():
    user = get_user_model().objects.create_user(username="alice", password="x" * 16)

    assert isinstance(user.pk, uuid.UUID)
