from unittest import mock

import pytest
from django.core.management import CommandError, call_command
from django.db import OperationalError


@pytest.mark.django_db
def test_check_ready_succeeds_when_dependencies_are_reachable(capsys):
    call_command("check_ready")

    assert capsys.readouterr().out.strip() == "ready"


@pytest.mark.django_db
def test_check_ready_fails_without_leaking_error_details():
    failure = OperationalError("could not connect to server at 10.0.0.5 password=x")

    with (
        mock.patch("django.core.cache.cache.get", side_effect=failure),
        pytest.raises(CommandError) as raised,
    ):
        call_command("check_ready")

    assert str(raised.value) == "Not ready."
