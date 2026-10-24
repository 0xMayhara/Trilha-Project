"""SPEC-0007 BR-17: the asset transfer participant contract, with a stand-in participant. The
findings participant itself is tested in test_findings_transfer.py."""

import pytest
from django.db import connection

from apps.assets import transfer
from apps.assets.exceptions import TransferUnconfirmed
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from tests.test_assets_security import ASSET_CODES, build_world, detail, grant, reload

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


@pytest.fixture
def world():
    return build_world()


class Recorder:
    def __init__(self, fail_in=None):
        self.calls, self.fail_in = [], fail_in

    def authorize(self, principal, asset, source, destination, finding_count):
        assert connection.in_atomic_block
        self.calls.append(("authorize", asset.team_id, source, destination, finding_count))
        if self.fail_in == "authorize":
            raise TransferUnconfirmed

    def record(self, principal, asset, source, destination):
        assert connection.in_atomic_block
        self.calls.append(("record", asset.team_id, source, destination))
        if self.fail_in == "record":
            raise RuntimeError("participant failure")


@pytest.fixture
def participant(monkeypatch):
    def install(fail_in=None):
        recorder = Recorder(fail_in)
        monkeypatch.setattr(transfer, "_participants", [recorder])
        return recorder

    return install


def body(world, **extra):
    return {"version": 1, "team_id": str(world.beta.pk), **extra}


def test_participants_authorize_before_and_record_after_the_move(world, participant):
    grant(world.manager, world.beta, *ASSET_CODES)
    recorder = participant()
    response = world.client.post(
        detail(world.asset, "transfer/"), body(world, finding_count=2), format="json"
    )
    assert response.status_code == 200, response.content
    alpha, beta = world.alpha.pk, world.beta.pk
    assert recorder.calls == [("authorize", alpha, alpha, beta, 2), ("record", beta, alpha, beta)]
    transfer.register(recorder)
    transfer.register(recorder)  # idempotent
    assert transfer.participants() == (recorder,)


def test_participant_refusal_or_failure_rolls_the_transfer_back(world, participant):
    grant(world.manager, world.beta, *ASSET_CODES)
    events = AuditEvent.objects.filter(action="assets.asset_transferred")
    participant("authorize")
    refused = world.client.post(detail(world.asset, "transfer/"), body(world), format="json")
    assert refused.status_code == 409
    assert refused.json()["error"]["message"] == (
        "This asset has findings. Review them and confirm the transfer."
    )
    participant("record")
    failed = world.client.post(detail(world.asset, "transfer/"), body(world), format="json")
    assert failed.status_code == 500 and failed.json()["error"]["code"] == "server_error"
    asset = reload(world.asset)
    assert (asset.team_id, asset.version) == (world.alpha.pk, 1) and not events.exists()


def test_finding_count_is_optional_and_strictly_typed(world, participant):
    grant(world.manager, world.beta, *ASSET_CODES)
    recorder = participant()
    for value in (True, -1, "1", 1.0, None):
        response = world.client.post(
            detail(world.asset, "transfer/"), body(world, finding_count=value), format="json"
        )
        assert response.status_code == 400, value
    assert recorder.calls == [] and reload(world.asset).team_id == world.alpha.pk
    assert (
        world.client.post(detail(world.asset, "transfer/"), body(world), format="json").status_code
        == 200
    )
    assert recorder.calls[0][-1] is None  # absent means no acknowledgement
