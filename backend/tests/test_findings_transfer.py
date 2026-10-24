"""SPEC-0007 BR-15-BR-18 / SEC-17-SEC-20: findings follow a transferred asset, under dual
authorization and an explicit acknowledgement, atomically and in lock order."""

import threading
import time
from types import SimpleNamespace
from unittest import mock

import pytest
from django.core import checks
from django.core.management import call_command
from django.core.management.base import CommandError, SystemCheckError
from django.db import transaction

from apps.assets import services as assets
from apps.assets import transfer
from apps.assets.models import Asset
from apps.audit.context import audit_source
from apps.audit.models import AuditEvent
from apps.findings import services
from apps.findings import transfer as participant
from apps.findings.models import Finding, FindingLogEntry
from apps.rbac.principals import UserPrincipal
from tests.test_assets_security import (
    ASSET_CODES,
    client_for,
    grant,
    in_thread,
    make_team,
    make_user,
)
from tests.test_findings_api import NEW, REPORTER, VIEW, detail, logbook

pytestmark = pytest.mark.django_db
ASSETS = "/api/v1/assets/"
UNCONFIRMED = "This asset has findings. Review them and confirm the transfer."


@pytest.fixture(autouse=True)
def audit_context():
    with audit_source("command"):
        yield


def build_world():
    alpha, beta = make_team("alpha"), make_team("beta")
    mover = make_user("mover")
    for team in (alpha, beta):
        grant(mover, team, *ASSET_CODES, VIEW)
    principal = UserPrincipal(mover.pk)
    asset = assets.create_asset(principal, team_id=alpha.pk, name="Web 01", kind="server")
    bare = assets.create_asset(principal, team_id=alpha.pk, name="Bare", kind="server")
    reporter = make_user("reporter")
    grant(reporter, alpha, *REPORTER)
    findings = [
        services.create_finding(
            UserPrincipal(reporter.pk), asset_id=asset.pk, **{**NEW, "title": t}
        )
        for t in ("First", "Second")
    ]
    return SimpleNamespace(
        alpha=alpha,
        beta=beta,
        mover=mover,
        client=client_for(mover),
        asset=asset,
        bare=bare,
        reporter=reporter,
        findings=findings,
    )


@pytest.fixture
def world(db):
    return build_world()


def move(client, asset, team, **extra):
    body = {"version": Asset.objects.get(pk=asset.pk).version, "team_id": str(team.pk), **extra}
    return client.post(f"{ASSETS}{asset.pk}/transfer/", body, format="json")


def snapshot():
    return (
        list(Asset.objects.order_by("pk").values()),
        list(Finding.objects.order_by("pk").values()),
        list(FindingLogEntry.objects.order_by("pk").values()),
        AuditEvent.objects.count(),
    )


# SEC-17 — view_finding in both teams (T-17, CWE-200)


def test_transfer_with_findings_requires_finding_authority_in_both_teams_cwe_200(world):
    before = snapshot()
    for team in (world.alpha, world.beta):  # missing in the source, then in the destination
        holder = make_user(f"holder-{team.code}")
        grant(holder, world.alpha, *ASSET_CODES, *([VIEW] if team == world.beta else []))
        grant(holder, world.beta, *ASSET_CODES, *([VIEW] if team == world.alpha else []))
        refused = move(client_for(holder), world.asset, world.beta, finding_count=2)
        assert refused.status_code == 403, team.code
        text = refused.content.decode()
        assert "First" not in text and "finding_count" not in text  # nothing about the findings
    assert snapshot()[0:3] == before[0:3]
    assert not AuditEvent.objects.filter(
        action__in=("assets.asset_transferred", "findings.asset_findings_transferred")
    ).exists()
    assert move(world.client, world.asset, world.beta, finding_count=2).status_code == 200


# SEC-18 — explicit acknowledgement of the current count (T-18, CWE-841)


def test_transfer_requires_current_finding_acknowledgement_cwe_841(world):
    before = snapshot()
    for extra in ({}, {"finding_count": 0}, {"finding_count": 1}, {"finding_count": 3}):
        refused = move(world.client, world.asset, world.beta, **extra)
        assert refused.status_code == 409, extra
        assert refused.json()["error"]["message"] == UNCONFIRMED
    assert snapshot()[0:3] == before[0:3]
    for value in (True, -1, "2"):
        assert move(world.client, world.asset, world.beta, finding_count=value).status_code == 400
    moved = move(world.client, world.asset, world.beta, finding_count=2)
    assert moved.status_code == 200
    # The success response is the unchanged asset shape (SPEC-0005).
    assert set(moved.json()) == set(client_for(world.mover).get(f"{ASSETS}{world.bare.pk}/").json())
    # Without findings the count is ignored, whatever it says.
    assert move(world.client, world.bare, world.beta).status_code == 200
    assert move(world.client, world.bare, world.alpha, finding_count=7).status_code == 200


# SEC-19 — the participant is registered and fails closed (T-19, CWE-693)


def test_findings_transfer_participant_is_registered_and_fails_closed_cwe_693(world, monkeypatch):
    assert participant in transfer.participants()
    assert checks.run_checks(tags=["trilha_integrity"]) == []
    before = snapshot()
    with mock.patch.object(participant, "record", side_effect=RuntimeError("boom")):
        failed = move(world.client, world.asset, world.beta, finding_count=2)
    assert (
        failed.status_code == 500 and failed.json()["error"]["message"] == "Internal server error."
    )
    assert snapshot() == before  # asset, findings, entries and audit all rolled back
    monkeypatch.setattr(transfer, "_participants", [])
    assert [m.id for m in checks.run_checks(tags=["trilha_integrity"])] == ["findings.E001"]
    with pytest.raises(SystemCheckError):
        call_command("check")
    with pytest.raises(CommandError, match="Not ready"):
        call_command("check_ready")


# SEC-20 — after a transfer, findings follow the asset's team (T-20, CWE-863)


def test_transferred_findings_follow_asset_visibility_cwe_863(world):
    source_reader = client_for(world.reporter)
    destination_reader = make_user("beta-reader")
    grant(destination_reader, world.beta, VIEW)
    destination = client_for(destination_reader)
    first = world.findings[0]
    history = list(first.log_entries.order_by("sequence").values())
    assert destination.get(detail(first)).status_code == 404
    assert move(world.client, world.asset, world.beta, finding_count=2).status_code == 200
    for path in (detail(first), detail(first, "logbook/")):
        assert source_reader.get(path).status_code == 404
        assert destination.get(path).status_code == 200
    assert source_reader.get("/api/v1/findings/").json()["count"] == 0
    assert destination.get("/api/v1/findings/").json()["count"] == 2
    assert destination.get(detail(first)).json()["team"]["code"] == "beta"
    for finding in world.findings:
        entries = list(finding.log_entries.order_by("sequence"))
        moved = [e for e in entries if e.event == "asset_transferred"]
        assert len(moved) == 1 and moved[0].sequence == len(entries) == 2
        assert moved[0].metadata == {"from_team": "alpha", "to_team": "beta"}
        assert moved[0].actor_id == world.mover.pk
        assert Finding.objects.get(pk=finding.pk).log_sequence == 2
    assert list(first.log_entries.filter(sequence=1).values()) == history  # history kept as is
    assert [e["sequence"] for e in logbook(destination, first).json()["results"]] == [1, 2]
    event = AuditEvent.objects.get(action="findings.asset_findings_transferred")
    assert (event.resource_type, event.resource_id) == ("assets.asset", str(world.asset.pk))
    assert event.metadata == {
        "source_team_id": str(world.alpha.pk),
        "destination_team_id": str(world.beta.pk),
        "finding_count": 2,
    }
    asset_event = AuditEvent.objects.get(action="assets.asset_transferred")
    assert set(asset_event.changes) == {"team_id"}  # unchanged SPEC-0005 event
    # A finding PATCH that read the old team now fails closed for the source team.
    edit = source_reader.patch(detail(first), {"version": 1, "title": "Late"}, format="json")
    assert edit.status_code == 404


# BR-18 — retirement with open findings


def test_retirement_with_findings_is_allowed_and_transfer_of_retired_assets_is_refused(world):
    retired = world.client.post(f"{ASSETS}{world.asset.pk}/retire/", {"version": 1}, format="json")
    assert retired.status_code == 200
    assert move(world.client, world.asset, world.beta, finding_count=2).status_code == 409
    assert Finding.objects.filter(asset=world.asset).count() == 2
    assert client_for(world.reporter).get(detail(world.findings[0])).status_code == 200


# Concurrency: count checked under the asset lock; opposite transfers never deadlock


@pytest.mark.django_db(transaction=True)
def test_finding_created_during_transfer_is_counted_under_the_lock():
    with audit_source("command"):
        w = build_world()
    created, release = threading.Event(), threading.Event()

    def create_and_hold():
        with transaction.atomic():
            services.create_finding(
                UserPrincipal(w.reporter.pk), asset_id=w.asset.pk, **{**NEW, "title": "Third"}
            )
            created.set()
            assert release.wait(10)  # holds the asset row lock until released

    creator, outcome = in_thread("creator", create_and_hold)
    assert created.wait(10)
    mover, result = in_thread("mover", lambda: move(w.client, w.asset, w.beta, finding_count=2))
    time.sleep(0.5)
    assert mover.is_alive()  # waiting for the asset lock, not deciding on a stale count
    release.set()
    creator.join(10)
    mover.join(10)
    assert "error" not in outcome
    assert result["value"].status_code == 409
    assert Asset.objects.get(pk=w.asset.pk).team_id == w.alpha.pk
    assert move(w.client, w.asset, w.beta, finding_count=3).status_code == 200


@pytest.mark.django_db(transaction=True)
def test_opposite_transfers_of_assets_with_findings_do_not_deadlock():
    with audit_source("command"):
        w = build_world()
        reporter_beta = make_user("reporter-beta")
        grant(reporter_beta, w.beta, *REPORTER)
        other = assets.create_asset(
            UserPrincipal(w.mover.pk), team_id=w.beta.pk, name="Db", kind="server"
        )
        services.create_finding(UserPrincipal(reporter_beta.pk), asset_id=other.pk, **NEW)
    rounds = 5

    def shuttle(asset, home, away, count):
        statuses = []
        for number in range(rounds):
            target = away if number % 2 == 0 else home
            statuses.append(
                move(client_for(w.mover), asset, target, finding_count=count).status_code
            )
        return statuses

    first, first_result = in_thread("first", lambda: shuttle(w.asset, w.alpha, w.beta, 2))
    second, second_result = in_thread("second", lambda: shuttle(other, w.beta, w.alpha, 1))
    for thread in (first, second):
        thread.join(60)
    # Both lock the two Team rows in UUID order, then their own asset: no deadlock, no 503.
    assert first_result.get("value") == [200] * rounds, first_result
    assert second_result.get("value") == [200] * rounds, second_result
    for finding in Finding.objects.all():
        sequences = list(
            finding.log_entries.order_by("sequence").values_list("sequence", flat=True)
        )
        assert sequences == list(range(1, finding.log_sequence + 1))  # gapless, never duplicated
        assert finding.log_entries.filter(event="asset_transferred").count() == rounds
