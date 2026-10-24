"""The findings participant of asset transfers (SPEC-0007 BR-15-BR-17).

Findings follow their asset. Moving an asset that has findings also requires `view_finding` in the
source and the destination team (otherwise 403, so a transfer never exposes findings to a team the
actor could not show them to) and an explicit `finding_count` equal to the current count (409
otherwise, so an old client that never showed the findings cannot move them blindly). Each moved
finding gets an `asset_transferred` logbook entry and the move one audit event. Assets without
findings transfer exactly as before."""

from django.db.models import F

from apps.assets.exceptions import AssetForbidden, TransferUnconfirmed
from apps.audit.services import record_event
from apps.audit.types import Resource
from apps.findings.models import Finding, FindingLogEntry, LogKind
from apps.rbac.policy import audit_actor
from apps.rbac.selectors import can_access
from apps.teams.selectors import teams

VIEW = "findings.view_finding"


def _findings(asset):
    return Finding.objects.filter(asset_id=asset.pk)


def authorize(principal, asset, source, destination, finding_count):
    # The asset row is already locked FOR UPDATE; its findings are locked next, in ID order (BR-50),
    # so no finding can be added to, or edited on, the asset until the transfer ends.
    count = len(_findings(asset).select_for_update().order_by("pk").values_list("pk", flat=True))
    if not count:
        return
    for team_id in (source, destination):
        if not can_access(principal, VIEW, team_id=team_id):
            raise AssetForbidden(asset.pk)
    if finding_count != count:
        raise TransferUnconfirmed


def record(principal, asset, source, destination):
    findings = _findings(asset)
    if not findings.exists():
        return
    codes = dict(teams().filter(pk__in=(source, destination)).values_list("pk", "code"))
    metadata = {"from_team": codes[source], "to_team": codes[destination]}
    # The finding rows stay locked from authorize(): each next sequence is gapless (BR-24).
    findings.update(log_sequence=F("log_sequence") + 1)
    rows = list(findings.order_by("pk").values_list("pk", "log_sequence"))
    FindingLogEntry.objects.bulk_create(
        FindingLogEntry(
            finding_id=finding_id,
            sequence=sequence,
            kind=LogKind.SYSTEM,
            event="asset_transferred",
            actor_id=principal.user_id,
            metadata=metadata,
        )
        for finding_id, sequence in rows
    )
    record_event(
        actor=audit_actor(principal),
        action="findings.asset_findings_transferred",
        resource=Resource.of(asset),
        metadata={
            "source_team_id": str(source),
            "destination_team_id": str(destination),
            "finding_count": len(rows),
        },
    )
