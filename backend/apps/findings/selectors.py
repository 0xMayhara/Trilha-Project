"""Scoped finding reads (SPEC-0007 SEC-02). Every call builds fresh SQL from the RBAC selectors
against the asset's current team (BR-01); nothing is cached (BR-29)."""

from apps.findings.exceptions import FindingForbidden, FindingNotFound
from apps.findings.models import Finding, FindingLogEntry
from apps.rbac.catalog import catalog_action
from apps.rbac.selectors import authorized_teams, can_access, is_platform_admin, scoped_teams

VIEW, CHANGE = "findings.view_finding", "findings.change_finding"
_RELATED = ("asset__team", "assignee", "reported_by")


def scoped_findings(principal):
    """Findings on assets of the principal's eligible teams: the scope that separates 404 from 403
    and the only base for mutations."""
    return Finding.objects.filter(asset__team__in=scoped_teams(principal))


def visible_findings(principal):
    """Findings the principal may view, through the membership of the asset's current team that
    holds the permission. A current Admin reads every finding (oversight): reads only."""
    if is_platform_admin(principal):
        return Finding.objects.all()
    return Finding.objects.filter(asset__team__in=authorized_teams(principal, VIEW))


def search_findings(
    principal,
    *,
    status=None,
    severity=None,
    category=None,
    team_id=None,
    asset_id=None,
    assignee_id=None,
    unassigned=False,
    q=None,
):
    """Filters run in SQL after scoping, so rows and counts never include hidden findings."""
    findings = visible_findings(principal)
    for field, value in (
        ("status", status),
        ("severity", severity),
        ("category", category),
        ("asset__team_id", team_id),
        ("asset_id", asset_id),
        ("assignee_id", assignee_id),
    ):
        if value is not None:
            findings = findings.filter(**{field: value})
    if unassigned:
        findings = findings.filter(assignee__isnull=True)
    if q is not None:
        findings = findings.filter(title__icontains=q)
    return findings.select_related(*_RELATED).order_by("-created_at", "id")


def viewable_finding(principal, finding_id):
    admin = is_platform_admin(principal)
    rows = Finding.objects.select_related(*_RELATED)
    if not admin:
        rows = rows.filter(asset__team__in=scoped_teams(principal))
    try:
        finding = rows.get(pk=finding_id)
    except Finding.DoesNotExist:
        raise FindingNotFound from None
    if not admin and not can_access(principal, VIEW, team_id=finding.asset.team_id):
        raise FindingForbidden(finding.pk)
    return finding


def capabilities(principal, finding):
    """Advisory UI hints computed with the services' checks; every mutation re-authorizes."""
    team_id = finding.asset.team_id
    return {
        "edit": all(
            can_access(principal, code, team_id=team_id, action=catalog_action(code))
            for code in (VIEW, CHANGE)
        )
    }


def logbook_page(principal, finding_id, *, after=None, before=None, limit=50):
    """Entries in ascending sequence: the latest `limit`, those before `before`, or those after
    `after`. Only entries up to the finding's recorded last sequence are returned, so a page never
    runs ahead of `last_sequence`. Sequences are gapless from 1 (BR-24)."""
    finding = viewable_finding(principal, finding_id)
    last = finding.log_sequence
    entries = FindingLogEntry.objects.filter(finding=finding, sequence__lte=last).select_related(
        "actor"
    )
    if after is not None:
        rows = list(entries.filter(sequence__gt=after).order_by("sequence")[:limit])
    else:
        if before is not None:
            entries = entries.filter(sequence__lt=before)
        rows = list(entries.order_by("-sequence")[:limit])[::-1]
    if rows:
        start = rows[0].sequence
    else:
        start = min(after, last) + 1 if after is not None else 1
    return {"results": rows, "has_more_before": start > 1, "last_sequence": last}
