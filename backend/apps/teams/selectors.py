"""Public team queries. Business API callers use the scoped RBAC selectors."""

from apps.teams.models import Membership, Team


def teams():
    return Team.objects.all()


def memberships():
    return Membership.objects.all()
