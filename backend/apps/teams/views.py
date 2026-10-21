from django.shortcuts import get_object_or_404
from rest_framework.generics import ListAPIView, RetrieveAPIView

from apps.rbac.permissions import ActiveSession, ViewTeam
from apps.rbac.principals import session_principal
from apps.rbac.selectors import authorized_teams, scoped_teams
from apps.rbac.views import validate_query
from apps.teams.serializers import TeamSummarySerializer


class TeamListView(ListAPIView):
    permission_classes = (ActiveSession,)
    serializer_class = TeamSummarySerializer

    def get_queryset(self):
        validate_query(self.request)
        return authorized_teams(session_principal(self.request.user)).order_by("code", "pk")


class TeamDetailView(RetrieveAPIView):
    permission_classes = (ViewTeam,)
    serializer_class = TeamSummarySerializer

    def get_object(self):
        validate_query(self.request, paginated=False)
        team = get_object_or_404(
            scoped_teams(session_principal(self.request.user)), pk=self.kwargs["pk"]
        )
        self.check_object_permissions(self.request, team)
        return team
