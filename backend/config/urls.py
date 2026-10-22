from django.urls import include, path

from apps.core.api.views import LivenessView
from apps.rbac.views import OwnAccessView
from apps.teams.views import TeamDetailView, TeamListView

# The Django admin is intentionally not mounted (SPEC-0001 SEC-20).
urlpatterns = [
    path("api/v1/health/live/", LivenessView.as_view(), name="health-live"),
    path("api/v1/auth/", include("apps.accounts.urls")),
    path("api/v1/rbac/me/", OwnAccessView.as_view(), name="rbac-me"),
    path("api/v1/teams/", TeamListView.as_view(), name="team-list"),
    path("api/v1/teams/<uuid:pk>/", TeamDetailView.as_view(), name="team-detail"),
    path("api/v1/assets/", include("apps.assets.urls")),
]

handler400 = "apps.core.views.bad_request"
handler403 = "apps.core.views.permission_denied"
handler404 = "apps.core.views.page_not_found"
handler500 = "apps.core.views.server_error"
