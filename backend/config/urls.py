from django.urls import path

from apps.core.api.views import LivenessView

# The Django admin is intentionally not mounted (SPEC-0001 SEC-20).
urlpatterns = [
    path("api/v1/health/live/", LivenessView.as_view(), name="health-live"),
]

handler400 = "apps.core.views.bad_request"
handler403 = "apps.core.views.permission_denied"
handler404 = "apps.core.views.page_not_found"
handler500 = "apps.core.views.server_error"
