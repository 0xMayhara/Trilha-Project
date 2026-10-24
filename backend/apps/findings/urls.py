from django.urls import path

from apps.findings import views

# Every route takes the finding UUID; nothing is addressed by title, CVE, hostname or IP.
urlpatterns = [
    path("", views.FindingListView.as_view(), name="finding-list"),
    path("<uuid:pk>/", views.FindingDetailView.as_view(), name="finding-detail"),
    path("<uuid:pk>/logbook/", views.LogbookView.as_view(), name="finding-logbook"),
]
