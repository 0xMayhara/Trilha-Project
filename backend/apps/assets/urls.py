from django.urls import path

from apps.assets import views

# Every route takes the asset UUID; nothing is looked up by name, hostname or IP (SEC-28).
urlpatterns = [
    path("", views.AssetListView.as_view(), name="asset-list"),
    path("<uuid:pk>/", views.AssetDetailView.as_view(), name="asset-detail"),
    path("<uuid:pk>/retire/", views.AssetRetireView.as_view(), name="asset-retire"),
    path("<uuid:pk>/restore/", views.AssetRestoreView.as_view(), name="asset-restore"),
    path("<uuid:pk>/transfer/", views.AssetTransferView.as_view(), name="asset-transfer"),
]
