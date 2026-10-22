from django.urls import path

from apps.rbac import admin_views as views

# Every object is addressed by UUID only; there is no delete route and no bulk route (SEC-14).
urlpatterns = [
    path("users/", views.UserListView.as_view(), name="admin-users"),
    path("users/<uuid:pk>/", views.UserDetailView.as_view(), name="admin-user"),
    path("users/<uuid:pk>/disable/", views.UserDisableView.as_view(), name="admin-user-disable"),
    path("users/<uuid:pk>/enable/", views.UserEnableView.as_view(), name="admin-user-enable"),
    path(
        "users/<uuid:pk>/password-link/",
        views.UserPasswordLinkView.as_view(),
        name="admin-user-password-link",
    ),
    path("users/<uuid:pk>/position/", views.UserPositionView.as_view(), name="admin-user-position"),
    path(
        "users/<uuid:pk>/grant-admin/", views.UserGrantAdminView.as_view(), name="admin-user-grant"
    ),
    path(
        "users/<uuid:pk>/revoke-admin/",
        views.UserRevokeAdminView.as_view(),
        name="admin-user-revoke",
    ),
    path("teams/", views.TeamListView.as_view(), name="admin-teams"),
    path("teams/<uuid:pk>/", views.TeamDetailView.as_view(), name="admin-team"),
    path(
        "teams/<uuid:pk>/deactivate/",
        views.TeamDeactivateView.as_view(),
        name="admin-team-deactivate",
    ),
    path(
        "teams/<uuid:pk>/activation-preview/",
        views.TeamActivationPreviewView.as_view(),
        name="admin-team-activation-preview",
    ),
    path("teams/<uuid:pk>/activate/", views.TeamActivateView.as_view(), name="admin-team-activate"),
    path("teams/<uuid:pk>/members/", views.TeamMembersView.as_view(), name="admin-team-members"),
    path(
        "teams/<uuid:pk>/members/<uuid:user_id>/remove/",
        views.TeamMemberRemoveView.as_view(),
        name="admin-team-member-remove",
    ),
    path(
        "memberships/<uuid:pk>/roles/",
        views.MembershipRolesView.as_view(),
        name="admin-membership-roles",
    ),
    path(
        "memberships/<uuid:pk>/roles/<uuid:role_id>/revoke/",
        views.MembershipRoleRevokeView.as_view(),
        name="admin-membership-role-revoke",
    ),
    path("roles/", views.RoleListView.as_view(), name="admin-roles"),
    path("roles/<uuid:pk>/", views.RoleDetailView.as_view(), name="admin-role"),
    path(
        "roles/<uuid:pk>/grant-permission/",
        views.RoleGrantPermissionView.as_view(),
        name="admin-role-grant",
    ),
    path(
        "roles/<uuid:pk>/revoke-permission/",
        views.RoleRevokePermissionView.as_view(),
        name="admin-role-revoke",
    ),
    path("permissions/", views.PermissionCatalogView.as_view(), name="admin-permissions"),
    path("audit-events/", views.AuditTrailView.as_view(), name="admin-audit-events"),
]
