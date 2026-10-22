import logging

from rest_framework.exceptions import NotAuthenticated
from rest_framework.permissions import BasePermission

from apps.rbac.policy import active_user
from apps.rbac.principals import session_principal
from apps.rbac.selectors import can_access, is_platform_admin

logger = logging.getLogger("apps.rbac")


class ActiveSession(BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated or not active_user(session_principal(request.user)):
            raise NotAuthenticated
        return True


class ViewTeam(ActiveSession):
    def has_object_permission(self, request, view, obj):
        allowed = can_access(session_principal(request.user), "teams.view_team", team_id=obj.pk)
        if not allowed:
            logger.warning(
                "authorization_denied",
                extra={"operation": "view_team", "actor_id": str(request.user.pk)},
            )
        return allowed


class PlatformAdmin(ActiveSession):
    """Admin-only reads: 403 before any lookup for every non-Admin, logged, not audited (SEC-19)."""

    def has_permission(self, request, view):
        super().has_permission(request, view)
        if is_platform_admin(session_principal(request.user)):
            return True
        logger.warning(
            "authorization_denied",
            extra={
                "operation": getattr(view, "operation", "read_directory"),
                "actor_id": str(request.user.pk),
                "outcome": "denied",
            },
        )
        return False
