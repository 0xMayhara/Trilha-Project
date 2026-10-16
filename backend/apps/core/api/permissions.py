from rest_framework.permissions import BasePermission


class DenyAll(BasePermission):
    """Default permission: a view that does not declare its permissions is unreachable
    (CLAUDE.md §11, SPEC-0001 SEC-06)."""

    def has_permission(self, request, view) -> bool:
        return False

    def has_object_permission(self, request, view, obj) -> bool:
        return False
