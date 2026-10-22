"""Thin HTTP adapters of the administration API (SPEC-0010 API Contract).

Reads use `PlatformAdmin`: 403 for every non-Admin before any lookup. Mutations only parse the body,
build the session principal with its step-up proof and call one `@administrative` use case, which
decides authority (audited denials), step-up, guards and locking. Errors map by type to fixed text.
"""

import logging

from django.core.exceptions import ObjectDoesNotExist
from rest_framework import exceptions
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

from apps.core.api.exceptions import Conflict, StepUpRequired
from apps.core.api.parsing import StrictJSONParser, parse_body
from apps.rbac import administration, directory
from apps.rbac import services as rbac
from apps.rbac.admin_serializers import (
    AUDIT_FILTERS,
    NULLABLE_TEXT,
    ROLE_FILTERS,
    TEAM_FILTERS,
    TEXT,
    USER_FILTERS,
    AuditTrailEntrySerializer,
    MemberSerializer,
    RoleAdminSerializer,
    TeamAdminSerializer,
    UserAdminDetailSerializer,
    UserAdminSerializer,
    activation_preview,
    audit_filters,
    password_link,
    position_value,
    revision_value,
    role_filters,
    team_filters,
    user_filters,
    uuid_value,
)
from apps.rbac.exceptions import (
    AdministrationDenied,
    RbacConflict,
    RbacError,
    RbacInvalid,
    RbacNotFound,
    ReauthenticationRequired,
)
from apps.rbac.permissions import ActiveSession, PlatformAdmin
from apps.rbac.throttles import AdminWriteThrottle
from apps.rbac.views import request_principal, validate_query
from apps.teams import services as teams

logger = logging.getLogger("apps.rbac")
NO_STORE = {"Cache-Control": "no-store"}
CONFLICT = "The request conflicts with the current state."


class AdminView(GenericAPIView):
    # Reads: Admin only, before any lookup. Mutations: an enabled session, then the use case
    # decides, so a non-Admin's attempt is denied and audited by the service (SEC-02, SEC-24).
    permission_classes = (PlatformAdmin,)
    parser_classes = (StrictJSONParser,)
    operation = "read_directory"

    def get_permissions(self):
        if self.request.method in SAFE_METHODS:
            return super().get_permissions()
        return [ActiveSession()]

    def get_throttles(self):
        throttles = super().get_throttles()
        if self.request.method not in SAFE_METHODS:
            throttles.append(AdminWriteThrottle())
        return throttles

    def read(self, call):
        try:
            return call(request_principal(self.request))
        except AdministrationDenied:
            raise exceptions.PermissionDenied from None
        except ObjectDoesNotExist:
            raise exceptions.NotFound from None

    def use_case(self, call):
        """Request data reaches only `call`; the use case decides every rule."""
        try:
            return call(request_principal(self.request))
        except AdministrationDenied:
            raise exceptions.PermissionDenied from None
        except ReauthenticationRequired:
            raise StepUpRequired from None
        except RbacNotFound:
            raise exceptions.NotFound from None
        except RbacInvalid as exc:
            raise exceptions.ValidationError({"non_field_errors": [str(exc)]}) from None
        except RbacConflict as exc:
            raise Conflict(str(exc)) from None
        except RbacError:
            raise Conflict(CONFLICT) from None

    def page(self, rows, serializer):
        return self.get_paginated_response(serializer(self.paginate_queryset(rows), many=True).data)

    def body(self, schema, required=()):
        return parse_body(self.request.data, schema, required=required)


# Users


def _user(view, user_id):
    return UserAdminSerializer(
        view.read(lambda principal: directory.user_detail(principal, user_id))
    ).data


class UserListView(AdminView):
    def get(self, request):
        validate_query(request, extra=USER_FILTERS)
        filters = user_filters(request.query_params)
        rows = self.read(lambda principal: directory.user_directory(principal, **filters))
        return self.page(rows, UserAdminSerializer)

    def post(self, request):
        data = self.body(
            {"username": TEXT, "first_name": TEXT, "last_name": TEXT, "email": TEXT},
            required=("username",),
        )
        user, link = self.use_case(
            lambda principal: administration.create_account(principal, **data)
        )
        return Response(
            {"user": _user(self, user.pk), "password_link": password_link(link)},
            status=201,
            headers=NO_STORE,
        )


class UserDetailView(AdminView):
    def get(self, request, pk):
        validate_query(request, paginated=False)
        user = self.read(lambda principal: directory.user_detail(principal, pk))
        return Response(UserAdminDetailSerializer(user).data)

    def patch(self, request, pk):
        changes = self.body({"first_name": TEXT, "last_name": TEXT, "email": TEXT})
        if not changes:
            raise exceptions.ValidationError({"non_field_errors": ["Provide a field to change."]})
        self.use_case(
            lambda principal: administration.update_account(principal, pk, changes=changes)
        )
        return Response(_user(self, pk))


class UserActionView(AdminView):
    """POST {} transitions on one account; each returns the account."""

    action = None

    def post(self, request, pk):
        self.body({})
        action = type(self).action
        self.use_case(lambda principal: action(principal, pk))
        return Response(_user(self, pk))


class UserDisableView(UserActionView):
    action = administration.disable_account


class UserGrantAdminView(UserActionView):
    action = administration.grant_admin


class UserRevokeAdminView(UserActionView):
    action = administration.revoke_admin


class UserEnableView(AdminView):
    def post(self, request, pk):
        self.body({})
        _, link = self.use_case(lambda principal: administration.enable_account(principal, pk))
        body = {"user": _user(self, pk), "password_link": password_link(link)}
        return Response(body, headers=NO_STORE)


class UserPasswordLinkView(AdminView):
    def post(self, request, pk):
        self.body({})
        link = self.use_case(lambda principal: administration.issue_password_link(principal, pk))
        return Response(password_link(link), headers=NO_STORE)


class UserPositionView(AdminView):
    def post(self, request, pk):
        position = position_value(self.body({"position": NULLABLE_TEXT}, required=("position",)))
        self.use_case(lambda principal: administration.set_position(principal, pk, position))
        return Response(_user(self, pk))


# Teams and memberships


def _team(view, team_id):
    return TeamAdminSerializer(
        view.read(lambda principal: directory.team_detail(principal, team_id))
    ).data


def _member(view, membership_id):
    return MemberSerializer(
        view.read(lambda principal: directory.membership_detail(principal, membership_id))
    ).data


class TeamListView(AdminView):
    def get(self, request):
        validate_query(request, extra=TEAM_FILTERS)
        filters = team_filters(request.query_params)
        rows = self.read(lambda principal: directory.team_directory(principal, **filters))
        return self.page(rows, TeamAdminSerializer)

    def post(self, request):
        data = self.body({"code": TEXT, "name": TEXT}, required=("code", "name"))
        team = self.use_case(lambda principal: teams.create_team(principal, **data))
        return Response(_team(self, team.pk), status=201)


class TeamDetailView(AdminView):
    def get(self, request, pk):
        validate_query(request, paginated=False)
        return Response(_team(self, pk))

    def patch(self, request, pk):
        data = self.body({"name": TEXT}, required=("name",))
        self.use_case(lambda principal: teams.update_team(principal, pk, name=data["name"]))
        return Response(_team(self, pk))


class TeamDeactivateView(AdminView):
    def post(self, request, pk):
        self.body({})
        self.use_case(lambda principal: teams.deactivate_team(principal, pk))
        return Response(_team(self, pk))


class TeamActivationPreviewView(AdminView):
    """GET-safe: short locks, no writes and no step-up (BR-10)."""

    def get(self, request, pk):
        validate_query(request, paginated=False)
        team = self.read(lambda principal: directory.team_detail(principal, pk))
        preview = self.use_case(lambda principal: teams.preview_team_activation(principal, pk))
        return Response(activation_preview(preview, team))


class TeamActivateView(AdminView):
    def post(self, request, pk):
        data = self.body(
            {"revision": TEXT, "confirmation_code": TEXT},
            required=("revision", "confirmation_code"),
        )
        revision = revision_value(data)
        self.use_case(
            lambda principal: teams.activate_team(
                principal, pk, revision, data["confirmation_code"]
            )
        )
        return Response(_team(self, pk))


class TeamMembersView(AdminView):
    def get(self, request, pk):
        validate_query(request)
        rows = self.read(lambda principal: directory.team_members(principal, pk))
        return self.page(rows, MemberSerializer)

    def post(self, request, pk):
        user_id = uuid_value(self.body({"user_id": TEXT}, required=("user_id",)), "user_id")
        membership = self.use_case(lambda principal: teams.add_member(principal, pk, user_id))
        return Response(_member(self, membership.pk), status=201)


class TeamMemberRemoveView(AdminView):
    def post(self, request, pk, user_id):
        self.body({})
        self.use_case(lambda principal: teams.remove_member(principal, pk, user_id))
        return Response(status=204)


class MembershipRolesView(AdminView):
    def post(self, request, pk):
        role_id = uuid_value(self.body({"role_id": TEXT}, required=("role_id",)), "role_id")
        self.use_case(lambda principal: rbac.assign_role(principal, pk, role_id))
        return Response(_member(self, pk), status=201)


class MembershipRoleRevokeView(AdminView):
    def post(self, request, pk, role_id):
        self.body({})
        self.use_case(lambda principal: rbac.revoke_role(principal, pk, role_id))
        return Response(_member(self, pk))


# Roles and the permission catalog


def _role(view, role_id):
    return RoleAdminSerializer(
        view.read(lambda principal: directory.role_detail(principal, role_id))
    ).data


class RoleListView(AdminView):
    def get(self, request):
        validate_query(request, extra=ROLE_FILTERS)
        filters = role_filters(request.query_params)
        rows = self.read(lambda principal: directory.role_directory(principal, **filters))
        return self.page(rows, RoleAdminSerializer)

    def post(self, request):
        data = self.body({"code": TEXT, "name": TEXT}, required=("code", "name"))
        role = self.use_case(lambda principal: rbac.create_role(principal, **data))
        return Response(_role(self, role.pk), status=201)


class RoleDetailView(AdminView):
    def get(self, request, pk):
        validate_query(request, paginated=False)
        return Response(_role(self, pk))

    def patch(self, request, pk):
        data = self.body({"name": TEXT}, required=("name",))
        self.use_case(lambda principal: rbac.update_role(principal, pk, name=data["name"]))
        return Response(_role(self, pk))


class RolePermissionView(AdminView):
    service = None

    def post(self, request, pk):
        code = self.body({"permission": TEXT}, required=("permission",))["permission"]
        service = type(self).service
        self.use_case(lambda principal: service(principal, pk, code))
        return Response(_role(self, pk))


class RoleGrantPermissionView(RolePermissionView):
    service = rbac.grant_permission


class RoleRevokePermissionView(RolePermissionView):
    service = rbac.revoke_permission


class PermissionCatalogView(AdminView):
    def get(self, request):
        validate_query(request)
        rows = self.read(directory.permission_catalog)
        page = self.paginate_queryset(rows)
        return self.get_paginated_response(page)


# Audit trail


class AuditTrailView(AdminView):
    operation = "search_audit"

    def get(self, request):
        validate_query(request, extra=AUDIT_FILTERS)
        filters = audit_filters(request.query_params)
        rows = self.read(lambda principal: directory.audit_search(principal, **filters))
        # Filter keys only: values may hold identifiers an investigation should not spread (§16).
        logger.info(
            "audit_trail_read",
            extra={
                "actor_id": str(request.user.pk),
                "filters": sorted(key for key in AUDIT_FILTERS if key in request.query_params),
            },
        )
        return self.page(rows, AuditTrailEntrySerializer)
