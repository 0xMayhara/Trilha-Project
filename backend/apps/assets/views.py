"""Thin HTTP adapters over apps.assets services and selectors (SPEC-0005 API Contract)."""

import logging

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import exceptions
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.assets import services
from apps.assets.exceptions import (
    AssetForbidden,
    AssetNotFound,
    InvalidState,
    NameTaken,
    StaleAsset,
    TeamUnavailable,
)
from apps.assets.selectors import os_catalog, search_assets, viewable_asset
from apps.assets.serializers import (
    CREATE_FIELDS,
    LIST_FILTERS,
    TRANSFER_FIELDS,
    TRANSITION_FIELDS,
    UPDATE_FIELDS,
    AssetSerializer,
    parse_list_query,
)
from apps.assets.throttles import AssetWriteThrottle
from apps.core.api.exceptions import Conflict
from apps.core.api.parsing import parse_body
from apps.rbac.permissions import ActiveSession
from apps.rbac.principals import session_principal
from apps.rbac.views import validate_query

logger = logging.getLogger("apps.assets")

# User-facing text is fixed here, per error type: exception content never reaches a response.
TEAM_UNAVAILABLE = "Select a team where you can perform this action."
STALE = "The asset changed. Reload and try again."
NAME_TAKEN = "An active asset with this name already exists in the team."
INVALID_STATE = "The asset's state does not allow this operation."


class AssetAPIView(APIView):
    permission_classes = (ActiveSession,)

    def get_throttles(self):
        throttles = super().get_throttles()
        if self.request.method not in SAFE_METHODS:
            throttles.append(AssetWriteThrottle())
        return throttles

    def run(self, operation, call):
        """Calls one domain use case with the session principal and translates its errors; no rule
        is decided here. Request data reaches only `call`, never this adapter's own arguments."""
        try:
            return call(session_principal(self.request.user))
        except AssetNotFound:
            self._denied(operation)
            raise exceptions.NotFound from None
        except AssetForbidden as exc:
            self._denied(operation, exc.asset_id)
            raise exceptions.PermissionDenied from None
        except TeamUnavailable:
            self._denied(operation, reason="team_unavailable")  # probing other teams' IDs
            raise exceptions.ValidationError({"team_id": [TEAM_UNAVAILABLE]}) from None
        except StaleAsset:
            raise Conflict(STALE) from None
        except NameTaken:
            raise Conflict(NAME_TAKEN) from None
        except InvalidState:
            raise Conflict(INVALID_STATE) from None
        except DjangoValidationError as exc:
            raise exceptions.ValidationError(exc.message_dict) from None

    def _denied(self, operation, asset_id=None, reason=None):
        # IDs only. The asset ID comes from the database row of an in-scope 403, never from the
        # URL, and is absent for hidden or missing assets. Submitted team IDs are never logged.
        extra = {"operation": operation, "actor_id": str(self.request.user.pk), "outcome": "denied"}
        if asset_id is not None:
            extra["asset_id"] = str(asset_id)
        if reason is not None:
            extra["reason"] = reason
        logger.warning("authorization_denied", extra=extra)


class AssetListView(AssetAPIView, ListAPIView):
    serializer_class = AssetSerializer

    def get_queryset(self):
        validate_query(self.request, extra=LIST_FILTERS)
        filters = parse_list_query(self.request.query_params)
        return search_assets(session_principal(self.request.user), **filters)

    def post(self, request):
        data = parse_body(request.data, CREATE_FIELDS, required=("team_id", "name", "kind"))
        asset = self.run("create", lambda principal: services.create_asset(principal, **data))
        return Response(AssetSerializer(asset).data, status=201)


class AssetDetailView(AssetAPIView):
    def get(self, request, pk):
        validate_query(request, paginated=False)
        asset = self.run("read", lambda principal: viewable_asset(principal, pk))
        return Response(AssetSerializer(asset).data)

    def patch(self, request, pk):
        data = parse_body(request.data, UPDATE_FIELDS, required=("version",))
        version = data.pop("version")
        asset = self.run(
            "update",
            lambda principal: services.update_asset(principal, pk, version=version, changes=data),
        )
        return Response(AssetSerializer(asset).data)


class OsCatalogView(AssetAPIView, GenericAPIView):
    """Constant, tenant-free reference data for any enabled session (SPEC-0011 SEC-03)."""

    def get(self, request):
        validate_query(request)
        return self.get_paginated_response(self.paginate_queryset(os_catalog()))


class AssetTransitionView(AssetAPIView):
    operation = None
    service = None

    def post(self, request, pk):
        data = parse_body(request.data, TRANSITION_FIELDS, required=("version",))
        service = type(self).service
        asset = self.run(
            self.operation, lambda principal: service(principal, pk, version=data["version"])
        )
        return Response(AssetSerializer(asset).data)


class AssetRetireView(AssetTransitionView):
    operation = "retire"
    service = services.retire_asset


class AssetRestoreView(AssetTransitionView):
    operation = "restore"
    service = services.restore_asset


class AssetTransferView(AssetAPIView):
    def post(self, request, pk):
        data = parse_body(request.data, TRANSFER_FIELDS, required=("version", "team_id"))
        asset = self.run(
            "transfer",
            lambda principal: services.transfer_asset(
                principal, pk, version=data["version"], team_id=data["team_id"]
            ),
        )
        return Response(AssetSerializer(asset).data)
