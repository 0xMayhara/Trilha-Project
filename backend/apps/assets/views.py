"""Thin HTTP adapters over apps.assets services and selectors (SPEC-0005 API Contract)."""

import logging

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import exceptions
from rest_framework.generics import ListAPIView
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.assets import services
from apps.assets.exceptions import AssetConflict, AssetForbidden, AssetNotFound, TeamUnavailable
from apps.assets.selectors import search_assets, viewable_asset
from apps.assets.serializers import (
    CREATE_FIELDS,
    LIST_FILTERS,
    TRANSFER_FIELDS,
    TRANSITION_FIELDS,
    UPDATE_FIELDS,
    AssetSerializer,
    parse_body,
    parse_list_query,
)
from apps.assets.throttles import AssetWriteThrottle
from apps.core.api.exceptions import Conflict
from apps.rbac.permissions import ActiveSession
from apps.rbac.principals import session_principal
from apps.rbac.views import validate_query

logger = logging.getLogger("apps.assets")


class AssetAPIView(APIView):
    permission_classes = (ActiveSession,)

    def get_throttles(self):
        throttles = super().get_throttles()
        if self.request.method not in SAFE_METHODS:
            throttles.append(AssetWriteThrottle())
        return throttles

    def run(self, operation, function, *args, asset_id=None, **kwargs):
        """Calls one domain use case and translates its errors; no rule is decided here."""
        try:
            return function(session_principal(self.request.user), *args, **kwargs)
        except AssetNotFound:
            self._denied(operation)
            raise exceptions.NotFound from None
        except AssetForbidden:
            self._denied(operation, asset_id)
            raise exceptions.PermissionDenied from None
        except TeamUnavailable as exc:
            raise exceptions.ValidationError({"team_id": [str(exc)]}) from None
        except AssetConflict as exc:
            raise Conflict(str(exc)) from None
        except DjangoValidationError as exc:
            raise exceptions.ValidationError(exc.message_dict) from None

    def _denied(self, operation, asset_id=None):
        # IDs only; the asset ID only for in-scope 403s, never for hidden or missing assets.
        extra = {"operation": operation, "actor_id": str(self.request.user.pk), "outcome": "denied"}
        if asset_id is not None:
            extra["asset_id"] = str(asset_id)
        logger.warning("authorization_denied", extra=extra)


class AssetListView(AssetAPIView, ListAPIView):
    serializer_class = AssetSerializer

    def get_queryset(self):
        validate_query(self.request, extra=LIST_FILTERS)
        filters = parse_list_query(self.request.query_params)
        return search_assets(session_principal(self.request.user), **filters)

    def post(self, request):
        data = parse_body(request.data, CREATE_FIELDS, required=("team_id", "name", "kind"))
        asset = self.run("create", services.create_asset, **data)
        return Response(AssetSerializer(asset).data, status=201)


class AssetDetailView(AssetAPIView):
    def get(self, request, pk):
        validate_query(request, paginated=False)
        asset = self.run("read", viewable_asset, pk, asset_id=pk)
        return Response(AssetSerializer(asset).data)

    def patch(self, request, pk):
        data = parse_body(request.data, UPDATE_FIELDS, required=("version",))
        version = data.pop("version")
        asset = self.run(
            "update", services.update_asset, pk, asset_id=pk, version=version, changes=data
        )
        return Response(AssetSerializer(asset).data)


class AssetTransitionView(AssetAPIView):
    operation = None
    service = None

    def post(self, request, pk):
        data = parse_body(request.data, TRANSITION_FIELDS, required=("version",))
        asset = self.run(
            self.operation, type(self).service, pk, asset_id=pk, version=data["version"]
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
            services.transfer_asset,
            pk,
            asset_id=pk,
            version=data["version"],
            team_id=data["team_id"],
        )
        return Response(AssetSerializer(asset).data)
