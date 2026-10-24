"""Thin HTTP adapters over apps.findings services and selectors (SPEC-0007 API Contract)."""

import logging

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import exceptions
from rest_framework.generics import ListAPIView
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.api.exceptions import Conflict
from apps.core.api.parsing import StrictJSONParser, parse_body
from apps.findings import services
from apps.findings.exceptions import (
    AssetRetired,
    AssetUnavailable,
    FindingForbidden,
    FindingNotFound,
    StaleFinding,
)
from apps.findings.selectors import logbook_page, search_findings, viewable_finding
from apps.findings.serializers import (
    CREATE_FIELDS,
    LIST_FILTERS,
    LOGBOOK_QUERY,
    UPDATE_FIELDS,
    EntrySerializer,
    FindingSerializer,
    FindingSummarySerializer,
    parse_list_query,
    parse_logbook_query,
)
from apps.findings.throttles import FindingWriteThrottle
from apps.rbac.permissions import ActiveSession
from apps.rbac.principals import session_principal
from apps.rbac.views import validate_query

logger = logging.getLogger("apps.findings")

# User-facing text is fixed here, per error type: exception content never reaches a response.
ASSET_UNAVAILABLE = "Select an asset where you can report findings."
STALE = "The finding changed. Reload and try again."
ASSET_RETIRED = "The asset is retired; new findings cannot be reported on it."


class FindingAPIView(APIView):
    permission_classes = (ActiveSession,)
    parser_classes = (StrictJSONParser,)  # repeated JSON keys are refused, never last-one-wins

    def get_throttles(self):
        throttles = super().get_throttles()
        if self.request.method not in SAFE_METHODS:
            throttles.append(FindingWriteThrottle())
        return throttles

    @property
    def principal(self):
        return session_principal(self.request.user)

    def run(self, operation, call):
        """Calls one use case with the session principal and translates its errors; no rule is
        decided here. Request data reaches only `call`, never this adapter's own arguments."""
        try:
            return call(self.principal)
        except FindingNotFound:
            self._denied(operation)
            raise exceptions.NotFound from None
        except FindingForbidden as exc:
            self._denied(operation, exc.finding_id)
            raise exceptions.PermissionDenied from None
        except AssetUnavailable:
            self._denied(operation, reason="asset_unavailable")  # probing other teams' assets
            raise exceptions.ValidationError({"asset_id": [ASSET_UNAVAILABLE]}) from None
        except StaleFinding:
            raise Conflict(STALE) from None
        except AssetRetired:
            raise Conflict(ASSET_RETIRED) from None
        except DjangoValidationError as exc:
            raise exceptions.ValidationError(exc.message_dict) from None

    def detail(self, finding_id, status=200):
        # Read through the scoped selector: the response shows what the actor may see now.
        finding = self.run("read", lambda principal: viewable_finding(principal, finding_id))
        context = {"principal": self.principal}
        return Response(FindingSerializer(finding, context=context).data, status=status)

    def _denied(self, operation, finding_id=None, reason=None):
        # IDs only, never content. The finding ID comes from the database row of an in-scope 403,
        # never from the URL; submitted asset IDs are never logged (SEC-45).
        extra = {"operation": operation, "actor_id": str(self.request.user.pk), "outcome": "denied"}
        if finding_id is not None:
            extra["finding_id"] = str(finding_id)
        if reason is not None:
            extra["reason"] = reason
        logger.warning("authorization_denied", extra=extra)


class FindingListView(FindingAPIView, ListAPIView):
    serializer_class = FindingSummarySerializer

    def get_queryset(self):
        validate_query(self.request, extra=LIST_FILTERS)
        filters = parse_list_query(self.request.query_params, self.request.user.pk)
        return search_findings(self.principal, **filters)

    def post(self, request):
        data = parse_body(request.data, CREATE_FIELDS, required=())
        finding = self.run("create", lambda principal: services.create_finding(principal, **data))
        return self.detail(finding.pk, status=201)


class FindingDetailView(FindingAPIView):
    def get(self, request, pk):
        validate_query(request, paginated=False)
        return self.detail(pk)

    def patch(self, request, pk):
        data = parse_body(request.data, UPDATE_FIELDS, required=("version",))
        version = data.pop("version")
        finding = self.run(
            "update",
            lambda principal: services.update_finding(principal, pk, version=version, changes=data),
        )
        return self.detail(finding.pk)


class LogbookView(FindingAPIView):
    """Read-only in slice B: comments arrive with slice C. No route updates or deletes an entry."""

    def get(self, request, pk):
        validate_query(request, paginated=False, extra=LOGBOOK_QUERY)
        cursor = parse_logbook_query(request.query_params)
        page = self.run("read_logbook", lambda principal: logbook_page(principal, pk, **cursor))
        return Response({**page, "results": EntrySerializer(page["results"], many=True).data})
