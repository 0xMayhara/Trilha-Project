import uuid
from typing import ClassVar

from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models.functions import Lower

from apps.assets.validation import HOSTNAME_PATTERN, MAX_IP_ADDRESSES

ACTIVE_NAME_CONSTRAINT = "asset_active_name_per_team"


class Kind(models.TextChoices):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    CLOUD_RESOURCE = "cloud_resource"
    OTHER = "other"


class Environment(models.TextChoices):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    OTHER = "other"


class Criticality(models.TextChoices):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Status(models.TextChoices):
    ACTIVE = "active"
    RETIRED = "retired"


class IsNFCNormalized(models.Func):
    """PostgreSQL `<text> IS NFC NORMALIZED` (UTF8 databases). Static SQL; no input reaches it."""

    template = "%(expressions)s IS NFC NORMALIZED"
    arity = 1
    output_field = models.BooleanField()


class Asset(models.Model):
    """A team-owned inventory record. Identity is the UUID; every other field is an attribute
    (ADR-0006). Changed only through apps.assets.services."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    team = models.ForeignKey("teams.Team", on_delete=models.PROTECT, related_name="assets")
    name = models.CharField(max_length=150)
    kind = models.CharField(max_length=32, choices=Kind.choices)
    hostname = models.CharField(max_length=253, blank=True, default="")
    ip_addresses = ArrayField(models.GenericIPAddressField(), blank=True, default=list)
    operating_system = models.CharField(max_length=150, blank=True, default="")
    # null means unspecified/unassessed (SPEC-0005); "" is never a valid value, so null is the
    # one empty state, not a second one.
    environment = models.CharField(max_length=16, choices=Environment.choices, null=True)  # noqa: DJ001
    criticality = models.CharField(max_length=16, choices=Criticality.choices, null=True)  # noqa: DJ001
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        default_permissions = ("view", "add", "change")
        permissions = (
            ("retire_asset", "Can retire or restore asset"),
            ("transfer_asset", "Can transfer asset between teams"),
        )
        constraints: ClassVar = [
            # PostgreSQL decides name uniqueness alone, over NFC-stored values (F-19).
            models.UniqueConstraint(
                Lower("name"),
                models.F("team"),
                condition=models.Q(status=Status.ACTIVE),
                name=ACTIVE_NAME_CONSTRAINT,
            ),
            models.CheckConstraint(condition=models.Q(kind__in=Kind.values), name="asset_kind"),
            models.CheckConstraint(
                condition=models.Q(environment__isnull=True)
                | models.Q(environment__in=Environment.values),
                name="asset_environment",
            ),
            models.CheckConstraint(
                condition=models.Q(criticality__isnull=True)
                | models.Q(criticality__in=Criticality.values),
                name="asset_criticality",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=Status.values), name="asset_status"
            ),
            models.CheckConstraint(condition=~models.Q(name=""), name="asset_name_nonempty"),
            models.CheckConstraint(condition=IsNFCNormalized("name"), name="asset_name_nfc"),
            models.CheckConstraint(
                condition=IsNFCNormalized("operating_system"), name="asset_os_nfc"
            ),
            models.CheckConstraint(
                condition=models.Q(hostname="") | models.Q(hostname__regex=HOSTNAME_PATTERN),
                name="asset_hostname",
            ),
            models.CheckConstraint(
                condition=models.Q(ip_addresses__len__lte=MAX_IP_ADDRESSES), name="asset_ip_count"
            ),
            models.CheckConstraint(condition=models.Q(version__gte=1), name="asset_version"),
        ]

    def __str__(self):
        return str(self.pk)
