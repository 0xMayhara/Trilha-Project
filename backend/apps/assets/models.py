import uuid
from typing import ClassVar

from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models.functions import Lower

from apps.assets.validation import (
    HOSTNAME_PATTERN,
    MAX_IP_ADDRESSES,
    OS_VERSION_MAX_LENGTH,
    OS_VERSION_PATTERN,
)

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


class OsFamily(models.TextChoices):
    LINUX = "linux", "Linux"
    WINDOWS = "windows", "Microsoft Windows"
    APPLE = "apple", "Apple"
    OTHER = "other", "Other"


class OsProduct(models.TextChoices):
    """The operating-system catalog (SPEC-0011), in display order. Append-only: a code is never
    renamed, reused or removed (BR-03); a new code also changes the `asset_os_product` check."""

    CLOUDLINUX = "cloudlinux", "CloudLinux"
    RHEL = "rhel", "Red Hat Enterprise Linux"
    UBUNTU_SERVER = "ubuntu_server", "Ubuntu Server"
    UBUNTU_DESKTOP = "ubuntu_desktop", "Ubuntu Desktop"
    DEBIAN = "debian", "Debian"
    FEDORA = "fedora", "Fedora"
    ROCKY_LINUX = "rocky_linux", "Rocky Linux"
    ALMALINUX = "almalinux", "AlmaLinux"
    CENTOS = "centos", "CentOS"
    ORACLE_LINUX = "oracle_linux", "Oracle Linux"
    SLES = "sles", "SUSE Linux Enterprise Server"
    OTHER_LINUX = "other_linux", "Other Linux"
    WINDOWS_10 = "windows_10", "Windows 10"
    WINDOWS_11 = "windows_11", "Windows 11"
    WINDOWS_SERVER_2008_R2 = "windows_server_2008_r2", "Windows Server 2008 R2"
    WINDOWS_SERVER_2012 = "windows_server_2012", "Windows Server 2012"
    WINDOWS_SERVER_2012_R2 = "windows_server_2012_r2", "Windows Server 2012 R2"
    WINDOWS_SERVER_2016 = "windows_server_2016", "Windows Server 2016"
    WINDOWS_SERVER_2019 = "windows_server_2019", "Windows Server 2019"
    WINDOWS_SERVER_2022 = "windows_server_2022", "Windows Server 2022"
    WINDOWS_SERVER_2025 = "windows_server_2025", "Windows Server 2025"
    OTHER_WINDOWS = "other_windows", "Other Windows"
    MACOS = "macos", "macOS"
    OTHER = "other", "Other / Unknown"


# Each product listed under exactly one family; the family is derived, never stored.
OS_FAMILIES = {
    OsFamily.LINUX: (
        OsProduct.CLOUDLINUX,
        OsProduct.RHEL,
        OsProduct.UBUNTU_SERVER,
        OsProduct.UBUNTU_DESKTOP,
        OsProduct.DEBIAN,
        OsProduct.FEDORA,
        OsProduct.ROCKY_LINUX,
        OsProduct.ALMALINUX,
        OsProduct.CENTOS,
        OsProduct.ORACLE_LINUX,
        OsProduct.SLES,
        OsProduct.OTHER_LINUX,
    ),
    OsFamily.WINDOWS: (
        OsProduct.WINDOWS_10,
        OsProduct.WINDOWS_11,
        OsProduct.WINDOWS_SERVER_2008_R2,
        OsProduct.WINDOWS_SERVER_2012,
        OsProduct.WINDOWS_SERVER_2012_R2,
        OsProduct.WINDOWS_SERVER_2016,
        OsProduct.WINDOWS_SERVER_2019,
        OsProduct.WINDOWS_SERVER_2022,
        OsProduct.WINDOWS_SERVER_2025,
        OsProduct.OTHER_WINDOWS,
    ),
    OsFamily.APPLE: (OsProduct.MACOS,),
    OsFamily.OTHER: (OsProduct.OTHER,),
}
OS_FAMILY = {product: family for family, products in OS_FAMILIES.items() for product in products}


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
    # Legacy free text, read-only since SPEC-0011 (D-1, D-3): kept as recorded, never written.
    operating_system = models.CharField(max_length=150, blank=True, default="")
    # null means unspecified, or legacy when operating_system is set (SPEC-0011).
    os_product = models.CharField(max_length=32, choices=OsProduct.choices, null=True)  # noqa: DJ001
    # db_default lets the previous release, which omits this column, still insert (SEC-13).
    os_version = models.CharField(
        max_length=OS_VERSION_MAX_LENGTH, blank=True, default="", db_default=""
    )
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
                condition=models.Q(os_product__isnull=True)
                | models.Q(os_product__in=OsProduct.values),
                name="asset_os_product",
            ),
            models.CheckConstraint(
                condition=models.Q(os_version="")
                | models.Q(os_product__isnull=False, os_version__regex=OS_VERSION_PATTERN),
                name="asset_os_version",
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
