from rest_framework import serializers

from apps.rbac.catalog import PERMISSION_CODES
from apps.rbac.models import Role
from apps.teams.serializers import TeamSummarySerializer


class RoleSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ("id", "code", "name")
        read_only_fields = fields


class AccessEntrySerializer(serializers.Serializer):
    membership_id = serializers.UUIDField(source="id", read_only=True)
    team = TeamSummarySerializer(read_only=True)
    roles = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    def get_roles(self, membership):
        return RoleSummarySerializer(
            [item.role for item in membership.display_assignments], many=True
        ).data

    def get_permissions(self, membership):
        return sorted(
            {
                PERMISSION_CODES[permission.natural_key()]
                for item in membership.display_assignments
                for permission in item.role.display_permissions
            }
        )
