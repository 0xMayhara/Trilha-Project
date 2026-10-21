from rest_framework import serializers

from apps.teams.models import Team


class TeamSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = ("id", "code", "name")
        read_only_fields = fields
