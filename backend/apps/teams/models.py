import uuid
from typing import ClassVar

from django.conf import settings
from django.db import models

from apps.teams.validation import CODE_PATTERN, validate_code, validate_name


class Team(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=63, unique=True, validators=[validate_code])
    name = models.CharField(max_length=150, validators=[validate_name])
    is_active = models.BooleanField(default=False)

    class Meta:
        default_permissions = ("view",)
        constraints: ClassVar = [
            models.CheckConstraint(condition=models.Q(code__regex=CODE_PATTERN), name="team_code"),
            models.CheckConstraint(condition=~models.Q(name=""), name="team_name_nonempty"),
        ]

    def __str__(self):
        return self.code


class Membership(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    team = models.ForeignKey(Team, on_delete=models.PROTECT, related_name="memberships")

    class Meta:
        default_permissions = ()
        constraints: ClassVar = [
            models.UniqueConstraint(fields=["user", "team"], name="membership_user_team")
        ]

    def __str__(self):
        return str(self.pk)
