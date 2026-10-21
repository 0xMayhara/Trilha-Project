import uuid
from typing import ClassVar

from django.contrib.auth.models import Permission
from django.db import models

from apps.teams.validation import CODE_PATTERN, validate_code, validate_name


class Role(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=63, unique=True, validators=[validate_code])
    name = models.CharField(max_length=150, validators=[validate_name])
    permissions = models.ManyToManyField(Permission, blank=True)

    class Meta:
        default_permissions = ()
        constraints: ClassVar = [
            models.CheckConstraint(condition=models.Q(code__regex=CODE_PATTERN), name="role_code"),
            models.CheckConstraint(condition=~models.Q(name=""), name="role_name_nonempty"),
        ]

    def __str__(self):
        return self.code


class RoleAssignment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    membership = models.ForeignKey(
        "teams.Membership", on_delete=models.CASCADE, related_name="role_assignments"
    )
    role = models.ForeignKey(Role, on_delete=models.PROTECT)

    class Meta:
        default_permissions = ()
        constraints: ClassVar = [
            models.UniqueConstraint(
                fields=["membership", "role"], name="assignment_membership_role"
            )
        ]

    def __str__(self):
        return str(self.pk)
