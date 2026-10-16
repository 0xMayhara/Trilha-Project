"""Value objects passed to record_event(). Events reference actors and resources by value, never
by foreign key, so deleting a user or a resource leaves its events untouched (SPEC-0002 SEC-15)."""

import uuid
from dataclasses import dataclass
from typing import Any

from django.db import models

from apps.audit.exceptions import AuditValidationError
from apps.audit.models import ActorType


def _is_unsaved(instance: Any) -> bool:
    # UUID primary keys get their default before the first save, so pk alone does not tell.
    state = getattr(instance, "_state", None)
    return instance.pk is None or (state is not None and state.adding)


@dataclass(frozen=True, slots=True)
class Actor:
    type: ActorType
    id: uuid.UUID | None = None
    label: str = ""

    @classmethod
    def user(cls, user: Any) -> "Actor":
        """A saved, authenticated user. The username is a snapshot: renames never rewrite it."""
        if user is None or not user.is_authenticated or _is_unsaved(user):
            raise AuditValidationError("A user actor requires a saved, authenticated user.")
        return cls(type=ActorType.USER, id=user.pk, label=user.get_username())

    @classmethod
    def system(cls, name: str) -> "Actor":
        return cls(type=ActorType.SYSTEM, label=name)

    @classmethod
    def provider(cls, key: str) -> "Actor":
        return cls(type=ActorType.PROVIDER, label=key)

    @classmethod
    def anonymous(cls) -> "Actor":
        return cls(type=ActorType.ANONYMOUS)

    @classmethod
    def for_request_user(cls, user: Any) -> "Actor":
        if user is not None and user.is_authenticated:
            return cls.user(user)
        return cls.anonymous()


@dataclass(frozen=True, slots=True)
class Resource:
    type: str
    id: str = ""

    @classmethod
    def of(cls, instance: models.Model) -> "Resource":
        if _is_unsaved(instance):
            raise AuditValidationError("An audited resource must be saved first.")
        return cls(type=instance._meta.label_lower, id=str(instance.pk))
