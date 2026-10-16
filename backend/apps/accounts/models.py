import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Platform user. Fields beyond Django's defaults are defined by SPEC-0003."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
