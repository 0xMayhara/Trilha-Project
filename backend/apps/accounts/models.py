import uuid

from django.contrib.auth.models import AbstractUser
from django.contrib.auth.validators import ASCIIUsernameValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    """Platform user (SPEC-0003). Accounts change only through apps.accounts.services."""

    # ASCII only, so no look-alike Unicode usernames (SPEC-0003 SEC-17, CWE-1007). The inherited
    # field keeps AbstractUser's validator, so it is redeclared here with the same options.
    username_validator = ASCIIUsernameValidator()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(
        _("username"),
        max_length=150,
        unique=True,
        help_text=_("Required. 150 characters or fewer. ASCII letters, digits and @/./+/-/_ only."),
        validators=[username_validator],
        error_messages={"unique": _("A user with that username already exists.")},
    )
