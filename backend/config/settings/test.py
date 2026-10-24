"""Test settings: production-like (DEBUG off), local test database defaults."""

import base64
import os
import secrets

from django.core.management.utils import get_random_secret_key

os.environ.setdefault("DJANGO_SECRET_KEY", get_random_secret_key())
os.environ.setdefault(
    "AUDIT_DIGEST_KEYS", "test:" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
)
os.environ.setdefault("AUDIT_DIGEST_ACTIVE_KEY_ID", "test")
os.environ.setdefault("POSTGRES_DB", "trilha")
os.environ.setdefault("POSTGRES_USER", "trilha")
os.environ.setdefault("POSTGRES_PASSWORD", "trilha-test")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PASSWORD", "unused-in-tests")
# Tests connect as the superuser of a throwaway server; role tests enable the check explicitly.
os.environ.setdefault("DB_REQUIRE_RESTRICTED_ROLE", "false")

from config.settings.base import *

ALLOWED_HOSTS = ["testserver"]

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
