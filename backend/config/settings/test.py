"""Test settings: production-like (DEBUG off), local test database defaults."""

import os

from django.core.management.utils import get_random_secret_key

os.environ.setdefault("DJANGO_SECRET_KEY", get_random_secret_key())
os.environ.setdefault("POSTGRES_DB", "trilha")
os.environ.setdefault("POSTGRES_USER", "trilha")
os.environ.setdefault("POSTGRES_PASSWORD", "trilha-test")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PASSWORD", "unused-in-tests")

from config.settings.base import *

ALLOWED_HOSTS = ["testserver"]

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
