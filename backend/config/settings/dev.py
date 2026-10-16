"""Local development settings. Never used by production images (SPEC-0001 BR-03)."""

import os

from django.core.management.utils import get_random_secret_key

# A per-process random key avoids committing any secret; sessions reset on restart.
os.environ.setdefault("DJANGO_SECRET_KEY", get_random_secret_key())

from config.env import env_list
from config.settings.base import *

DEBUG = True
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
