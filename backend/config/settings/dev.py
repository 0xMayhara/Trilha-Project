"""Local development settings. Never used by production images (SPEC-0001 BR-03)."""

import base64
import os
import secrets

from django.core.management.utils import get_random_secret_key

# A per-process random key avoids committing any secret; sessions reset on restart.
os.environ.setdefault("DJANGO_SECRET_KEY", get_random_secret_key())
# Likewise for the audit digest ring when none, or the example placeholder, is set: digests made
# in one dev process do not verify after a restart.
if "change-me" in os.environ.get("AUDIT_DIGEST_KEYS", "change-me").lower():
    os.environ["AUDIT_DIGEST_KEYS"] = (
        "dev:" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    )
    os.environ["AUDIT_DIGEST_ACTIVE_KEY_ID"] = "dev"

from config.env import env_list
from config.settings.base import *

DEBUG = True
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
