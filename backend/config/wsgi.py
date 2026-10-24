import os

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.wsgi import get_wsgi_application

# Production images default to production settings (SPEC-0001 BR-03).
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.prod")

application = get_wsgi_application()

# The process serving HTTP signs audit content digests: it never starts without its key ring
# (SPEC-0007 SEC-53). Migrations and the worker sign nothing and run without one.
if not settings.AUDIT_DIGEST_KEYS:
    raise ImproperlyConfigured("Set AUDIT_DIGEST_KEYS and AUDIT_DIGEST_ACTIVE_KEY_ID.")
