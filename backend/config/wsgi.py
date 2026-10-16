import os

from django.core.wsgi import get_wsgi_application

# Production images default to production settings (SPEC-0001 BR-03).
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.prod")

application = get_wsgi_application()
