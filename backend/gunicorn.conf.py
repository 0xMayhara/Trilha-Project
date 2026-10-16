"""Gunicorn settings for the backend container."""

import os

# Reachable only on the internal compose network; the proxy is the sole published service.
bind = "0.0.0.0:8000"
workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "30"))
graceful_timeout = 30
keepalive = 5

# Django's access log middleware is the single request log (SPEC-0001 SEC-13).
accesslog = None
errorlog = "-"

limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# The root filesystem is read-only; /dev/shm is private to the container (gunicorn heartbeat files).
worker_tmp_dir = "/dev/shm"  # noqa: S108
