from django.apps import AppConfig


class AuditConfig(AppConfig):
    name = "apps.audit"
    label = "audit"

    def ready(self) -> None:
        from apps.audit import celery_signals  # noqa: F401  (connects signal handlers)
