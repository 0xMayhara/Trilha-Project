from django.apps import AppConfig


class CoreConfig(AppConfig):
    name = "apps.core"
    label = "core"

    def ready(self) -> None:
        from apps.core import celery_signals  # noqa: F401  (connects signal handlers)
