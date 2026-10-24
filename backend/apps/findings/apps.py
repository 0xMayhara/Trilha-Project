from django.apps import AppConfig


class FindingsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.findings"

    def ready(self):
        from apps.assets import transfer
        from apps.findings import checks  # noqa: F401  (registers the startup check)
        from apps.findings import transfer as participant

        transfer.register(participant)
