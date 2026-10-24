"""Startup check (SPEC-0007 SEC-19): with findings installed, an asset transfer must never skip the
findings participant. Runs with `manage.py check` and `migrate` (so `db_migrate` stops a broken
deployment) and in the readiness probe."""

from django.core import checks

from apps.assets import transfer

TAG = "trilha_integrity"


@checks.register(TAG)
def transfer_participant_registered(app_configs, **kwargs):
    from apps.findings import transfer as participant

    if participant in transfer.participants():
        return []
    return [
        checks.Error(
            "The findings transfer participant is not registered: asset transfers would move "
            "findings without their checks.",
            id="findings.E001",
        )
    ]
