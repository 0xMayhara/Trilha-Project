"""Asset domain errors. They carry no user-facing text: each adapter maps the error type to its own
fixed message, so exception content never reaches a response (CWE-209)."""


class AssetError(Exception):
    pass


class AssetNotFound(AssetError):
    """Missing, or outside the actor's team scope: callers must not tell the two apart."""


class AssetForbidden(AssetError):
    """In scope, but a required permission is missing."""

    def __init__(self, asset_id=None):
        super().__init__("A required asset permission is missing.")
        # Read from the database row, never from request input: safe for denial logs.
        self.asset_id = asset_id


class TeamUnavailable(AssetError):
    """The target team is absent, inactive or not one of the actor's teams (one generic answer)."""


class AssetConflict(AssetError):
    """The request conflicts with the asset's current state."""


class StaleAsset(AssetConflict):
    """The version, team or authorization changed since the client read the asset."""


class NameTaken(AssetConflict):
    """Another active asset of the team already uses the name."""


class InvalidState(AssetConflict):
    """The lifecycle state does not allow the operation."""


class AssetIntegrityFailure(AssetError):
    """An unexpected database integrity violation; raised without its database cause."""
