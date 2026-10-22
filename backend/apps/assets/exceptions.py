"""Asset domain errors. Messages are fixed strings, safe to show; none echo stored values."""


class AssetError(Exception):
    pass


class AssetNotFound(AssetError):
    """Missing, or outside the actor's team scope: callers must not tell the two apart."""

    def __init__(self):
        super().__init__("Not found.")


class AssetForbidden(AssetError):
    """In scope, but a required permission is missing."""

    def __init__(self):
        super().__init__("You do not have permission to perform this action.")


class TeamUnavailable(AssetError):
    """The target team is absent, inactive or not one of the actor's teams (one generic answer)."""

    def __init__(self):
        super().__init__("Select a team where you can perform this action.")


class AssetConflict(AssetError):
    STALE = "The asset changed. Reload and try again."
    NAME_TAKEN = "An active asset with this name already exists in the team."
    STATE = "The asset's state does not allow this operation."


class AssetIntegrityFailure(AssetError):
    """An unexpected database integrity violation; raised without its database cause."""

    def __init__(self):
        super().__init__("Asset integrity check failed.")
