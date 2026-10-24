"""Finding domain errors. Like the asset errors they carry no user-facing text: the HTTP adapter
maps each type to a fixed message, so exception content never reaches a response (CWE-209)."""


class FindingError(Exception):
    pass


class FindingNotFound(FindingError):
    """Missing, or outside the actor's team scope: callers must not tell the two apart."""


class FindingForbidden(FindingError):
    """In scope, but a required permission is missing."""

    def __init__(self, finding_id=None):
        super().__init__("A required finding permission is missing.")
        # Read from the database row, never from request input: safe for denial logs.
        self.finding_id = finding_id


class AssetUnavailable(FindingError):
    """The asset of a new finding is missing, outside scope or not viewable: one generic answer, so
    a refusal never confirms that another team's asset exists (SEC-04, CWE-204)."""


class FindingConflict(FindingError):
    """The request conflicts with current state."""


class StaleFinding(FindingConflict):
    """The version, the owning team or the actor's authority changed since the client read it."""


class AssetRetired(FindingConflict):
    """New findings are reported only on active assets (BR-04, BR-18)."""


class FindingIntegrityFailure(FindingError):
    """An unexpected database integrity violation; raised without its database cause."""
