class RbacError(Exception):
    """A safe-to-display domain validation or conflict error."""


class AdministrationDenied(RbacError):
    def __init__(self):
        super().__init__("Administration is not allowed.")


class RbacNotFound(RbacError):
    """A referenced user, team, role, membership or binding does not exist."""

    def __init__(self):
        super().__init__("The requested object does not exist.")


class RbacInvalid(RbacError):
    """A domain value fails validation."""

    def __init__(self, message="Invalid domain value."):
        super().__init__(message)


class RbacConflict(RbacError):
    """The request conflicts with current state or an Admin guard (SPEC-0010 BR-06)."""

    REASONS = frozenset({"self_target", "last_admin", "unchanged", "state"})

    def __init__(self, reason, message):
        if reason not in self.REASONS:
            raise ValueError(reason)
        super().__init__(message)
        self.reason = reason
