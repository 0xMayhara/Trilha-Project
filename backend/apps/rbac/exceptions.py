class RbacError(Exception):
    """A safe-to-display domain validation or conflict error."""


class AdministrationDenied(RbacError):
    def __init__(self):
        super().__init__("Administration is not allowed.")
