"""Errors raised by the audit trail (SPEC-0002). All are programming or integrity errors: they
propagate, roll back the caller's transaction and surface as a generic 500 (fail closed)."""


class AuditError(Exception):
    pass


class AuditEventImmutable(AuditError):
    """An update or delete of an audit event was attempted (BR-01)."""


class AuditTransactionRequired(AuditError):
    """record_event() was called outside transaction.atomic (BR-02)."""


class AuditContextMissing(AuditError):
    """No audit context (source) is bound for the current request, task or command (BR-06)."""


class AuditPayloadTooLarge(AuditError):
    """changes + metadata exceed the size limit (BR-09)."""


class AuditValidationError(AuditError, ValueError):
    """An action code, resource, actor or payload does not meet the audit formats (BR-10)."""
