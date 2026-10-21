"""Server-established identities, never deserialized from external claims or audit context."""

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class UserPrincipal:
    user_id: UUID


class _InfrastructureOperator:
    __slots__ = ()


_OPERATOR = _InfrastructureOperator()


def infrastructure_operator():
    """Trusted deployment adapters only. Shell/code control is already an operator capability."""
    return _OPERATOR


def is_infrastructure_operator(principal) -> bool:
    return principal is _OPERATOR


def session_principal(user) -> UserPrincipal:
    if not user.is_authenticated or user._state.adding:
        raise ValueError("A session principal requires a persisted authenticated user.")
    return UserPrincipal(user.pk)
