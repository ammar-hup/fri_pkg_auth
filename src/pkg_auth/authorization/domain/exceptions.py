"""Authorization (ACL) exceptions.

These are deliberately a *separate* hierarchy from
``pkg_auth.authentication.domain.exceptions``: authentication failures
are 401, authorization failures are 403/404. Integration layers map
each to the right HTTP status.
"""
from __future__ import annotations

from enum import Enum


class AuthorizationError(Exception):
    """Base for all authorization (ACL) failures."""


class NotAMember(AuthorizationError):
    """The user has no membership in the requested organization."""


class MissingPermission(AuthorizationError):
    """The user's role in the organization does not include the required permission."""


class UnknownOrganization(AuthorizationError):
    """The referenced organization does not exist."""


class UnknownUser(AuthorizationError):
    """The referenced user does not exist."""


class UserNotProvisioned(AuthorizationError):
    """JWT-authenticated user has no row in the local ACL ``users`` table.

    Raised by :class:`ResolveUserFromJwtUseCase` in Mode B (consuming)
    services: the caller is a valid Keycloak principal, but the
    source-of-truth service (Mode A) hasn't mirrored them into the
    shared ACL yet. Integration layers map this to HTTP 403.
    """


class UnknownRole(AuthorizationError):
    """The referenced role does not exist."""


class UnknownPermission(AuthorizationError):
    """A referenced permission key is not registered in the catalog."""


class PermissionVisibilityConflict(AuthorizationError):
    """A role tried to use a permission whose visibility forbids it.

    Raised when a platform-org role references a ``tenant_only`` permission,
    or a normal-org role references a ``platform_only`` permission.
    """


class UnknownService(AuthorizationError):
    """The referenced service is not registered in the ``services`` table."""


class ServiceNotSaaSAvailable(AuthorizationError):
    """A platform admin tried to enable a service the vendor has not marked
    ``saas_available``. Integration layers map this to HTTP 403.
    """


class ServiceNotEnabled(AuthorizationError):
    """The organization does not have the required service enabled."""


class DelegationRefusal(str, Enum):
    """Why a delegated (on-behalf-of) request was refused.

    One member per row 3–9 of ``auth:AD-1``'s order of checks. Integration
    layers map ``REPEATED`` and ``EMPTY_TARGET`` to 400,
    ``UNKNOWN_ORGANIZATION`` to 404, and every other reason to 403.
    """

    REPEATED = "repeated"
    NOT_A_DELEGATOR = "not_a_delegator"
    EMPTY_TARGET = "empty_target"
    UNKNOWN_ORGANIZATION = "unknown_organization"
    ORGANIZATION_NOT_ALLOWED = "organization_not_allowed"
    TARGET_NOT_PROVISIONED = "target_not_provisioned"
    TARGET_NOT_A_MEMBER = "target_not_a_member"

    def __str__(self) -> str:
        return self.value


class DelegationRefused(AuthorizationError):
    """A delegated request was refused; ``reason`` says which check failed.

    The only error :class:`ResolveDelegatedAuthContextUseCase` raises for a
    refusal — never :class:`NotAMember` or :class:`UserNotProvisioned`, so
    no integration can mistake a refused delegation for the caller's own
    failure and fall back to the caller's context.
    """

    def __init__(self, reason: DelegationRefusal, detail: str | None = None) -> None:
        self.reason = reason
        super().__init__(detail or f"delegation refused: {reason.value}")
