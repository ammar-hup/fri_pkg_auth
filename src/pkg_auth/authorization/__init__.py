"""Authorization module: full ACL on top of pkg_auth.authentication.

Public API:

    Entities:        User, Organization, Permission, Role, Membership, AuthContext
    Value objects:   UserId, OrgId, RoleId, PermissionId, RoleName, PermissionKey
    Ports:           UserRepository, OrganizationRepository, RoleRepository,
                     MembershipRepository, PermissionCatalogRepository
    Exceptions:      AuthorizationError, NotAMember, MissingPermission,
                     UnknownOrganization, UnknownUser, UnknownRole,
                     UserNotProvisioned, DelegationRefused, DelegationRefusal

The application layer (use cases) is added in M3; SQLAlchemy / Django ORM
adapters in M4 / M6; cache layer in M5; framework integrations in M7-M9.
"""
from __future__ import annotations

from .application.use_cases.register_permission_catalog import (
    CatalogEntry,
    ServiceManifest,
)
from .application.use_cases.sync_service_catalog import ServiceSpec
from .config import default_locale
from .domain.entities import (
    AuthContext,
    Membership,
    Organization,
    OrganizationService,
    Permission,
    Role,
    Service,
    User,
)
from .platform import is_platform_context
from .domain.exceptions import (
    AuthorizationError,
    DelegationRefusal,
    DelegationRefused,
    MissingPermission,
    NotAMember,
    PermissionVisibilityConflict,
    ServiceNotEnabled,
    ServiceNotSaaSAvailable,
    UnknownOrganization,
    UnknownPermission,
    UnknownRole,
    UnknownService,
    UnknownUser,
    UserNotProvisioned,
)
from .domain.ports import (
    MembershipRepository,
    OrganizationRepository,
    OrganizationServiceRepository,
    PermissionCatalogRepository,
    PermissionScope,
    RoleRepository,
    ServiceRepository,
    UserRepository,
)
from .domain.value_objects import (
    LocalizedText,
    OrgId,
    PermissionId,
    PermissionKey,
    PermissionVisibility,
    RoleId,
    RoleName,
    ServiceName,
    UserId,
)

__all__ = [
    # Entities
    "User",
    "Organization",
    "Permission",
    "Role",
    "Membership",
    "AuthContext",
    "Service",
    "OrganizationService",
    # Value objects
    "UserId",
    "OrgId",
    "RoleId",
    "PermissionId",
    "RoleName",
    "PermissionKey",
    "PermissionVisibility",
    "ServiceName",
    "LocalizedText",
    # Ports (Protocols)
    "UserRepository",
    "OrganizationRepository",
    "RoleRepository",
    "MembershipRepository",
    "PermissionCatalogRepository",
    "ServiceRepository",
    "OrganizationServiceRepository",
    # Application DTOs
    "CatalogEntry",
    "ServiceSpec",
    "ServiceManifest",
    "PermissionScope",
    # Config
    "default_locale",
    # Platform helpers
    "is_platform_context",
    # Exceptions
    "AuthorizationError",
    "NotAMember",
    "MissingPermission",
    "UnknownOrganization",
    "UnknownUser",
    "UnknownRole",
    "UnknownPermission",
    "UnknownService",
    "ServiceNotSaaSAvailable",
    "ServiceNotEnabled",
    "PermissionVisibilityConflict",
    "UserNotProvisioned",
    "DelegationRefused",
    "DelegationRefusal",
]
