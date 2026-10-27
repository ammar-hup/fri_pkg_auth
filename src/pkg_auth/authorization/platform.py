"""Helpers for detecting platform-org context.

A "platform" organization is one whose members are granted cross-org
administrative privileges by the consuming service. There's nothing
special about its DB row — it's just an organization that the service
has designated as the platform org via configuration (slug, env var,
settings module, etc.).

The intended pattern:

1. The service caches the platform org's id at startup, e.g. by looking
   it up via slug from its ``OrganizationRepository`` in a lifespan or
   ``AppConfig.ready()`` hook. Where the cache lives is up to the
   service (module global, app config, request scope, …).
2. Platform admins send their requests with
   ``X-Organization-Id: <platform-org-slug>`` to surface their elevated
   privileges. The auth dependency builds an :class:`AuthContext` whose
   ``organization_id`` is the platform org id.
3. Inside handlers, the service calls
   :func:`is_platform_context` with the request's ``AuthContext`` and
   the cached platform org id. When it returns ``True``, the handler
   broadens its queryset filters (e.g. lists users from all orgs).

This module is intentionally stateless — pkg_auth does not own the
platform org id cache. Each consuming service decides where the cache
lives and when to refresh it.
"""
from __future__ import annotations

from .domain.entities import AuthContext
from .domain.value_objects import OrgId


def is_platform_context(
    auth_ctx: AuthContext, platform_org_id: OrgId | None,
) -> bool:
    """Return True if the request is being made in the platform org.

    ``platform_org_id`` is whatever the consuming service has cached
    (typically resolved by slug at startup). When ``None`` — for
    example before the cache is initialized, or in services that
    don't have a designated platform org — this returns ``False``,
    which is equivalent to "no platform-admin privileges available".

    A platform context also requires at least one role: a roleless
    member of the platform organization is not a platform admin.
    """
    if platform_org_id is None:
        return False
    return auth_ctx.organization_id == platform_org_id and bool(
        auth_ctx.role_names
    )
