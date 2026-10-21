"""AuthContextMiddleware — reads X-Organization-Id, attaches ``request.auth_context``."""
from __future__ import annotations

from typing import Awaitable, Callable
from uuid import UUID

from asgiref.sync import iscoroutinefunction
from django.http import HttpRequest, HttpResponse, JsonResponse

from ...authorization import (
    NotAMember,
    OrgId,
    UnknownOrganization,
    UserNotProvisioned,
)
from ...authorization.application.use_cases.resolve_delegated_auth_context import (
    ON_BEHALF_OF_HEADER,
)
from ...authorization.domain.entities import User
from .install import get_registry


class AuthContextMiddleware:
    """Resolve and attach ``request.auth_context`` for protected routes.

    Requires ``IdentityMiddleware`` to run first so ``request.identity``
    is populated. Behavior:

        - ``X-On-Behalf-Of`` present (any value, with or without the org
          header or an identity) → 403; this middleware cannot delegate
          (``auth:AD-1``)
        - no header → ``request.auth_context = None`` (route decides)
        - identity is None and header present → 401
        - org not found → 404
        - user not a member → 403

    pkg_auth deliberately does NOT bake in a "platform admin fallback"
    here. Platform-admin detection is a *service-level* policy: services
    that want it call :func:`pkg_auth.authorization.is_platform_context`
    inside views, comparing the request's ``AuthContext.organization_id``
    against their own cached platform org id. Services that need to
    *resolve* the caller against a platform org when they aren't a
    member of the requested org can subclass this middleware and
    intercept the ``NotAMember`` branch themselves.
    """

    sync_capable = False
    async_capable = True

    def __init__(
        self,
        get_response: Callable[[HttpRequest], Awaitable[HttpResponse]],
    ) -> None:
        self.get_response = get_response
        if not iscoroutinefunction(get_response):
            raise RuntimeError(
                "AuthContextMiddleware requires async middleware chain "
                "(use ASGI / runserver)."
            )

    async def __call__(self, request: HttpRequest) -> HttpResponse:
        request.auth_context = None  # type: ignore[attr-defined]
        if request.headers.get(ON_BEHALF_OF_HEADER) is not None:
            return JsonResponse(
                {"detail": f"{ON_BEHALF_OF_HEADER} is not accepted here"},
                status=403,
            )

        registry = get_registry()

        raw = request.headers.get(registry.header_name)
        if raw is None:
            return await self.get_response(request)

        identity = getattr(request, "identity", None)
        if identity is None:
            return JsonResponse(
                {"detail": "Not authenticated"}, status=401,
            )

        user: User
        try:
            if registry.sync_user is not None:
                user = await registry.sync_user.execute(
                    sub=identity.subject_str,
                    email=identity.email_str or "",
                    full_name=identity.full_name,
                )
            else:
                assert registry.resolve_user is not None
                user = await registry.resolve_user.execute(
                    sub=identity.subject_str,
                )
        except UserNotProvisioned as exc:
            return JsonResponse({"detail": str(exc)}, status=403)

        # Accept UUID or slug. The package switched to UUID PKs in v1.2;
        # the legacy isdigit() fast-path is gone.
        try:
            org = await registry.organization_repo.get(OrgId(UUID(raw)))
        except (ValueError, AttributeError):
            org = await registry.organization_repo.get_by_slug(raw)
        if org is None:
            return JsonResponse(
                {"detail": f"Organization {raw!r} not found"}, status=404,
            )

        try:
            request.auth_context = await registry.resolve_auth.execute(  # type: ignore[attr-defined]
                user.id, org.id,
            )
        except NotAMember as exc:
            return JsonResponse({"detail": str(exc)}, status=403)
        except UnknownOrganization as exc:
            return JsonResponse({"detail": str(exc)}, status=404)

        return await self.get_response(request)
