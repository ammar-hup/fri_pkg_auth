"""Strawberry context getter producing ``(IdentityContext, AuthContext)``."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable
from uuid import UUID

from starlette.exceptions import HTTPException
from starlette.requests import Request

from ...authentication import (
    AuthenticateTokenUseCase,
    AuthenticationError,
    IdentityContext,
    InvalidTokenError,
    TokenExpiredError,
)
from ...authorization import (
    AuthContext,
    NotAMember,
    OrgId,
    UserNotProvisioned,
)
from ...authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from ...authorization.application.use_cases.resolve_delegated_auth_context import (
    ON_BEHALF_OF_HEADER,
)
from ...authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)
from ...authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)
from ...authorization.domain.entities import User
from ...authorization.domain.ports import OrganizationRepository

DEFAULT_HEADER_NAME = "X-Organization-Id"
DEFAULT_COOKIE_NAME = "access_token"


@dataclass(slots=True)
class StrawberryContext:
    """Context object exposed to every Strawberry resolver via ``info.context``.

    Carries the request, the validated identity (``None`` for anonymous
    queries), and the per-organization authorization context (``None``
    if no ``X-Organization-Id`` header was provided).
    """

    request: Request
    identity: IdentityContext | None = None
    auth_context: AuthContext | None = None
    extra: dict[str, object] = field(default_factory=dict)


def _extract_token(request: Request, cookie_name: str) -> str | None:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if token:
            return token
    return request.cookies.get(cookie_name)


def make_context_getter(
    *,
    authenticate_use_case: AuthenticateTokenUseCase,
    resolve_use_case: ResolveAuthContextUseCase,
    organization_repo: OrganizationRepository,
    sync_user_use_case: SyncUserFromJwtUseCase | None = None,
    resolve_user_use_case: ResolveUserFromJwtUseCase | None = None,
    header_name: str = DEFAULT_HEADER_NAME,
    cookie_name: str = DEFAULT_COOKIE_NAME,
) -> Callable[[Request], Awaitable[StrawberryContext]]:
    """Build an async ``context_getter`` for ``strawberry.fastapi.GraphQLRouter``.

    Exactly one of ``sync_user_use_case`` (Mode A — source-of-truth) or
    ``resolve_user_use_case`` (Mode B — consumer) must be supplied.

    The returned function is permissive: token errors, missing headers,
    and ``UserNotProvisioned`` degrade the context fields to ``None``
    rather than raising. Permission classes (``IsAuthenticated``,
    ``RequirePermission``) are responsible for rejecting under-privileged
    queries.

    The one non-permissive case is ``X-On-Behalf-Of``: this integration
    cannot delegate, so a request carrying it (any value, any token
    state) is refused with HTTP 403 before any user work (``auth:AD-1``).
    """
    if (sync_user_use_case is None) == (resolve_user_use_case is None):
        raise ValueError(
            "make_context_getter: pass exactly one of "
            "sync_user_use_case (Mode A) or resolve_user_use_case (Mode B)."
        )

    async def _context_getter(request: Request) -> StrawberryContext:
        if request.headers.getlist(ON_BEHALF_OF_HEADER):
            raise HTTPException(
                status_code=403,
                detail=f"{ON_BEHALF_OF_HEADER} is not accepted here",
            )

        ctx = StrawberryContext(request=request)

        token = _extract_token(request, cookie_name)
        if token is not None:
            try:
                ctx.identity = authenticate_use_case.execute(token)
            except (TokenExpiredError, InvalidTokenError, AuthenticationError):
                ctx.identity = None

        if ctx.identity is None:
            return ctx

        raw = request.headers.get(header_name)
        if raw is None:
            return ctx

        user: User
        try:
            if sync_user_use_case is not None:
                user = await sync_user_use_case.execute(
                    sub=ctx.identity.subject_str,
                    email=ctx.identity.email_str or "",
                    full_name=ctx.identity.full_name,
                )
            else:
                assert resolve_user_use_case is not None
                user = await resolve_user_use_case.execute(
                    sub=ctx.identity.subject_str,
                )
        except UserNotProvisioned:
            return ctx

        try:
            org = await organization_repo.get(OrgId(UUID(raw)))
        except ValueError:
            org = await organization_repo.get_by_slug(raw)
        if org is None:
            return ctx

        try:
            ctx.auth_context = await resolve_use_case.execute(user.id, org.id)
        except NotAMember:
            ctx.auth_context = None

        return ctx

    return _context_getter
