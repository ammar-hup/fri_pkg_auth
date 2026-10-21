"""``make_get_current_user`` factory — the org-less ACL user dependency.

Resolves the caller's ACL :class:`User` from the token alone, with no
``X-Organization-Id``. It cannot delegate, so it refuses ``X-On-Behalf-Of``
with 403 before any user work (``auth:AD-1`` Coverage).
"""
from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status

from ...authentication import IdentityContext
from ...authorization import UserNotProvisioned
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


async def _refuse_on_behalf_of(request: Request) -> None:
    # Declared before ``get_identity`` so FastAPI resolves it first: the
    # header is refused even without a valid token.
    if request.headers.getlist(ON_BEHALF_OF_HEADER):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{ON_BEHALF_OF_HEADER} is not accepted here",
        )


def make_get_current_user(
    *,
    get_identity: Callable[..., Awaitable[IdentityContext]],
    sync_user_use_case: SyncUserFromJwtUseCase | None = None,
    resolve_user_use_case: ResolveUserFromJwtUseCase | None = None,
) -> Callable[..., Awaitable[User]]:
    """Build a FastAPI dependency returning the caller's ACL ``User``.

    Exactly one of ``sync_user_use_case`` (Mode A — upserts the caller)
    or ``resolve_user_use_case`` (Mode B — read-through) must be supplied.

    Errors map to:
        - ``X-On-Behalf-Of`` present (any value, any token) → 403
        - no or invalid token                    → 401 (from ``get_identity``)
        - user not provisioned (Mode B)          → 403
    """
    if (sync_user_use_case is None) == (resolve_user_use_case is None):
        raise ValueError(
            "make_get_current_user: pass exactly one of "
            "sync_user_use_case (Mode A) or resolve_user_use_case (Mode B)."
        )

    async def dependency(
        _: None = Depends(_refuse_on_behalf_of),
        identity: IdentityContext = Depends(get_identity),
    ) -> User:
        try:
            if sync_user_use_case is not None:
                return await sync_user_use_case.execute(
                    sub=identity.subject_str,
                    email=identity.email_str or "",
                    full_name=identity.full_name,
                )
            assert resolve_user_use_case is not None
            return await resolve_user_use_case.execute(sub=identity.subject_str)
        except UserNotProvisioned as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc

    return dependency
