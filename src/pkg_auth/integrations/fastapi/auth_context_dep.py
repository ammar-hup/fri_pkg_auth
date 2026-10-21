"""``make_get_auth_context`` factory.

Composes ``Authentication.get_identity`` (from the authentication
module) with the authorization layer's ``ResolveAuthContextUseCase``,
either ``SyncUserFromJwtUseCase`` (Mode A — writer) or
``ResolveUserFromJwtUseCase`` (Mode B — reader), and
``OrganizationRepository`` to produce a single FastAPI dependency that
returns ``(IdentityContext, AuthContext)``.

Exactly one of ``sync_user_use_case`` / ``resolve_user_use_case`` must
be supplied:

- **Mode A** (source-of-truth, extends the ACL schema): pass
  ``sync_user_use_case=...`` — the dep will upsert the local user row
  from JWT claims on every request.
- **Mode B** (consumer, ACL DB is owned by a Mode A peer): pass
  ``resolve_user_use_case=...`` — the dep will read-through and raise
  ``UserNotProvisioned`` (→ HTTP 403) if the source-of-truth hasn't
  mirrored the user yet.

pkg_auth deliberately does NOT bake in a "platform admin fallback"
here. Platform-admin detection is a *service-level* policy: services
that want it call :func:`pkg_auth.authorization.is_platform_context`
inside handlers, comparing the request's ``AuthContext.organization_id``
against their own cached platform org id. Services that need
elevated-privilege fallbacks (resolving the caller against a platform
org when they aren't a member of the requested org) wrap this factory
in their own dependency. See ``docs/FastAPI.md`` for the canonical
pattern.
"""
from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status

from ...authentication import IdentityContext
from ...authorization import (
    AuthContext,
    DelegationRefusal,
    DelegationRefused,
    NotAMember,
    UnknownOrganization,
    UserNotProvisioned,
)
from ...authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from ...authorization.application.use_cases.resolve_delegated_auth_context import (
    ON_BEHALF_OF_HEADER,
    ResolveDelegatedAuthContextUseCase,
    find_organization,
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

# Unlisted reasons fall through to 403, so a new reason fails closed.
_REFUSAL_STATUS: dict[DelegationRefusal, int] = {
    DelegationRefusal.REPEATED: status.HTTP_400_BAD_REQUEST,
    DelegationRefusal.EMPTY_TARGET: status.HTTP_400_BAD_REQUEST,
    DelegationRefusal.UNKNOWN_ORGANIZATION: status.HTTP_404_NOT_FOUND,
}


def make_get_auth_context(
    *,
    get_identity: Callable[..., Awaitable[IdentityContext]],
    resolve_use_case: ResolveAuthContextUseCase,
    organization_repo: OrganizationRepository,
    sync_user_use_case: SyncUserFromJwtUseCase | None = None,
    resolve_user_use_case: ResolveUserFromJwtUseCase | None = None,
    header_name: str = DEFAULT_HEADER_NAME,
    delegation: ResolveDelegatedAuthContextUseCase | None = None,
) -> Callable[..., Awaitable[tuple[IdentityContext, AuthContext]]]:
    """Build a FastAPI dependency returning ``(IdentityContext, AuthContext)``.

    Exactly one of ``sync_user_use_case`` or ``resolve_user_use_case``
    must be supplied. See the module docstring for when to use each.

    The dependency:
        1. Resolves identity via the injected ``get_identity``.
        2. Either lazily upserts the local user row from JWT claims
           (Mode A) or reads it through and 403s if missing (Mode B).
        3. Reads ``header_name`` from the request and parses it as a
           UUID first, falling back to a slug lookup.
        4. Resolves the user's auth context for that organization.

    If the request carries ``X-On-Behalf-Of`` (checked only after steps 1
    and 2, ``auth:AD-1``), steps 3–4 are replaced by ``delegation``: the
    result is ``(caller's IdentityContext, target's AuthContext)`` with
    ``acted_by`` set to the caller's ACL id. Without ``delegation`` the
    header is refused with 403. A refusal never falls back to the
    caller's own context.

    Errors map to:
        - missing header                → 400
        - unknown organization          → 404
        - user not a member             → 403
        - user not provisioned (Mode B) → 403
        - ``X-On-Behalf-Of`` without ``delegation`` → 403
        - delegation refused: repeated header or empty value → 400,
          unknown organization → 404, any other reason → 403
    """
    if (sync_user_use_case is None) == (resolve_user_use_case is None):
        raise ValueError(
            "make_get_auth_context: pass exactly one of "
            "sync_user_use_case (Mode A) or resolve_user_use_case (Mode B)."
        )

    async def dependency(
        request: Request,
        identity: IdentityContext = Depends(get_identity),
    ) -> tuple[IdentityContext, AuthContext]:
        raw = request.headers.get(header_name)
        if not raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing {header_name} header",
            )

        user: User
        try:
            if sync_user_use_case is not None:
                user = await sync_user_use_case.execute(
                    sub=identity.subject_str,
                    email=identity.email_str or "",
                    full_name=identity.full_name,
                )
            else:
                assert resolve_user_use_case is not None
                user = await resolve_user_use_case.execute(
                    sub=identity.subject_str,
                )
        except UserNotProvisioned as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc

        on_behalf_of = request.headers.getlist(ON_BEHALF_OF_HEADER)
        if on_behalf_of:
            if delegation is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"{ON_BEHALF_OF_HEADER} is not accepted here",
                )
            try:
                auth_ctx = await delegation.execute(
                    caller=user, on_behalf_of=on_behalf_of, organization=raw
                )
            except DelegationRefused as exc:
                raise HTTPException(
                    status_code=_REFUSAL_STATUS.get(
                        exc.reason, status.HTTP_403_FORBIDDEN
                    ),
                    detail=str(exc),
                ) from exc
            return identity, auth_ctx

        org = await find_organization(organization_repo, raw)
        if org is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization {raw!r} not found",
            )

        try:
            auth_ctx = await resolve_use_case.execute(user.id, org.id)
        except NotAMember as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc
        except UnknownOrganization as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

        return identity, auth_ctx

    return dependency
