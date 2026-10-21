"""Resolve a delegated (on-behalf-of) :class:`AuthContext` (``auth:AD-1``)."""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any
from uuid import UUID

from ...domain.entities import AuthContext, Organization, User
from ...domain.exceptions import (
    DelegationRefusal,
    DelegationRefused,
    NotAMember,
)
from ...domain.ports import OrganizationRepository, UserRepository
from ...domain.value_objects import OrgId
from .resolve_auth_context import ResolveAuthContextUseCase

Delegators = Mapping[str, frozenset[OrgId]]

ON_BEHALF_OF_HEADER = "X-On-Behalf-Of"


async def find_organization(
    repo: OrganizationRepository, raw: str
) -> Organization | None:
    """Look up an org from a raw ``X-Organization-Id`` value.

    Tries ``raw`` as a UUID first and falls back to a slug lookup. The one
    lookup rule shared by the FastAPI dependency and the delegated use case,
    so the two cannot drift.
    """
    try:
        org_id = OrgId(UUID(raw))
    except ValueError:
        return await repo.get_by_slug(raw)
    return await repo.get(org_id)


def _to_org_id(raw: Any, sub: str) -> OrgId:
    if isinstance(raw, OrgId):
        return raw
    if isinstance(raw, UUID):
        return OrgId(raw)
    if isinstance(raw, str):
        try:
            return OrgId(UUID(raw))
        except ValueError:
            pass
    raise ValueError(
        f"delegators[{sub!r}]: organization {raw!r} is not a UUID"
    )


def normalize_delegators(
    raw: Mapping[str, Iterable[Any]] | None,
) -> MappingProxyType[str, frozenset[OrgId]]:
    """Normalize a ``delegators`` config into an immutable allowlist.

    Keys are Keycloak service-account ``sub`` strings, kept exactly as
    given. Values are iterables of org ids (``OrgId``, ``UUID`` or UUID
    strings). ``None`` or an empty mapping yields an empty map, so nobody
    delegates (fail closed); a ``sub`` with no orgs is dropped, so it is
    refused as not a delegator before any lookup.

    Raises :class:`ValueError` when ``raw`` is a bare ``str`` or not a
    mapping, a ``sub`` is not a non-blank, unpadded ``str``, a value is a bare
    ``str`` or not iterable, or an org is not a UUID.
    """
    if raw is None:
        return MappingProxyType({})
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Mapping):
        raise ValueError(
            f"delegators must be a mapping of sub -> org ids, got {type(raw).__name__}"
        )
    normalized: dict[str, frozenset[OrgId]] = {}
    for sub, orgs in raw.items():
        if not isinstance(sub, str) or not sub.strip() or sub != sub.strip():
            raise ValueError(f"delegators: blank, padded or non-string sub {sub!r}")
        if isinstance(orgs, (str, bytes)):
            raise ValueError(
                f"delegators[{sub!r}] must be a collection of org ids, not a bare string"
            )
        try:
            items = list(orgs)
        except TypeError as exc:
            raise ValueError(
                f"delegators[{sub!r}] must be a collection of org ids"
            ) from exc
        org_ids = frozenset(_to_org_id(o, sub) for o in items)
        if org_ids:  # an agent with no orgs is not a delegator at all
            normalized[sub] = org_ids
    return MappingProxyType(normalized)


@dataclass(slots=True)
class ResolveDelegatedAuthContextUseCase:
    """Decide a delegated request and return the target's :class:`AuthContext`.

    The single framework-free place that holds ``delegators`` (``auth:AD-1``
    Placement). Integrations pass the raw ``X-On-Behalf-Of`` values and the
    raw ``X-Organization-Id`` value; they never see the allowlist.

    Checks run in ``auth:AD-1``'s order (rows 3–9), first match wins, and
    every refusal is a :class:`DelegationRefused`. The target is looked up
    read-only through ``UserRepository.get_by_keycloak_sub`` — delegation
    never creates a user. On success the result is the target's own
    context from ``resolve_use_case`` (same service guard, same cache
    entry) with ``acted_by`` attached afterwards; the caller's perms are
    never used.
    """

    resolve_use_case: ResolveAuthContextUseCase
    user_repo: UserRepository
    organization_repo: OrganizationRepository
    delegators: Delegators | None = field(default=None)

    def __post_init__(self) -> None:
        self.delegators = normalize_delegators(self.delegators)

    async def execute(
        self,
        *,
        caller: User,
        on_behalf_of: Sequence[str],
        organization: str,
    ) -> AuthContext:
        if isinstance(on_behalf_of, (str, bytes)):
            raise TypeError("on_behalf_of must be the header's list of values")
        if len(on_behalf_of) == 0:
            raise ValueError("on_behalf_of is empty; only call when the header is present")

        # Row 3: repeated header.
        if len(on_behalf_of) > 1:
            raise DelegationRefused(DelegationRefusal.REPEATED)

        # Row 4: caller not a delegator — before any lookup.
        assert self.delegators is not None
        allowed_orgs = self.delegators.get(caller.keycloak_sub)
        if allowed_orgs is None:
            raise DelegationRefused(DelegationRefusal.NOT_A_DELEGATOR)

        # Row 5: empty value.
        target_sub = on_behalf_of[0]
        if not target_sub.strip():
            raise DelegationRefused(DelegationRefusal.EMPTY_TARGET)

        # Row 6: unknown org (UUID first, then slug).
        org = await find_organization(self.organization_repo, organization)
        if org is None:
            raise DelegationRefused(DelegationRefusal.UNKNOWN_ORGANIZATION)

        # Row 7: org not on this agent's list (no platform-org bypass).
        if org.id not in allowed_orgs:
            raise DelegationRefused(DelegationRefusal.ORGANIZATION_NOT_ALLOWED)

        # Row 8: target not provisioned — read-only lookup, never upsert.
        target = await self.user_repo.get_by_keycloak_sub(target_sub)
        if target is None:
            raise DelegationRefused(DelegationRefusal.TARGET_NOT_PROVISIONED)

        # Row 9: target not a member.
        try:
            ctx = await self.resolve_use_case.execute(target.id, org.id)
        except NotAMember as exc:
            raise DelegationRefused(DelegationRefusal.TARGET_NOT_A_MEMBER) from exc

        return replace(ctx, acted_by=caller.id)
