"""ResolveDelegatedAuthContextUseCase — auth:AD-1 rows 3–9, one test per matrix row."""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from uuid import uuid4

import pytest

from pkg_auth.authorization import (
    CatalogEntry,
    DelegationRefusal,
    DelegationRefused,
    NotAMember,
    OrgId,
    PermissionKey,
    RoleName,
    ServiceName,
    User,
    UserNotProvisioned,
)
from pkg_auth.authorization.adapters.cache import (
    CachedMembershipRepository,
    InMemoryTTLCache,
)
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from pkg_auth.authorization.application.use_cases.resolve_delegated_auth_context import (
    ResolveDelegatedAuthContextUseCase,
    normalize_delegators,
)

from .fakes import (
    FakeMembershipRepository,
    FakeOrganizationRepository,
    FakeOrganizationServiceRepository,
    FakePermissionCatalogRepository,
    FakeRoleRepository,
    FakeUserRepository,
)

AGENT_SUB = "service-account-admin-assistant"
TARGET_SUB = "target-user-sub"


# --------------------------------------------------------------------------- #
# Spies — record every call so "no lookup" / "no upsert" can be asserted.
# --------------------------------------------------------------------------- #


@dataclass
class SpyUserRepository:
    inner: FakeUserRepository
    calls: list[str] = field(default_factory=list)

    async def get_by_id(self, user_id):
        self.calls.append("get_by_id")
        return await self.inner.get_by_id(user_id)

    async def get_by_keycloak_sub(self, sub):
        self.calls.append("get_by_keycloak_sub")
        return await self.inner.get_by_keycloak_sub(sub)

    async def upsert_from_identity(self, **kwargs):
        self.calls.append("upsert_from_identity")
        return await self.inner.upsert_from_identity(**kwargs)


@dataclass
class SpyOrganizationRepository:
    inner: FakeOrganizationRepository
    calls: list[str] = field(default_factory=list)

    async def get(self, org_id):
        self.calls.append("get")
        return await self.inner.get(org_id)

    async def get_by_slug(self, slug):
        self.calls.append("get_by_slug")
        return await self.inner.get_by_slug(slug)


@dataclass
class SpyMembershipRepository:
    inner: object
    calls: list[str] = field(default_factory=list)

    async def load_auth_context(self, user_id, org_id):
        self.calls.append("load_auth_context")
        return await self.inner.load_auth_context(user_id, org_id)


@dataclass
class World:
    agent: User
    target: User
    org: object
    other_org: object
    platform_org: object
    users: SpyUserRepository
    orgs: SpyOrganizationRepository
    memberships: SpyMembershipRepository
    resolve: ResolveAuthContextUseCase

    def use_case(self, delegators=None) -> ResolveDelegatedAuthContextUseCase:
        return ResolveDelegatedAuthContextUseCase(
            resolve_use_case=self.resolve,
            user_repo=self.users,
            organization_repo=self.orgs,
            delegators=delegators,
        )

    def calls(self) -> list[str]:
        return self.users.calls + self.orgs.calls + self.memberships.calls


async def _world(*, guard: bool = False, enabled=("users", "courses")) -> World:
    users = FakeUserRepository()
    agent = await users.upsert_from_identity(sub=AGENT_SUB, email="a@x", full_name=None)
    target = await users.upsert_from_identity(sub=TARGET_SUB, email="t@x", full_name=None)

    orgs = FakeOrganizationRepository()
    org = await orgs.create(slug="acme", name="Acme")
    other_org = await orgs.create(slug="other", name="Other")
    platform_org = await orgs.create(slug="platform", name="Platform")

    catalog = FakePermissionCatalogRepository()
    await catalog.register_many(
        service_name="courses",
        entries=[CatalogEntry(PermissionKey("course:edit"), "Edit course")],
    )
    await catalog.register_many(
        service_name="users",
        entries=[CatalogEntry(PermissionKey("users:read"), "Read user")],
    )

    roles = FakeRoleRepository()
    editor = await roles.create(
        org_id=org.id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit"), PermissionKey("users:read")],
    )
    admin = await roles.create(
        org_id=org.id,
        name=RoleName("agent-role"),
        description=None,
        permission_keys=[PermissionKey("users:admin")],
    )
    inner = FakeMembershipRepository(role_repo=roles)
    await inner.upsert(user_id=target.id, org_id=org.id, role_id=editor.id, status="active")
    await inner.upsert(user_id=agent.id, org_id=org.id, role_id=admin.id, status="active")
    memberships = SpyMembershipRepository(inner=inner)

    org_services = FakeOrganizationServiceRepository()
    for svc in enabled:
        await org_services.enable(org.id, ServiceName(svc), source="manual")

    resolve = ResolveAuthContextUseCase(
        membership_repo=memberships,
        org_service_repo=org_services if guard else None,
        catalog_repo=catalog if guard else None,
        platform_org_id=platform_org.id,
    )
    return World(
        agent=agent,
        target=target,
        org=org,
        other_org=other_org,
        platform_org=platform_org,
        users=SpyUserRepository(inner=users),
        orgs=SpyOrganizationRepository(inner=orgs),
        memberships=memberships,
        resolve=resolve,
    )


def _allow(w: World, *orgs) -> dict:
    return {AGENT_SUB: [o.id for o in (orgs or (w.org,))]}


async def _refused(uc, reason, **kwargs):
    with pytest.raises(DelegationRefused) as exc:
        await uc.execute(**kwargs)
    assert exc.value.reason is reason
    assert not isinstance(exc.value, (NotAMember, UserNotProvisioned))
    return exc.value


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


async def test_happy_path_returns_target_ctx_with_acted_by():
    w = await _world()
    ctx = await w.use_case(_allow(w)).execute(
        caller=w.agent, on_behalf_of=[TARGET_SUB], organization=str(w.org.id)
    )
    assert ctx.user_id == w.target.id
    assert ctx.organization_id == w.org.id
    assert ctx.perms == frozenset({"course:edit", "users:read"})
    assert "users:admin" not in ctx.perms  # caller's perms never used
    assert ctx.acted_by == w.agent.id
    assert "upsert_from_identity" not in w.users.calls


async def test_org_resolved_by_slug():
    w = await _world()
    ctx = await w.use_case(_allow(w)).execute(
        caller=w.agent, on_behalf_of=[TARGET_SUB], organization="acme"
    )
    assert ctx.organization_id == w.org.id


async def test_delegated_perms_equal_targets_own_after_service_guard():
    w = await _world(guard=True, enabled=("users",))  # courses disabled
    own = await w.resolve.execute(w.target.id, w.org.id)
    ctx = await w.use_case(_allow(w)).execute(
        caller=w.agent, on_behalf_of=[TARGET_SUB], organization=str(w.org.id)
    )
    assert own.perms == frozenset({"users:read"})
    assert ctx.perms == own.perms
    assert ctx.role_names == own.role_names
    assert ctx.acted_by == w.agent.id


# --------------------------------------------------------------------------- #
# Refusals, in auth:AD-1 order
# --------------------------------------------------------------------------- #


async def test_repeated_is_refused_before_any_lookup_even_for_delegator():
    w = await _world()
    await _refused(
        w.use_case(_allow(w)),
        DelegationRefusal.REPEATED,
        caller=w.agent,
        on_behalf_of=[TARGET_SUB, TARGET_SUB],
        organization=str(w.org.id),
    )
    assert w.calls() == []


@pytest.mark.parametrize("value", [TARGET_SUB, "", "   "])
@pytest.mark.parametrize("delegators", [None, {}, {"someone-else": []}])
async def test_not_a_delegator_refused_without_touching_repos(value, delegators):
    w = await _world()
    await _refused(
        w.use_case(delegators),
        DelegationRefusal.NOT_A_DELEGATOR,
        caller=w.agent,
        on_behalf_of=[value],
        organization=str(w.org.id),
    )
    assert w.calls() == []


async def test_not_a_delegator_ranks_above_empty_value_and_unknown_org():
    w = await _world()
    await _refused(
        w.use_case({}),
        DelegationRefusal.NOT_A_DELEGATOR,
        caller=w.target,
        on_behalf_of=[""],
        organization="no-such-org",
    )
    assert w.calls() == []


@pytest.mark.parametrize("value", ["", "  ", "\t"])
async def test_empty_value_refused(value):
    w = await _world()
    await _refused(
        w.use_case(_allow(w)),
        DelegationRefusal.EMPTY_TARGET,
        caller=w.agent,
        on_behalf_of=[value],
        organization=str(w.org.id),
    )
    assert w.calls() == []


@pytest.mark.parametrize("org_ref", ["no-such-slug", str(uuid4())])
async def test_unknown_org_refused(org_ref):
    w = await _world()
    await _refused(
        w.use_case(_allow(w)),
        DelegationRefusal.UNKNOWN_ORGANIZATION,
        caller=w.agent,
        on_behalf_of=[TARGET_SUB],
        organization=org_ref,
    )
    assert w.users.calls == []


async def test_org_off_list_refused():
    w = await _world()
    await _refused(
        w.use_case(_allow(w)),
        DelegationRefusal.ORGANIZATION_NOT_ALLOWED,
        caller=w.agent,
        on_behalf_of=[TARGET_SUB],
        organization=str(w.other_org.id),
    )
    assert w.users.calls == []
    assert w.memberships.calls == []


async def test_platform_org_refused_unless_named():
    w = await _world()
    assert w.resolve.platform_org_id == w.platform_org.id
    await _refused(
        w.use_case(_allow(w)),
        DelegationRefusal.ORGANIZATION_NOT_ALLOWED,
        caller=w.agent,
        on_behalf_of=[TARGET_SUB],
        organization=str(w.platform_org.id),
    )
    assert w.users.calls == []
    assert w.memberships.calls == []


async def test_platform_org_passes_the_list_check_when_named():
    w = await _world()
    # Named, so it passes row 7; the target is not a platform member → row 9.
    await _refused(
        w.use_case(_allow(w, w.org, w.platform_org)),
        DelegationRefusal.TARGET_NOT_A_MEMBER,
        caller=w.agent,
        on_behalf_of=[TARGET_SUB],
        organization=str(w.platform_org.id),
    )


async def test_unprovisioned_target_refused_without_upsert():
    w = await _world()
    await _refused(
        w.use_case(_allow(w)),
        DelegationRefusal.TARGET_NOT_PROVISIONED,
        caller=w.agent,
        on_behalf_of=["never-seen-sub"],
        organization=str(w.org.id),
    )
    assert w.users.calls == ["get_by_keycloak_sub"]
    assert await w.users.inner.get_by_keycloak_sub("never-seen-sub") is None
    assert w.memberships.calls == []


async def test_target_outside_org_refused_never_callers_ctx():
    w = await _world()
    outsider = await w.users.inner.upsert_from_identity(
        sub="outsider", email="o@x", full_name=None
    )
    assert outsider is not None
    await _refused(
        w.use_case(_allow(w)),
        DelegationRefusal.TARGET_NOT_A_MEMBER,
        caller=w.agent,  # agent IS a member of org — must not fall back
        on_behalf_of=["outsider"],
        organization=str(w.org.id),
    )
    assert "upsert_from_identity" not in w.users.calls


@pytest.mark.parametrize(
    ("value", "error"), [(TARGET_SUB, TypeError), ([], ValueError)]
)
async def test_misused_on_behalf_of_fails_loudly_before_any_lookup(value, error):
    w = await _world()
    with pytest.raises(error):
        await w.use_case(_allow(w)).execute(
            caller=w.agent, on_behalf_of=value, organization=str(w.org.id)
        )
    assert w.calls() == []


# --------------------------------------------------------------------------- #
# Configuration / normalization
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("raw", [None, {}])
def test_no_config_yields_empty_read_only_map(raw):
    result = normalize_delegators(raw)
    assert isinstance(result, MappingProxyType)
    assert dict(result) == {}
    with pytest.raises(TypeError):
        result["x"] = frozenset()  # type: ignore[index]


def test_normalization_accepts_uuid_strings_uuids_and_org_ids():
    a, b, c = uuid4(), uuid4(), uuid4()
    result = normalize_delegators({"sub-1": [str(a), b, OrgId(c)]})
    assert isinstance(result, MappingProxyType)
    assert result["sub-1"] == frozenset({OrgId(a), OrgId(b), OrgId(c)})
    assert isinstance(result["sub-1"], frozenset)


def test_normalization_keeps_exact_sub():
    org = uuid4()
    result = normalize_delegators({"Sub-1": [org]})
    assert list(result) == ["Sub-1"]


async def test_sub_with_no_orgs_is_not_a_delegator():
    w = await _world()
    uc = w.use_case({AGENT_SUB: []})
    assert dict(uc.delegators) == {}
    await _refused(
        uc,
        DelegationRefusal.NOT_A_DELEGATOR,
        caller=w.agent,
        on_behalf_of=[TARGET_SUB],
        organization=str(w.org.id),
    )
    assert w.calls() == []


def test_normalized_map_is_detached_from_the_input():
    raw = {"sub-1": [uuid4()]}
    result = normalize_delegators(raw)
    raw["sub-2"] = []
    assert "sub-2" not in result


@pytest.mark.parametrize(
    "raw",
    [
        "sub-1",
        {"sub-1": str(uuid4())},
        {"": [str(uuid4())]},
        {"   ": [str(uuid4())]},
        {" sub-1 ": [str(uuid4())]},
        {"sub-1": ["not-a-uuid"]},
        {"sub-1": [42]},
        [("sub-1", [str(uuid4())])],
    ],
)
def test_bad_config_fails_construction(raw):
    with pytest.raises(ValueError):
        normalize_delegators(raw)
    with pytest.raises(ValueError):
        ResolveDelegatedAuthContextUseCase(
            resolve_use_case=ResolveAuthContextUseCase(
                membership_repo=FakeMembershipRepository()
            ),
            user_repo=FakeUserRepository(),
            organization_repo=FakeOrganizationRepository(),
            delegators=raw,
        )


async def test_use_case_normalizes_in_post_init():
    w = await _world()
    uc = w.use_case({AGENT_SUB: [str(w.org.id)]})
    assert isinstance(uc.delegators, MappingProxyType)
    assert uc.delegators[AGENT_SUB] == frozenset({w.org.id})


# --------------------------------------------------------------------------- #
# Shared cache never mixes the two principals
# --------------------------------------------------------------------------- #


async def test_shared_cache_never_carries_acted_by_or_crosses_perms():
    w = await _world()
    cache = InMemoryTTLCache()
    cached = CachedMembershipRepository(inner=w.memberships.inner, cache=cache)
    resolve = ResolveAuthContextUseCase(membership_repo=cached)
    uc = ResolveDelegatedAuthContextUseCase(
        resolve_use_case=resolve,
        user_repo=w.users,
        organization_repo=w.orgs,
        delegators=_allow(w),
    )

    agent_own_1 = await resolve.execute(w.agent.id, w.org.id)
    delegated = await uc.execute(
        caller=w.agent, on_behalf_of=[TARGET_SUB], organization=str(w.org.id)
    )
    target_own = await resolve.execute(w.target.id, w.org.id)
    agent_own_2 = await resolve.execute(w.agent.id, w.org.id)

    assert delegated.acted_by == w.agent.id
    assert delegated.perms == target_own.perms
    for ctx in (agent_own_1, target_own, agent_own_2):
        assert ctx.acted_by is None
    assert target_own.user_id == w.target.id
    assert target_own.perms == frozenset({"course:edit", "users:read"})
    assert agent_own_1.perms == agent_own_2.perms == frozenset({"users:admin"})

    agent_blob = await cache.get(f"auth_ctx:{w.agent.id}:{w.org.id}")
    target_blob = await cache.get(f"auth_ctx:{w.target.id}:{w.org.id}")
    assert agent_blob is not None and target_blob is not None
    assert set(cache._store) == {
        f"auth_ctx:{w.agent.id}:{w.org.id}",
        f"auth_ctx:{w.target.id}:{w.org.id}",
    }
    for blob in (agent_blob, target_blob):
        assert b"acted_by" not in blob
    assert b"users:admin" in agent_blob and b"course:edit" not in agent_blob
    assert b"course:edit" in target_blob and b"users:admin" not in target_blob
    assert str(w.agent.id).encode() not in target_blob
