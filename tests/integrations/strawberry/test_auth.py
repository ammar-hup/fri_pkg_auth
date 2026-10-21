"""Strawberry context getter refuses X-On-Behalf-Of (auth:AD-1 Coverage)."""
from __future__ import annotations

from dataclasses import dataclass

import pytest
import strawberry
from fastapi import FastAPI
from fastapi.testclient import TestClient
from strawberry.fastapi import GraphQLRouter
from starlette.requests import Request
from strawberry.types import Info

from pkg_auth.authentication import IdentityContext, InvalidTokenError
from pkg_auth.authentication.domain.value_objects import Subject
from pkg_auth.authorization import PermissionKey, RoleName
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)
from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)
from pkg_auth.integrations.fastapi import ON_BEHALF_OF_HEADER
from pkg_auth.integrations.strawberry.auth import make_context_getter
from tests.authorization.application.fakes import (
    FakeMembershipRepository,
    FakeOrganizationRepository,
    FakeRoleRepository,
    FakeUserRepository,
)

MEMBER_SUB = "member-sub"
ORG_HEADER = "X-Organization-Id"
QUERY = {"query": "{ whoami }"}


class StubAuthenticate:
    """Treats the bearer token as the subject; ``bad`` is an invalid token."""

    def execute(self, token: str) -> IdentityContext:
        if token == "bad":
            raise InvalidTokenError("bad token")
        return IdentityContext(subject=Subject(token))


@dataclass
class Spy:
    inner: object
    calls: int = 0

    async def execute(self, *args, **kwargs):
        self.calls += 1
        return await self.inner.execute(*args, **kwargs)


class SpyOrgs:
    def __init__(self, inner: FakeOrganizationRepository) -> None:
        self.inner = inner
        self.calls = 0

    async def get(self, org_id):
        self.calls += 1
        return await self.inner.get(org_id)

    async def get_by_slug(self, slug):
        self.calls += 1
        return await self.inner.get_by_slug(slug)


@strawberry.type
class Query:
    @strawberry.field
    def whoami(self, info: Info) -> str:
        ctx = info.context
        sub = None if ctx.identity is None else ctx.identity.subject_str
        perms = None if ctx.auth_context is None else sorted(ctx.auth_context.perms)
        return f"{sub}|{perms}"


@dataclass
class World:
    users: FakeUserRepository
    orgs: SpyOrgs
    org: object
    user_spy: Spy
    resolve_spy: Spy
    client: TestClient
    getter: object


async def _world(mode: str) -> World:
    users = FakeUserRepository()
    member = await users.upsert_from_identity(sub=MEMBER_SUB, email="m@x", full_name=None)
    raw_orgs = FakeOrganizationRepository()
    org = await raw_orgs.create(slug="acme", name="Acme")
    roles = FakeRoleRepository()
    role = await roles.create(
        org_id=org.id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit")],
    )
    memberships = FakeMembershipRepository(role_repo=roles)
    await memberships.upsert(user_id=member.id, org_id=org.id, role_id=role.id, status="active")

    orgs = SpyOrgs(raw_orgs)
    resolve_spy = Spy(ResolveAuthContextUseCase(membership_repo=memberships))
    if mode == "A":
        user_spy = Spy(SyncUserFromJwtUseCase(user_repo=users))
        kw = {"sync_user_use_case": user_spy}
    else:
        user_spy = Spy(ResolveUserFromJwtUseCase(user_repo=users))
        kw = {"resolve_user_use_case": user_spy}
    getter = make_context_getter(
        authenticate_use_case=StubAuthenticate(),
        resolve_use_case=resolve_spy,
        organization_repo=orgs,
        **kw,
    )
    app = FastAPI()
    app.include_router(
        GraphQLRouter(strawberry.Schema(query=Query), context_getter=getter),
        prefix="/graphql",
    )
    return World(users, orgs, org, user_spy, resolve_spy, TestClient(app), getter)


def _post(w: World, *, token=None, org=None, obo=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if org is not None:
        headers[ORG_HEADER] = str(org)
    if obo is not None:
        headers[ON_BEHALF_OF_HEADER] = obo
    return w.client.post("/graphql", json=QUERY, headers=headers)


@pytest.mark.parametrize("mode", ["A", "B"])
@pytest.mark.parametrize("token", [None, "bad", MEMBER_SUB, "brand-new-sub"])
@pytest.mark.parametrize("with_org", [False, True])
@pytest.mark.parametrize("obo", [MEMBER_SUB, ""])
async def test_header_present_is_403_before_user_work(mode, token, with_org, obo):
    w = await _world(mode)
    r = _post(w, token=token, org=w.org.id if with_org else None, obo=obo)
    assert r.status_code == 403
    assert r.json() == {"detail": "X-On-Behalf-Of is not accepted here"}
    assert w.user_spy.calls == 0
    assert w.resolve_spy.calls == 0
    assert w.orgs.calls == 0
    assert await w.users.get_by_keycloak_sub("brand-new-sub") is None


def _request(*, token=None, org=None) -> Request:
    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    if org is not None:
        headers.append((ORG_HEADER.lower().encode(), str(org).encode()))
    return Request({"type": "http", "method": "POST", "path": "/graphql", "headers": headers})


# The no-header rows call the getter directly: StrawberryContext is neither a
# BaseContext nor a dict, so services adapt it before handing it to the router.


@pytest.mark.parametrize("mode", ["A", "B"])
async def test_no_header_resolves_identity_and_context(mode):
    w = await _world(mode)
    ctx = await w.getter(_request(token=MEMBER_SUB, org=w.org.id))
    assert ctx.identity.subject_str == MEMBER_SUB
    assert sorted(ctx.auth_context.perms) == ["course:edit"]


@pytest.mark.parametrize("mode", ["A", "B"])
async def test_no_header_without_org_degrades_to_none(mode):
    w = await _world(mode)
    ctx = await w.getter(_request(token=MEMBER_SUB))
    assert ctx.identity.subject_str == MEMBER_SUB
    assert ctx.auth_context is None
    assert w.user_spy.calls == 0


async def test_no_header_anonymous_degrades_to_none():
    w = await _world("A")
    ctx = await w.getter(_request(token="bad", org=w.org.id))
    assert ctx.identity is None
    assert ctx.auth_context is None
