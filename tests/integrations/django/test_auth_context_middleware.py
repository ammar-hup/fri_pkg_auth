"""Django AuthContextMiddleware refuses X-On-Behalf-Of (auth:AD-1 Coverage)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from asgiref.sync import markcoroutinefunction
from django.conf import settings

if not settings.configured:
    settings.configure(DEFAULT_CHARSET="utf-8", ALLOWED_HOSTS=["*"])

from django.http import HttpResponse  # noqa: E402
from django.test import RequestFactory  # noqa: E402

from pkg_auth.authentication import IdentityContext  # noqa: E402
from pkg_auth.authentication.domain.value_objects import Subject  # noqa: E402
from pkg_auth.authorization import PermissionKey, RoleName  # noqa: E402
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (  # noqa: E402
    ResolveAuthContextUseCase,
)
from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import (  # noqa: E402
    ResolveUserFromJwtUseCase,
)
from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import (  # noqa: E402
    SyncUserFromJwtUseCase,
)
from pkg_auth.integrations.django import auth_context_middleware  # noqa: E402
from pkg_auth.integrations.django.auth_context_middleware import (  # noqa: E402
    AuthContextMiddleware,
)
from tests.authorization.application.fakes import (  # noqa: E402
    FakeMembershipRepository,
    FakeOrganizationRepository,
    FakeRoleRepository,
    FakeUserRepository,
)

MEMBER_SUB = "member-sub"
ORG_HEADER = "X-Organization-Id"
OBO_META = "HTTP_X_ON_BEHALF_OF"
ORG_META = "HTTP_X_ORGANIZATION_ID"


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


class GetResponseSpy:
    def __init__(self) -> None:
        self.calls = 0
        self.seen = None
        markcoroutinefunction(self)

    async def __call__(self, request):
        self.calls += 1
        self.seen = request
        return HttpResponse("ok")


@dataclass
class World:
    users: FakeUserRepository
    orgs: SpyOrgs
    org: object
    user_spy: Spy
    resolve_spy: Spy
    get_response: GetResponseSpy
    middleware: AuthContextMiddleware


@pytest.fixture(params=["A", "B"])
async def w(request, monkeypatch) -> World:
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
    if request.param == "A":
        user_spy = Spy(SyncUserFromJwtUseCase(user_repo=users))
        sync_user, resolve_user = user_spy, None
    else:
        user_spy = Spy(ResolveUserFromJwtUseCase(user_repo=users))
        sync_user, resolve_user = None, user_spy
    registry = SimpleNamespace(
        header_name=ORG_HEADER,
        sync_user=sync_user,
        resolve_user=resolve_user,
        organization_repo=orgs,
        resolve_auth=resolve_spy,
    )
    monkeypatch.setattr(auth_context_middleware, "get_registry", lambda: registry)
    get_response = GetResponseSpy()
    return World(
        users, orgs, org, user_spy, resolve_spy, get_response,
        AuthContextMiddleware(get_response),
    )


def _request(*, sub=None, org=None, obo=None):
    meta = {}
    if org is not None:
        meta[ORG_META] = str(org)
    if obo is not None:
        meta[OBO_META] = obo
    req = RequestFactory().get("/", **meta)
    req.identity = None if sub is None else IdentityContext(subject=Subject(sub))
    return req


@pytest.mark.parametrize("sub", [None, MEMBER_SUB, "brand-new-sub"])
@pytest.mark.parametrize("with_org", [False, True])
@pytest.mark.parametrize("obo", [MEMBER_SUB, ""])
async def test_header_present_is_403_and_never_passes_through(w, sub, with_org, obo):
    request = _request(sub=sub, org=w.org.id if with_org else None, obo=obo)
    r = await w.middleware(request)
    assert r.status_code == 403
    assert request.auth_context is None
    assert json.loads(r.content) == {"detail": "X-On-Behalf-Of is not accepted here"}
    assert w.get_response.calls == 0
    assert w.user_spy.calls == 0
    assert w.resolve_spy.calls == 0
    assert w.orgs.calls == 0
    assert await w.users.get_by_keycloak_sub("brand-new-sub") is None


async def test_no_header_without_org_passes_through_with_none(w):
    r = await w.middleware(_request(sub=MEMBER_SUB))
    assert r.status_code == 200
    assert w.get_response.calls == 1
    assert w.get_response.seen.auth_context is None
    assert w.user_spy.calls == 0


async def test_no_header_with_org_resolves(w):
    r = await w.middleware(_request(sub=MEMBER_SUB, org=w.org.id))
    assert r.status_code == 200
    assert w.get_response.calls == 1
    assert sorted(w.get_response.seen.auth_context.perms) == ["course:edit"]


async def test_no_header_with_org_and_no_identity_is_401(w):
    r = await w.middleware(_request(org=w.org.id))
    assert r.status_code == 401
    assert w.get_response.calls == 0
