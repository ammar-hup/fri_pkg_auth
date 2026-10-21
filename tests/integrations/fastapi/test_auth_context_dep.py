"""make_get_auth_context and X-On-Behalf-Of — auth:AD-1 order through a TestClient."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from pkg_auth.authentication import IdentityContext
from pkg_auth.authentication.domain.value_objects import Subject
from pkg_auth.authorization import PermissionKey, RoleName, User
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from pkg_auth.authorization.application.use_cases.resolve_delegated_auth_context import (
    ResolveDelegatedAuthContextUseCase,
)
from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)
from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)
from pkg_auth.integrations.fastapi.auth_context_dep import (
    ON_BEHALF_OF_HEADER,
    make_get_auth_context,
)
from tests.authorization.application.fakes import (
    FakeMembershipRepository,
    FakeOrganizationRepository,
    FakeRoleRepository,
    FakeUserRepository,
)

AGENT_SUB = "service-account-admin-assistant"
TARGET_SUB = "target-user-sub"
OUTSIDER_SUB = "outsider-user-sub"
TEST_SUB_HEADER = "X-Test-Sub"
ORG_HEADER = "X-Organization-Id"


async def get_identity(request: Request) -> IdentityContext:
    return IdentityContext(subject=Subject(request.headers[TEST_SUB_HEADER]))


@dataclass
class SpyDelegation:
    inner: ResolveDelegatedAuthContextUseCase
    calls: int = 0

    async def execute(self, **kwargs):
        self.calls += 1
        return await self.inner.execute(**kwargs)


@dataclass
class World:
    agent: User
    target: User
    outsider: User
    org: object
    other_org: object
    users: FakeUserRepository
    orgs: FakeOrganizationRepository
    resolve: ResolveAuthContextUseCase
    spies: list[SpyDelegation] = field(default_factory=list)

    def delegation(self, *orgs) -> SpyDelegation:
        spy = SpyDelegation(
            ResolveDelegatedAuthContextUseCase(
                resolve_use_case=self.resolve,
                user_repo=self.users,
                organization_repo=self.orgs,
                delegators={AGENT_SUB: [o.id for o in (orgs or (self.org,))]},
            )
        )
        self.spies.append(spy)
        return spy

    def client(self, *, mode: str = "A", delegation=None) -> TestClient:
        modes = {
            "A": {"sync_user_use_case": SyncUserFromJwtUseCase(user_repo=self.users)},
            "B": {"resolve_user_use_case": ResolveUserFromJwtUseCase(user_repo=self.users)},
        }
        dep = make_get_auth_context(
            get_identity=get_identity,
            resolve_use_case=self.resolve,
            organization_repo=self.orgs,
            delegation=delegation,
            **modes[mode],
        )
        app = FastAPI()

        @app.get("/whoami")
        async def whoami(pair=Depends(dep)):
            identity, ctx = pair
            return {
                "sub": identity.subject_str,
                "user_id": str(ctx.user_id),
                "perms": sorted(ctx.perms),
                "acted_by": None if ctx.acted_by is None else str(ctx.acted_by),
            }

        return TestClient(app)


async def _build() -> World:
    users = FakeUserRepository()
    agent = await users.upsert_from_identity(sub=AGENT_SUB, email="a@x", full_name=None)
    target = await users.upsert_from_identity(sub=TARGET_SUB, email="t@x", full_name=None)
    outsider = await users.upsert_from_identity(sub=OUTSIDER_SUB, email="o@x", full_name=None)

    orgs = FakeOrganizationRepository()
    org = await orgs.create(slug="acme", name="Acme")
    other_org = await orgs.create(slug="other", name="Other")

    roles = FakeRoleRepository()
    editor = await roles.create(
        org_id=org.id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit"), PermissionKey("users:read")],
    )
    agent_role = await roles.create(
        org_id=org.id,
        name=RoleName("agent-role"),
        description=None,
        permission_keys=[PermissionKey("users:admin")],
    )
    other_role = await roles.create(
        org_id=other_org.id,
        name=RoleName("viewer"),
        description=None,
        permission_keys=[PermissionKey("users:read")],
    )
    memberships = FakeMembershipRepository(role_repo=roles)
    await memberships.upsert(user_id=target.id, org_id=org.id, role_id=editor.id, status="active")
    await memberships.upsert(user_id=agent.id, org_id=org.id, role_id=agent_role.id, status="active")
    await memberships.upsert(
        user_id=outsider.id, org_id=other_org.id, role_id=other_role.id, status="active"
    )

    return World(
        agent=agent,
        target=target,
        outsider=outsider,
        org=org,
        other_org=other_org,
        users=users,
        orgs=orgs,
        resolve=ResolveAuthContextUseCase(membership_repo=memberships),
    )


@pytest.fixture
def w() -> World:
    return asyncio.run(_build())


def _get(client: TestClient, *, sub=AGENT_SUB, org=None, obo=()):
    headers = [(TEST_SUB_HEADER, sub)]
    if org is not None:
        headers.append((ORG_HEADER, str(org)))
    headers += [(ON_BEHALF_OF_HEADER, v) for v in obo]
    return client.get("/whoami", headers=headers)


# --------------------------------------------------------------------------- #
# Without the header — unchanged from 3.1.0
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("mode", ["A", "B"])
@pytest.mark.parametrize("with_delegation", [False, True])
def test_no_header_returns_callers_own_ctx(w, mode, with_delegation):
    delegation = w.delegation() if with_delegation else None
    r = _get(w.client(mode=mode, delegation=delegation), sub=TARGET_SUB, org=w.org.id)
    assert r.status_code == 200
    assert r.json() == {
        "sub": TARGET_SUB,
        "user_id": str(w.target.id),
        "perms": ["course:edit", "users:read"],
        "acted_by": None,
    }
    assert all(s.calls == 0 for s in w.spies)


def test_no_header_mode_a_provisions_a_new_caller(w):
    r = _get(w.client(mode="A"), sub="brand-new-sub", org=w.org.id)
    assert r.status_code == 403  # synced, but not a member
    assert asyncio.run(w.users.get_by_keycloak_sub("brand-new-sub")) is not None


def test_no_header_slug_still_resolves(w):
    r = _get(w.client(), sub=TARGET_SUB, org="acme")
    assert r.status_code == 200
    assert r.json()["user_id"] == str(w.target.id)


# --------------------------------------------------------------------------- #
# With the header — auth:AD-1 order, first match wins
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("mode", ["A", "B"])
@pytest.mark.parametrize("value", [TARGET_SUB, ""])
def test_header_without_delegation_is_403(w, mode, value):
    r = _get(w.client(mode=mode), org=w.org.id, obo=[value])
    assert r.status_code == 403
    assert r.json()["detail"] == f"{ON_BEHALF_OF_HEADER} is not accepted here"


def test_org_header_missing_is_400(w):
    d = w.delegation()
    r = _get(w.client(delegation=d), obo=[TARGET_SUB])
    assert r.status_code == 400
    assert d.calls == 0


def test_mode_b_agent_without_acl_row_is_403_before_delegation(w):
    d = SpyDelegation(
        ResolveDelegatedAuthContextUseCase(
            resolve_use_case=w.resolve,
            user_repo=w.users,
            organization_repo=w.orgs,
            delegators={"ghost-agent": [w.org.id]},
        )
    )
    r = _get(w.client(mode="B", delegation=d), sub="ghost-agent", org=w.org.id, obo=[TARGET_SUB])
    assert r.status_code == 403
    assert d.calls == 0


def test_repeated_header_is_400(w):
    r = _get(w.client(delegation=w.delegation()), org=w.org.id, obo=[TARGET_SUB, TARGET_SUB])
    assert r.status_code == 400
    assert r.json()["detail"].endswith("repeated")


def test_repeated_header_differing_only_in_case_is_400(w):
    headers = [
        (TEST_SUB_HEADER, AGENT_SUB),
        (ORG_HEADER, str(w.org.id)),
        (ON_BEHALF_OF_HEADER, TARGET_SUB),
        (ON_BEHALF_OF_HEADER.lower(), TARGET_SUB),
    ]
    r = w.client(delegation=w.delegation()).get("/whoami", headers=headers)
    assert r.status_code == 400
    assert r.json()["detail"].endswith("repeated")


@pytest.mark.parametrize("value", [TARGET_SUB, "", "anything"])
def test_caller_not_a_delegator_is_403(w, value):
    r = _get(w.client(delegation=w.delegation()), sub=TARGET_SUB, org=w.org.id, obo=[value])
    assert r.status_code == 403
    assert r.json()["detail"].endswith("not_a_delegator")


def test_empty_value_from_delegator_is_400(w):
    r = _get(w.client(delegation=w.delegation()), org=w.org.id, obo=[""])
    assert r.status_code == 400
    assert r.json()["detail"].endswith("empty_target")


@pytest.mark.parametrize("org", ["no-such-slug", str(uuid4())])
def test_unknown_org_is_404(w, org):
    r = _get(w.client(delegation=w.delegation()), org=org, obo=[TARGET_SUB])
    assert r.status_code == 404
    assert r.json()["detail"].endswith("unknown_organization")


def test_org_off_the_agents_list_is_403(w):
    r = _get(w.client(delegation=w.delegation(w.org)), org=w.other_org.id, obo=[OUTSIDER_SUB])
    assert r.status_code == 403
    assert r.json()["detail"].endswith("organization_not_allowed")


@pytest.mark.parametrize("mode", ["A", "B"])
def test_target_not_provisioned_is_403_and_never_created(w, mode):
    r = _get(w.client(mode=mode, delegation=w.delegation()), org=w.org.id, obo=["unknown-sub"])
    assert r.status_code == 403
    assert r.json()["detail"].endswith("target_not_provisioned")
    assert asyncio.run(w.users.get_by_keycloak_sub("unknown-sub")) is None


def test_target_not_a_member_is_403_never_the_agents_ctx(w):
    r = _get(w.client(delegation=w.delegation()), org=w.org.id, obo=[OUTSIDER_SUB])
    assert r.status_code == 403
    assert r.json() == {"detail": "delegation refused: target_not_a_member"}


@pytest.mark.parametrize("mode", ["A", "B"])
@pytest.mark.parametrize("org_by", ["id", "slug"])
def test_happy_path_returns_targets_ctx_with_acted_by(w, mode, org_by):
    org = w.org.id if org_by == "id" else w.org.slug
    r = _get(w.client(mode=mode, delegation=w.delegation()), org=org, obo=[TARGET_SUB])
    assert r.status_code == 200
    body = r.json()
    assert body["sub"] == AGENT_SUB
    assert body["user_id"] == str(w.target.id)
    assert body["perms"] == ["course:edit", "users:read"]
    assert "users:admin" not in body["perms"]
    assert body["acted_by"] == str(w.agent.id)
