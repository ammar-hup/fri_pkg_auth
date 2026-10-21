"""make_get_current_user — org-less ACL user, refuses X-On-Behalf-Of (auth:AD-1)."""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from pkg_auth.authentication import IdentityContext
from pkg_auth.authentication.domain.value_objects import EmailAddress, Subject
from pkg_auth.authorization import User
from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)
from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)
from pkg_auth.integrations.fastapi import ON_BEHALF_OF_HEADER, make_get_current_user
from tests.authorization.application.fakes import FakeUserRepository

KNOWN_SUB = "known-user-sub"
TEST_SUB_HEADER = "X-Test-Sub"


async def get_identity(request: Request) -> IdentityContext:
    sub = request.headers.get(TEST_SUB_HEADER)
    if sub is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    email = request.headers.get("X-Test-Email")
    return IdentityContext(
        subject=Subject(sub),
        email=None if email is None else EmailAddress(email),
        full_name=request.headers.get("X-Test-Name"),
    )


@dataclass
class Spy:
    inner: object
    calls: int = 0

    async def execute(self, **kwargs):
        self.calls += 1
        return await self.inner.execute(**kwargs)


@pytest.fixture
async def users() -> FakeUserRepository:
    repo = FakeUserRepository()
    await repo.upsert_from_identity(sub=KNOWN_SUB, email="k@x", full_name=None)
    return repo


def _client(users: FakeUserRepository, mode: str) -> tuple[TestClient, Spy]:
    if mode == "A":
        spy = Spy(SyncUserFromJwtUseCase(user_repo=users))
        dep = make_get_current_user(get_identity=get_identity, sync_user_use_case=spy)
    else:
        spy = Spy(ResolveUserFromJwtUseCase(user_repo=users))
        dep = make_get_current_user(get_identity=get_identity, resolve_user_use_case=spy)
    app = FastAPI()

    @app.get("/me")
    async def me(user: User = Depends(dep)):
        return {"id": str(user.id), "sub": user.keycloak_sub}

    return TestClient(app), spy


@pytest.mark.parametrize("mode", ["A", "B"])
@pytest.mark.parametrize("value", [KNOWN_SUB, "", "anything"])
async def test_header_present_is_refused_before_user_work(users, mode, value):
    client, spy = _client(users, mode)
    r = client.get(
        "/me", headers={TEST_SUB_HEADER: KNOWN_SUB, ON_BEHALF_OF_HEADER: value}
    )
    assert r.status_code == 403
    assert r.json() == {"detail": "X-On-Behalf-Of is not accepted here"}
    assert spy.calls == 0


async def test_header_present_mode_a_never_upserts_the_caller(users):
    client, spy = _client(users, "A")
    r = client.get(
        "/me", headers={TEST_SUB_HEADER: "brand-new-sub", ON_BEHALF_OF_HEADER: KNOWN_SUB}
    )
    assert r.status_code == 403
    assert spy.calls == 0
    assert await users.get_by_keycloak_sub("brand-new-sub") is None


async def test_no_header_mode_a_provisions_the_caller(users):
    client, _ = _client(users, "A")
    r = client.get("/me", headers={TEST_SUB_HEADER: "brand-new-sub"})
    assert r.status_code == 200
    created = await users.get_by_keycloak_sub("brand-new-sub")
    assert created is not None
    assert r.json() == {"id": str(created.id), "sub": "brand-new-sub"}


async def test_no_header_mode_a_passes_email_and_name_through(users):
    client, _ = _client(users, "A")
    r = client.get(
        "/me",
        headers={TEST_SUB_HEADER: "brand-new-sub", "X-Test-Email": "n@x.io", "X-Test-Name": "New User"},
    )
    assert r.status_code == 200
    created = await users.get_by_keycloak_sub("brand-new-sub")
    assert (str(created.email), created.full_name) == ("n@x.io", "New User")


@pytest.mark.parametrize("mode", ["A", "B"])
async def test_header_without_token_is_403_not_401(users, mode):
    client, spy = _client(users, mode)
    r = client.get("/me", headers={ON_BEHALF_OF_HEADER: KNOWN_SUB})
    assert r.status_code == 403
    assert spy.calls == 0


async def test_no_header_mode_b_returns_known_user(users):
    client, _ = _client(users, "B")
    r = client.get("/me", headers={TEST_SUB_HEADER: KNOWN_SUB})
    known = await users.get_by_keycloak_sub(KNOWN_SUB)
    assert r.status_code == 200
    assert r.json() == {"id": str(known.id), "sub": KNOWN_SUB}


async def test_no_header_mode_b_unprovisioned_is_403(users):
    client, _ = _client(users, "B")
    r = client.get("/me", headers={TEST_SUB_HEADER: "unknown-sub"})
    assert r.status_code == 403


@pytest.mark.parametrize("mode", ["A", "B"])
async def test_no_token_is_401_unchanged(users, mode):
    client, spy = _client(users, mode)
    r = client.get("/me")
    assert r.status_code == 401
    assert spy.calls == 0


def test_exactly_one_mode_is_required():
    users = FakeUserRepository()
    with pytest.raises(ValueError):
        make_get_current_user(get_identity=get_identity)
    with pytest.raises(ValueError):
        make_get_current_user(
            get_identity=get_identity,
            sync_user_use_case=SyncUserFromJwtUseCase(user_repo=users),
            resolve_user_use_case=ResolveUserFromJwtUseCase(user_repo=users),
        )
