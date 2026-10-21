from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from pkg_auth.authentication import ServiceTokenError
from pkg_auth.authentication.adapters.keycloak import (
    ServiceCredentials,
    ServiceTokenAuth,
    ServiceTokenProvider,
)

TOKEN_URL = "https://kc.example/realms/Itqadem/protocol/openid-connect/token"
CREDS = ServiceCredentials(token_url=TOKEN_URL, client_id="articles-api", client_secret="s3cret")


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Keycloak:
    """Issues tok-1, tok-2, ... and records every token request."""

    def __init__(self, expires_in: int = 300, status: int = 200, body: object = None) -> None:
        self.expires_in = expires_in
        self.status = status
        self.body = body
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status != 200:
            return httpx.Response(self.status, json=self.body)
        return httpx.Response(
            200, json={"access_token": f"tok-{len(self.requests)}", "expires_in": self.expires_in}
        )


def provider(kc: Keycloak, clock: Clock | None = None) -> ServiceTokenProvider:
    return ServiceTokenProvider(
        CREDS,
        clock=clock or Clock(),
        transport=httpx.MockTransport(kc.handle),
        async_transport=httpx.MockTransport(kc.handle),
    )


def test_from_env_builds_the_realm_token_url() -> None:
    creds = ServiceCredentials.from_env(
        {
            "KEYCLOAK_BASE_URL": "https://kc.example/",
            "KEYCLOAK_REALM": "Itqadem",
            "KEYCLOAK_CLIENT_ID": "articles-api",
            "KEYCLOAK_CLIENT_SECRET": "s3cret",
        }
    )
    assert creds == CREDS


def test_from_env_names_every_missing_variable() -> None:
    with pytest.raises(ValueError) as exc:
        ServiceCredentials.from_env({"KEYCLOAK_BASE_URL": "https://kc.example", "KEYCLOAK_REALM": " "})
    message = str(exc.value)
    assert "KEYCLOAK_REALM" in message
    assert "KEYCLOAK_CLIENT_ID" in message
    assert "KEYCLOAK_CLIENT_SECRET" in message
    assert "KEYCLOAK_BASE_URL" not in message


def test_secret_never_appears_in_repr() -> None:
    assert "s3cret" not in repr(CREDS)


def test_sends_a_client_credentials_request() -> None:
    kc = Keycloak()
    assert provider(kc).get_token() == "tok-1"
    (request,) = kc.requests
    assert str(request.url) == TOKEN_URL
    assert parse_qs(request.content.decode()) == {
        "grant_type": ["client_credentials"],
        "client_id": ["articles-api"],
        "client_secret": ["s3cret"],
    }


def test_reuses_the_token_until_the_refresh_margin() -> None:
    kc, clock = Keycloak(expires_in=300), Clock()
    p = provider(kc, clock)
    assert p.get_token() == "tok-1"
    clock.now += 269
    assert p.get_token() == "tok-1"
    clock.now += 1
    assert p.get_token() == "tok-2"


def test_short_lived_token_refreshes_at_half_its_lifetime() -> None:
    kc, clock = Keycloak(expires_in=20), Clock()
    p = provider(kc, clock)
    p.get_token()
    clock.now += 9.9
    assert p.get_token() == "tok-1"
    clock.now += 0.1
    assert p.get_token() == "tok-2"


def test_invalidate_forces_a_new_token() -> None:
    kc = Keycloak()
    p = provider(kc)
    p.get_token()
    p.invalidate()
    assert p.get_token() == "tok-2"


def test_refusal_raises_with_keycloaks_reason_and_no_secret() -> None:
    kc = Keycloak(status=401, body={"error": "unauthorized_client", "error_description": "Invalid client secret"})
    with pytest.raises(ServiceTokenError) as exc:
        provider(kc).get_token()
    assert "articles-api" in str(exc.value)
    assert "Invalid client secret" in str(exc.value)
    assert "s3cret" not in str(exc.value)


def test_unreachable_keycloak_raises_service_token_error() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    p = ServiceTokenProvider(CREDS, transport=httpx.MockTransport(down))
    with pytest.raises(ServiceTokenError, match="could not reach Keycloak"):
        p.get_token()


def test_missing_access_token_raises() -> None:
    def empty(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"expires_in": 300})

    p = ServiceTokenProvider(CREDS, transport=httpx.MockTransport(empty))
    with pytest.raises(ServiceTokenError, match="no access_token"):
        p.get_token()


async def test_async_path_shares_the_cache() -> None:
    kc = Keycloak()
    p = provider(kc)
    assert await p.aget_token() == "tok-1"
    assert p.get_token() == "tok-1"
    assert len(kc.requests) == 1


def _api(seen: list[str], reject: set[str]) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        auth = request.headers["Authorization"]
        seen.append(auth)
        return httpx.Response(401 if auth in reject else 200)

    return httpx.MockTransport(handle)


def test_auth_sends_the_token_and_retries_once_on_401() -> None:
    p = provider(Keycloak())
    seen: list[str] = []
    with httpx.Client(auth=ServiceTokenAuth(p), transport=_api(seen, {"Bearer tok-1"})) as client:
        response = client.post("https://media.example/assets", json={"a": 1})
    assert response.status_code == 200
    assert seen == ["Bearer tok-1", "Bearer tok-2"]


def test_auth_does_not_retry_twice() -> None:
    p = provider(Keycloak())
    seen: list[str] = []
    reject = {"Bearer tok-1", "Bearer tok-2"}
    with httpx.Client(auth=ServiceTokenAuth(p), transport=_api(seen, reject)) as client:
        assert client.get("https://media.example/assets").status_code == 401
    assert len(seen) == 2


async def test_async_auth_retries_once_on_401() -> None:
    p = provider(Keycloak())
    seen: list[str] = []
    async with httpx.AsyncClient(auth=ServiceTokenAuth(p), transport=_api(seen, {"Bearer tok-1"})) as client:
        response = await client.get("https://media.example/assets")
    assert response.status_code == 200
    assert seen == ["Bearer tok-1", "Bearer tok-2"]
