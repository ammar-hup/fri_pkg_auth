"""This service's own Keycloak token (client-credentials grant), for calling other services."""
from __future__ import annotations

import asyncio
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Callable, Generator, Mapping, Optional, Tuple

import httpx

from ...domain.exceptions import ServiceTokenError

_ENV_NAMES = (
    "KEYCLOAK_BASE_URL",
    "KEYCLOAK_REALM",
    "KEYCLOAK_CLIENT_ID",
    "KEYCLOAK_CLIENT_SECRET",
)


@dataclass(frozen=True)
class ServiceCredentials:
    """Where and as whom a service asks Keycloak for its own token."""

    token_url: str
    client_id: str
    client_secret: str = field(repr=False)

    @classmethod
    def for_realm(
        cls, *, base_url: str, realm: str, client_id: str, client_secret: str
    ) -> "ServiceCredentials":
        token_url = f"{base_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token"
        return cls(token_url=token_url, client_id=client_id, client_secret=client_secret)

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "ServiceCredentials":
        """Read ``KEYCLOAK_BASE_URL``, ``KEYCLOAK_REALM``, ``KEYCLOAK_CLIENT_ID``
        and ``KEYCLOAK_CLIENT_SECRET``; raise ``ValueError`` naming every one unset."""
        env = os.environ if environ is None else environ
        values = {name: (env.get(name) or "").strip() for name in _ENV_NAMES}
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise ValueError(f"service token needs {', '.join(missing)}")
        return cls.for_realm(
            base_url=values["KEYCLOAK_BASE_URL"],
            realm=values["KEYCLOAK_REALM"],
            client_id=values["KEYCLOAK_CLIENT_ID"],
            client_secret=values["KEYCLOAK_CLIENT_SECRET"],
        )


class ServiceTokenProvider:
    """Fetches, caches and refreshes this service's token.

    One instance per process, shared by sync and async callers. A cached
    token is reused until ``refresh_margin_seconds`` before it expires (or
    half its lifetime, for tokens shorter than twice the margin), so a call
    never goes out with a token that dies in flight.
    """

    def __init__(
        self,
        credentials: ServiceCredentials,
        *,
        refresh_margin_seconds: float = 30.0,
        timeout_seconds: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
        transport: Optional[httpx.BaseTransport] = None,
        async_transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self._credentials = credentials
        self._margin = refresh_margin_seconds
        self._timeout = timeout_seconds
        self._clock = clock
        self._transport = transport
        self._async_transport = async_transport

        self._token: Optional[str] = None
        self._refresh_at = 0.0
        self._sync_lock = threading.Lock()
        self._async_lock: Optional[asyncio.Lock] = None

    @classmethod
    def from_env(
        cls, environ: Optional[Mapping[str, str]] = None, **kwargs: Any
    ) -> "ServiceTokenProvider":
        return cls(ServiceCredentials.from_env(environ), **kwargs)

    @property
    def client_id(self) -> str:
        return self._credentials.client_id

    def get_token(self) -> str:
        token = self._cached()
        if token is not None:
            return token
        with self._sync_lock:
            token = self._cached()
            if token is not None:
                return token
            with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                try:
                    response = client.post(**self._request())
                except httpx.HTTPError as exc:
                    raise self._unreachable(exc) from exc
            return self._store(response)

    async def aget_token(self) -> str:
        token = self._cached()
        if token is not None:
            return token
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        async with self._async_lock:
            token = self._cached()
            if token is not None:
                return token
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._async_transport
            ) as client:
                try:
                    response = await client.post(**self._request())
                except httpx.HTTPError as exc:
                    raise self._unreachable(exc) from exc
            return self._store(response)

    def invalidate(self) -> None:
        """Drop the cached token; the next call fetches a new one."""
        self._token = None
        self._refresh_at = 0.0

    def _cached(self) -> Optional[str]:
        token = self._token
        if token is not None and self._clock() < self._refresh_at:
            return token
        return None

    def _request(self) -> dict[str, Any]:
        return {
            "url": self._credentials.token_url,
            "data": {
                "grant_type": "client_credentials",
                "client_id": self._credentials.client_id,
                "client_secret": self._credentials.client_secret,
            },
        }

    def _unreachable(self, exc: Exception) -> ServiceTokenError:
        return ServiceTokenError(
            f"could not reach Keycloak for client {self._credentials.client_id!r}: {exc}"
        )

    def _store(self, response: httpx.Response) -> str:
        token, expires_in = self._parse(response)
        lifetime = max(float(expires_in), 0.0)
        self._token = token
        self._refresh_at = self._clock() + lifetime - min(self._margin, lifetime / 2)
        return token

    def _parse(self, response: httpx.Response) -> Tuple[str, Any]:
        client_id = self._credentials.client_id
        try:
            body = response.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        if response.status_code != 200:
            reason = body.get("error_description") or body.get("error") or response.text[:200]
            raise ServiceTokenError(
                f"Keycloak refused a token for client {client_id!r}: "
                f"HTTP {response.status_code} {reason}"
            )
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise ServiceTokenError(f"Keycloak returned no access_token for client {client_id!r}")
        return token, body.get("expires_in", 60)


class ServiceTokenAuth(httpx.Auth):
    """``httpx`` auth that sends the service token and, on a 401, fetches a
    fresh one and retries once (the cached token may have been revoked)."""

    requires_request_body = True

    def __init__(self, provider: ServiceTokenProvider) -> None:
        self._provider = provider

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self._provider.get_token()}"
        response = yield request
        if response.status_code == 401:
            self._provider.invalidate()
            request.headers["Authorization"] = f"Bearer {self._provider.get_token()}"
            yield request

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        request.headers["Authorization"] = f"Bearer {await self._provider.aget_token()}"
        response = yield request
        if response.status_code == 401:
            self._provider.invalidate()
            request.headers["Authorization"] = f"Bearer {await self._provider.aget_token()}"
            yield request
