# Service Token

A service that calls another service (the media library, for example) does so as
itself: it holds its own confidential Keycloak client and asks for a token with
the client-credentials grant. The callee sees the service as the token's `azp`.

`pkg_auth` fetches that token, caches it, and refreshes it before it expires.

## Configure

| Variable | Example |
|---|---|
| `KEYCLOAK_BASE_URL` | `http://hakeycloak.ha-identity.svc.cluster.local` |
| `KEYCLOAK_REALM` | `Itqadem` |
| `KEYCLOAK_CLIENT_ID` | `articles-api` |
| `KEYCLOAK_CLIENT_SECRET` | from the service's secret store, never the image |

The client must have **Service accounts** enabled and must not be bearer-only.
Which audiences its token carries is set on the Keycloak client (audience
mappers), not by the caller.

## Use

Create one provider per process, at startup:

```python
from pkg_auth.authentication.adapters.keycloak import ServiceTokenProvider

provider = ServiceTokenProvider.from_env()   # ValueError names any unset variable
```

With an `httpx` client, let the auth class handle it. It sends the token and, on a
401, fetches a fresh one and retries the request once:

```python
import httpx
from pkg_auth.authentication.adapters.keycloak import ServiceTokenAuth

client = httpx.AsyncClient(base_url=MEDIA_URL, auth=ServiceTokenAuth(provider))
```

With a client that takes a bearer string, ask for the token just before each call;
it is served from the cache until it nears expiry:

```python
media.set_token(await provider.aget_token())   # or provider.get_token() in sync code
```

`ServiceTokenError` (an `AuthenticationError`) means Keycloak refused the client
(the message carries Keycloak's reason, such as an invalid secret) or could not be
reached. The secret never appears in messages or in `repr`.

## Tuning

`ServiceTokenProvider(credentials, refresh_margin_seconds=30, timeout_seconds=10)`.
A token is refreshed `refresh_margin_seconds` before it expires, or at half its
lifetime when it is shorter than twice the margin.
