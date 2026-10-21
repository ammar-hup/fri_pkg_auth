# FastAPI Integration

## Setup (Mode B — consumer, the common case)

Most services share the ACL database with a source-of-truth peer
(e.g. `itq_users`) and do **not** own the `users` table. Those services
must read through, never write: use `ResolveUserFromJwtUseCase`.

```python
from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from pkg_auth.integrations.fastapi import (
    create_authentication,
    make_get_auth_context,
    require_permission,
    install_exception_handlers,
)

# 1. Identity (Keycloak JWT)
auth = create_authentication(
    keycloak_base_url="https://auth.example.com",
    realm="itqadem",
    audience="courses-service",
)

# 2. Authorization context (composes identity + ACL lookup)
resolve_user = ResolveUserFromJwtUseCase(user_repo=user_repo)
resolve = ResolveAuthContextUseCase(membership_repo=membership_repo)
get_auth_context = make_get_auth_context(
    get_identity=auth.get_identity,
    resolve_user_use_case=resolve_user,       # Mode B — reader
    resolve_use_case=resolve,
    organization_repo=org_repo,
    header_name="X-Organization-Id",          # default
)

# 3. Exception handlers (optional — makes domain errors map to HTTP)
install_exception_handlers(app)
```

To enable the optional **service guard** (default-deny: resolved perms are
filtered to the services the org has enabled), construct `resolve` with the
extra repos — the platform org bypasses the guard:

```python
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)

resolve = ResolveAuthContextUseCase(
    membership_repo=membership_repo,
    org_service_repo=org_service_repo,   # e.g. SqlAlchemyOrganizationServiceRepository
    catalog_repo=catalog_repo,
    platform_org_id=platform_org_id,
)
```

Populate the service registry — each service self-registers its identity via
`pkg-auth-sync-catalog` and the vendor sets `auto_provision` / `saas_available`
flags via `pkg-auth-sync-services` — and wrap `org_service_repo` in
`CachedOrganizationServiceRepository` to cache the enabled-service set on the
guard hot path.

A Mode B request whose Keycloak `sub` hasn't been mirrored into the
local ACL yet raises `UserNotProvisioned` → **HTTP 403**. That's the
signal the source-of-truth service hasn't provisioned the user yet;
the consumer never writes in response.

## Setup (Mode A — source-of-truth service)

Only the service that owns the `users` schema (e.g. `itq_users`)
should upsert on JWT sight. Those services pass `sync_user_use_case`
instead — the two params are mutually exclusive.

```python
from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)

sync_user = SyncUserFromJwtUseCase(user_repo=user_repo)
get_auth_context = make_get_auth_context(
    get_identity=auth.get_identity,
    sync_user_use_case=sync_user,             # Mode A — writer
    resolve_use_case=resolve,
    organization_repo=org_repo,
)
```

Passing both (or neither) raises `ValueError` at factory-call time.

## Delegation (on behalf of)

*Since 3.2.0 — `auth:AD-1`, bound for adopters by `estate:AD-27`.*

An allowlisted agent (a Keycloak service account that is also an ACL user)
can call a service on a user's behalf by sending the target's Keycloak `sub`
in `X-On-Behalf-Of`. The request is then authorized with **exactly the
target's permissions** in the requested org, and only in the orgs on that
agent's list. The agent's own permissions are never used, alone or combined.

Wire it by passing a `ResolveDelegatedAuthContextUseCase` as `delegation`.
The allowlist comes from the service's own config:

```python
from pkg_auth.authorization.application.use_cases.resolve_delegated_auth_context import (
    ResolveDelegatedAuthContextUseCase,
)
from pkg_auth.integrations.fastapi import make_get_auth_context

# settings.auth_delegators: dict[str, list[str]] = {}   # default: empty
#   shape: {agent_keycloak_sub: [org_uuid, ...]}

delegation = ResolveDelegatedAuthContextUseCase(
    resolve_use_case=resolve,
    user_repo=user_repo,
    organization_repo=org_repo,
    delegators=settings.auth_delegators,
)
get_auth_context = make_get_auth_context(
    get_identity=auth.get_identity,
    resolve_user_use_case=resolve_user,   # or sync_user_use_case (Mode A)
    resolve_use_case=resolve,
    organization_repo=org_repo,
    delegation=delegation,
)
```

**Keep `delegators` empty.** It stays empty in every service until
`estate:AD-27`'s audit gate is met: the audit columns recording the caller
(an `estate:AD-24` amendment in `pkg_audit`) must exist first. Empty or unset
means nobody delegates, and every `X-On-Behalf-Of` gets 403.

`delegators` is normalized when the use case is built:

- keys are the agent's exact Keycloak `sub`, matched only against the
  verified token's `sub` (never a header, `azp` or clientId);
- values are org UUIDs (`OrgId`, `UUID` or UUID strings);
- a bare `str`, a blank or padded `sub`, or a non-UUID org raises `ValueError`;
- the platform org is refused unless an entry names it explicitly.

### What a delegated request returns

The dependency still returns `(IdentityContext, AuthContext)`:

- `IdentityContext` is the **caller's** verified token (the agent);
- `AuthContext` is the **target's** own context for that org — the same
  service guard and the same cache entry as a direct request by the target —
  with `acted_by` set to the caller's ACL user id.

`AuthContext.acted_by` is `None` on every non-delegated request. It is
attribution only and is never cached; `AuthContext.user_id` is the acting
principal.

### Order of checks

Checks run in `auth:AD-1`'s order; the first match wins. Rows 3–9 raise
`DelegationRefused` (from `pkg_auth.authorization`), whose `reason` is a
`DelegationRefusal`. A refusal never falls back to the caller's own context.

| # | Condition | Status | `DelegationRefusal` |
|---|---|---|---|
| 1 | Missing `X-Organization-Id` | 400 | — |
| 2 | Caller not resolved (bad token / not provisioned in Mode B) | 401 / 403 | — |
| 3 | `X-On-Behalf-Of` repeated | 400 | `REPEATED` |
| 4 | Header present (any value) and caller not in `delegators` | 403 | `NOT_A_DELEGATOR` |
| 5 | Empty value | 400 | `EMPTY_TARGET` |
| 6 | Org unknown | 404 | `UNKNOWN_ORGANIZATION` |
| 7 | Org not in this agent's list | 403 | `ORGANIZATION_NOT_ALLOWED` |
| 8 | Target not provisioned | 403 | `TARGET_NOT_PROVISIONED` |
| 9 | Target not a member of the org | 403 | `TARGET_NOT_A_MEMBER` |

Row 4 runs before any user, org or membership lookup. The target lookup is
read-only (`UserRepository.get_by_keycloak_sub`) in both modes: delegation
never creates a user.

Without `delegation`, `make_get_auth_context` refuses any `X-On-Behalf-Of`
with 403. So do `make_get_current_user`, the Strawberry context getter and
the Django `AuthContextMiddleware`, none of which can delegate.

### Rules for adopters (`estate:AD-27`)

- **Authorize and attribute ownership on `AuthContext.user_id`** — the
  target on a delegated request — never on `IdentityContext.subject`.
- **Keep `acted_by`.** A service wrapper or fallback that rebuilds an
  `AuthContext` must carry `acted_by` through (e.g. `dataclasses.replace`).
- **No fallback after `DelegationRefused`.** A platform-admin or other
  service-level fallback must not run when delegation was refused; let the
  refusal stand.
- **Never parse `X-On-Behalf-Of` yourself.** Only pkg_auth reads it; use
  `ON_BEHALF_OF_HEADER` from `pkg_auth.integrations.fastapi` if you need the
  name (e.g. for CORS allow-headers).
- **Use `make_get_current_user`, not `get_identity`, for the acting user** on
  org-less routes, so the header is refused instead of silently ignored.

## Org-less routes: `make_get_current_user`

For routes that need the caller's ACL `User` but no organization (no
`X-Organization-Id`), use `make_get_current_user` instead of reading
`get_identity` directly. It takes the same Mode A / Mode B choice:

```python
from pkg_auth.integrations.fastapi import make_get_current_user

get_current_user = make_get_current_user(
    get_identity=auth.get_identity,
    resolve_user_use_case=resolve_user,   # or sync_user_use_case (Mode A)
)

@router.get("/me")
async def me(user: User = Depends(get_current_user)):
    ...
```

It refuses `X-On-Behalf-Of` with 403 before the token is checked, returns
401 for a missing or invalid token, and 403 when the user is not provisioned
(Mode B). Passing both (or neither) use case raises `ValueError`.

## Protecting routes

### Via `require_permission`

```python
@router.get("/courses/{id}")
async def get_course(
    id: str,
    bundle: tuple[IdentityContext, AuthContext] = Depends(
        require_permission("course:view", get_auth_context=get_auth_context)
    ),
):
    identity, auth_ctx = bundle
    ...
```

### Via route-level dependencies

```python
@router.delete(
    "/courses/{id}",
    dependencies=[Depends(require_permission("course:delete", get_auth_context=get_auth_context))],
)
async def delete_course(id: str):
    ...
```

## Error mapping

| Condition | Status |
|---|---|
| No/invalid token | 401 |
| Missing `X-Organization-Id` | 400 |
| User not provisioned (Mode B) | 403 |
| User not a member | 403 |
| Permission missing | 403 |
| Unknown org | 404 |
| `X-On-Behalf-Of` where delegation is not wired (incl. `make_get_current_user`) | 403 |
| `X-On-Behalf-Of` repeated, or empty value | 400 |
| Delegation: caller not a delegator, org not allowed, target not provisioned or not a member | 403 |
| Delegation: unknown org | 404 |

## Reference example

See [`examples/itqadem_courses_app`](../examples/itqadem_courses_app) for the full wiring.
