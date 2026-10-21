# pkg-auth

Clean-architecture **identity + ACL** for multi-framework Python services. Handles JWT authentication (via Keycloak) and database-backed authorization (users, organizations, roles, permissions, memberships) in a single package with first-class support for **FastAPI**, **Django**, and **Strawberry GraphQL**.

> **v3.0.0 is a breaking change.** The `permissions.is_platform` flag is replaced by a tri-state `visibility` enum (`platform_only`/`shared`/`tenant_only`); permission `description` is now a localized JSONB map; and a first-class **Service** model with a **default-deny service guard** is added. See [`docs/Upgrade-Service-Guard.md`](docs/Upgrade-Service-Guard.md) for the 3.0.0 upgrade guide. Earlier migrations: [`docs/MIGRATION_v1.md`](docs/MIGRATION_v1.md), [`docs/MIGRATION_v2.md`](docs/MIGRATION_v2.md).

## Install

```bash
# Core (identity only — no DB deps)
pip install pkg-auth

# With ACL + FastAPI (most common for fritill services)
pip install "pkg-auth[acl-sqlalchemy,fastapi]"

# With ACL + Django
pip install "pkg-auth[acl-django,django]"

# With optional Redis cache
pip install "pkg-auth[cache-redis]"

# Everything
pip install "pkg-auth[all]"
```

Available extras: `acl-sqlalchemy`, `acl-django`, `cache-redis`, `fastapi`, `django`, `strawberry`, `all`.

## Quickstart (FastAPI)

```python
from fastapi import Depends, FastAPI
from pkg_auth.authentication import IdentityContext
from pkg_auth.authorization import AuthContext
from pkg_auth.integrations.fastapi import (
    create_authentication,
    make_get_auth_context,
    require_permission,
)

# --- Wire authentication + authorization ---

auth = create_authentication(
    keycloak_base_url="https://auth.example.com",
    realm="fritill",
    audience="courses-service",
)

# Mode B (consumer — the common case): pass resolve_user_use_case.
# Mode A (source-of-truth): pass sync_user_use_case instead. Exactly
# one of the two is required; passing both raises ValueError.
get_auth_context = make_get_auth_context(
    get_identity=auth.get_identity,
    resolve_user_use_case=resolve_user,   # or: sync_user_use_case=sync_user (Mode A)
    resolve_use_case=resolve,
    organization_repo=org_repo,
)

app = FastAPI()

# --- Use in routes ---

@app.get("/courses/{id}")
async def get_course(
    id: str,
    bundle: tuple[IdentityContext, AuthContext] = Depends(
        require_permission("course:view", get_auth_context=get_auth_context)
    ),
):
    identity, auth_ctx = bundle
    return {"course_id": id, "roles": sorted(auth_ctx.role_names)}
```

See [`examples/itqadem_courses_app`](examples/itqadem_courses_app) for a complete working example.

## Features

- **Authentication** — Keycloak JWT validation producing an `IdentityContext`.
- **Service token** — a service's own Keycloak token (client credentials), cached and refreshed, for calling other services.
- **Authorization (ACL)** — database-backed users, organizations, roles, permissions, and memberships, resolved into a hot-path `AuthContext` (`role_names`, `perms`).
- **Permission visibility** — tri-state catalog visibility (`platform_only` / `shared` / `tenant_only`).
- **Localized descriptions** — permission descriptions stored as localized JSONB (`LocalizedText`, `ACL_DEFAULT_LOCALE`).
- **Services & service guard** — first-class `Service` / `OrganizationService` model with a **default-deny** service guard; the platform org bypasses it.
- **Mode A / Mode B** — be the source of truth for the `users` table, or consume a shared ACL read-only.
- **Integrations** — FastAPI, Django, and Strawberry GraphQL.
- **CLIs** — `keycloak-init-client`, `pkg-auth-sync-catalog`, `pkg-auth-sync-services`.

## Architecture

```
pkg_auth/
  authentication/             JWT validation → IdentityContext; the service's own token
  authorization/              Full ACL (users, orgs, roles, perms, memberships)
    domain/                   Pure entities, ports (Protocol), exceptions
    application/use_cases/    Business logic (use cases)
    adapters/
      sqlalchemy/             Canonical schema + Alembic migrations (0001–0005) + repos
      django_orm/             Mirror models (managed=False) + repos
      cache/                  InMemoryTTLCache / RedisCache + decorator
  integrations/
    fastapi/                  Deps + require_permission + exception handlers
    django/                   Middleware + decorators
    strawberry/               Context getter + permission classes
  admin/                      Keycloak admin client (user provisioning)
```

**Layering rules**: domain has zero external imports; application imports only domain; adapters import their framework; integrations import everything.

## Documentation

- [Authorization model](docs/Authorization.md) — schema, permission catalog, roles, memberships, service guard
- [Upgrade to the Service Guard (3.0.0)](docs/Upgrade-Service-Guard.md)
- [Caching](docs/Caching.md) — InMemoryTTLCache, RedisCache, invalidation contract
- [FastAPI Integration](docs/FastAPI.md)
- [Django Integration](docs/Django.md)
- [Strawberry Integration](docs/Strawberry.md)
- [Service Token](docs/Service-Token.md) — call another service as this service
- [Keycloak Admin](docs/Keycloak-Admin.md)
- [Migration v1](docs/MIGRATION_v1.md) · [Migration v2](docs/MIGRATION_v2.md)
