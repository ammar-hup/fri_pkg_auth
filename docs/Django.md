# Django Integration

`pkg_auth` ships first-class Django support: an `AppConfig` with
`managed=False` mirror models for the central ACL schema, abstract
column mixins for services that want to extend the schema, async
middleware that resolves identity + organization context, and a
`@require_permission` view decorator. The same Keycloak JWT layer used
by FastAPI services is reused — Django doesn't have to know anything
about JWTs beyond mounting the middleware.

## Two integration modes

There are two ways a Django service can integrate.

### Mode A — Source-of-truth service (owns the schema)

The service owns the ACL tables and adds its own columns to one or
more of them (e.g. `itq_users` adds `username`, `bio`, `status` to
the `users` table). It subclasses the abstract mixins, declares its
own concrete models with `Meta.managed = True`, and runs its own
Django migrations. Typically one service in the fleet is the SoT.

### Mode B — Consuming service (read-only mirror)

The service shares the ACL database with the source-of-truth
service (e.g. `itq_users`). It does **not** own the ACL tables —
the SoT's migrations create them, and this service just reads them
via Django ORM mirror models with `Meta.managed = False`. This is
the default and simplest setup for any service that isn't the SoT.

Use Mode B unless your service is the source-of-truth for the ACL
tables.

## Setup (Mode B — consuming)

### 1. Install

```bash
pip install pkg-auth[acl-django,django]
```

### 2. Add to INSTALLED_APPS

```python
INSTALLED_APPS = [
    ...
    "pkg_auth.authorization.adapters.django_orm",  # managed=False mirror models
    "pkg_auth.integrations.django",                 # middleware + decorators
]
```

### 3. Wire at startup

In your project's `AppConfig.ready()`:

```python
from pkg_auth.integrations.django import install_pkg_auth
from pkg_auth.authorization.adapters.django_orm.repositories import (
    DjangoUserRepository,
    DjangoOrganizationRepository,
    DjangoMembershipRepository,
)
from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)

install_pkg_auth(
    keycloak_base_url="https://auth.example.com",
    realm="itqadem",
    audience="my-django-service",
    resolve_user_use_case=ResolveUserFromJwtUseCase(    # Mode B — reader
        user_repo=DjangoUserRepository(),
    ),
    resolve_use_case=ResolveAuthContextUseCase(
        membership_repo=DjangoMembershipRepository(),
    ),
    organization_repo=DjangoOrganizationRepository(),
)
```

A Mode B request whose Keycloak `sub` isn't mirrored into the shared
ACL yet produces **HTTP 403** — that's the signal the source-of-truth
service hasn't provisioned the user. Consumers never write in response.

Mode A (source-of-truth) services pass `sync_user_use_case=SyncUserFromJwtUseCase(...)`
instead — see [Setup (Mode A — source-of-truth, extending the schema)](#setup-mode-a--source-of-truth-extending-the-schema).
The two parameters are mutually exclusive; passing both (or neither)
raises `ValueError` at install time.

For platform-admin detection see [Platform admin pattern](#platform-admin-pattern)
below — pkg_auth ships a stateless helper rather than baking it into
the middleware.

#### Optional service guard

`ResolveAuthContextUseCase` accepts an optional **service guard**
(default-deny: resolved perms are filtered to the services the org has
enabled). Wire it by passing `org_service_repo`, `catalog_repo`, and
`platform_org_id` — the platform org bypasses the guard; leaving these unset
disables filtering:

```python
from pkg_auth.authorization.adapters.django_orm.repositories import (
    DjangoOrganizationServiceRepository,
    DjangoPermissionCatalogRepository,
)

resolve_use_case=ResolveAuthContextUseCase(
    membership_repo=DjangoMembershipRepository(),
    org_service_repo=DjangoOrganizationServiceRepository(),
    catalog_repo=DjangoPermissionCatalogRepository(),
    platform_org_id=platform_org_id,
)
```

Populate the service registry — each service self-registers its identity via
`pkg-auth-sync-catalog` and the vendor sets `auto_provision` / `saas_available`
flags via `pkg-auth-sync-services` — and wrap `org_service_repo` in
`CachedOrganizationServiceRepository` to cache the enabled-service set on the
guard hot path.

### 4. Add middleware (in order)

```python
MIDDLEWARE = [
    ...
    "pkg_auth.integrations.django.IdentityMiddleware",      # validates JWT
    "pkg_auth.integrations.django.AuthContextMiddleware",   # resolves org membership
    ...
]
```

`IdentityMiddleware` **must** come before `AuthContextMiddleware`. The
`AuthContextMiddleware` is async-only — your app must be served via
ASGI (`uvicorn`, `daphne`, or `python manage.py runserver` in async
mode).

### 5. Register your permission catalog (optional)

If your Django service publishes its own permissions to the central
catalog, register them on boot via the `CatalogEntry` shape:

```python
from pkg_auth.authorization import CatalogEntry, PermissionKey, PermissionVisibility
from pkg_auth.authorization.application.use_cases.register_permission_catalog import (
    RegisterPermissionCatalogUseCase,
)
from pkg_auth.authorization.adapters.django_orm.repositories import (
    DjangoPermissionCatalogRepository,
)

CATALOG: list[CatalogEntry] = [
    # Org-level perms — visibility defaults to PermissionVisibility.SHARED
    CatalogEntry(PermissionKey("courses:create"), "Create a new course"),
    CatalogEntry(PermissionKey("courses:edit"),   "Edit course content"),

    # Platform-only perm — hidden from tenant orgs, only meaningful at the
    # system level. The 3rd arg is the visibility ENUM (never a bool).
    CatalogEntry(
        PermissionKey("courses:moderate-globally"),
        "Cross-org course moderation",
        visibility=PermissionVisibility.PLATFORM_ONLY,
    ),

    # Tenant-only perm — hidden from the platform org.
    CatalogEntry(
        PermissionKey("courses:self-enroll"),
        "Enroll yourself in a course",
        visibility=PermissionVisibility.TENANT_ONLY,
    ),
]

# `description` accepts a plain str (coerced to LocalizedText using the default
# locale from ACL_DEFAULT_LOCALE), a {locale: text} dict, or a LocalizedText.

# Run once at startup, e.g. via a management command or AppConfig.ready()
async def register_catalog():
    await RegisterPermissionCatalogUseCase(
        catalog_repo=DjangoPermissionCatalogRepository(),
    ).execute(service_name="courses", entries=CATALOG)
```

## Protecting views

```python
from pkg_auth.integrations.django import require_permission
from django.http import JsonResponse

@require_permission("courses:edit")
async def edit_course(request, course_id):
    auth_ctx = request.auth_context
    return JsonResponse({
        "roles": sorted(auth_ctx.role_names),
        "user_id": str(auth_ctx.user_id),
    })
```

The decorator works for both sync and async views. Returns:

- `401` if `request.identity` is None (token missing/invalid)
- `400` if `X-Organization-Id` header is missing
- `403` if the named permission isn't granted

## The `AuthContext` object

`request.auth_context` is set by the middleware to one of:

- `None` — no `X-Organization-Id` header on the request
- An `AuthContext` instance — populated for protected routes

The shape:

```python
@dataclass(frozen=True, slots=True)
class AuthContext:
    user_id: UserId
    organization_id: OrgId
    role_names: frozenset[str]   # all active roles for this user in this org
    perms: frozenset[str]         # union of perms across all active roles

    def has(self, perm: str) -> bool: ...
    def require(self, perm: str) -> None: ...   # raises MissingPermission
    def has_role(self, role: str) -> bool: ...
```

A user can hold **multiple roles** in the same organization (multi-role
per org, since v1.3). `role_names` is the frozenset of all of them, and
`perms` is the union of all those roles' permissions.

`AuthContext` deliberately does **not** carry an `is_platform: bool`
flag. Platform-admin detection is a service-level concern — see the
next section.

### Platform admin pattern

A "platform" organization is one whose members are granted cross-org
administrative privileges by your service. There's nothing special
about its DB row — it's just an org you've designated via slug.

The pattern:

1. **Cache the platform org's id at startup.** Look it up by slug from
   your `OrganizationRepository`. Where the cache lives is your call —
   module global, app config, request scope.

   ```python
   # accounts/platform.py
   from pkg_auth.authorization import OrgId

   _platform_org_id: OrgId | None = None

   async def init_platform_org_id(org_repo) -> None:
       global _platform_org_id
       org = await org_repo.get_by_slug("platform")
       if org is not None:
           _platform_org_id = org.id

   def get_platform_org_id() -> OrgId | None:
       return _platform_org_id
   ```

2. **Platform admins send `X-Organization-Id: platform`** on their
   requests. The middleware resolves their membership in the platform
   org and builds an `AuthContext` whose `organization_id` is the
   platform org id.

3. **Handlers call the helper** to decide whether to broaden their
   filters:

   ```python
   from pkg_auth.authorization import is_platform_context
   from accounts.platform import get_platform_org_id

   @require_permission("users:read")
   async def list_users(request):
       auth_ctx = request.auth_context
       if is_platform_context(auth_ctx, get_platform_org_id()):
           users = User.objects.all()  # cross-org
       else:
           users = User.objects.filter(
               memberships__organization_id=auth_ctx.organization_id.value,
           )
       ...
   ```

The helper signature:

```python
def is_platform_context(
    auth_ctx: AuthContext, platform_org_id: OrgId | None,
) -> bool:
    """True if auth_ctx.organization_id == platform_org_id and the
    context holds at least one role (a roleless member is not an admin)."""
```

It returns `False` when `platform_org_id` is `None` (cache not yet
initialized, or no platform org in this service), so it's safe to
call early in the request lifecycle.

**Why a helper instead of a flag on `AuthContext`?** Two ways to ask
the same question (a field on the dataclass *and* a helper) creates
drift. The helper-based approach also keeps `pkg_auth` decoupled from
"what counts as a platform admin" — that's a service-level policy.

## Querying the ACL tables

The `managed = False` mirror models at
`pkg_auth.authorization.adapters.django_orm.models` let you query the
ACL tables with Django's ORM:

```python
from pkg_auth.authorization.adapters.django_orm.models import (
    User, Organization, Membership, Role, Permission,
)

# All orgs a user belongs to
async for org in Organization.objects.filter(
    memberships__user__keycloak_sub="kc-uuid-1",
).distinct():
    print(org.name)

# Roles in an org
async for role in Role.objects.filter(organization_id=org_id):
    print(role.name)
```

The schema is owned by Alembic (from the SQLAlchemy adapter). Django's
`makemigrations` will not generate migrations for these models.

## Setup (Mode A — source-of-truth, extending the schema)

If your Django service is the source-of-truth for the ACL tables and
needs to add columns to one or more of them (the `itq_users` pattern:
`username`, `bio`, `status` on `users`):

### 1. Subclass the abstract mixin

```python
# accounts/models.py
import uuid
from django.db import models
from pkg_auth.authorization.adapters.django_orm.mixins import UserMixin

class User(UserMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # UserMixin columns inherited automatically:
    #   keycloak_sub, email, full_name, first_seen_at, last_seen_at,
    #   created_at, updated_at
    username = models.CharField(max_length=255, unique=True)
    bio = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=32, default="active")

    class Meta:
        db_table = "users"
        app_label = "accounts"
```

The same pattern applies to `OrganizationMixin`, `RoleMixin`,
`PermissionMixin`, `MembershipMixin`. **Important**: import the mixin
from the explicit submodule (`...django_orm.mixins`) — the package
`__init__.py` does not re-export it because Django needs the apps
registry to be ready before model classes can be defined.

### 2. Inject your concrete models into the repos

```python
from accounts.models import User as MyUser
from pkg_auth.authorization.adapters.django_orm.repositories import (
    DjangoUserRepository,
)

user_repo = DjangoUserRepository(model=MyUser)
```

Each Django repo (`DjangoUserRepository`, `DjangoOrganizationRepository`,
`DjangoRoleRepository`, `DjangoMembershipRepository`,
`DjangoPermissionCatalogRepository`) has injectable model fields. Pass
your service's concrete subclasses and the repos will use them in all
queries — no monkey-patching, no fork.

### 3. Own the schema with Django migrations

In Mode A, your service runs `makemigrations` / `migrate` for the
ACL tables. The package's bundled Alembic migrations are a starting
point only — once you take ownership your Django migrations are the
authoritative source.

### 4. Wire `SyncUserFromJwtUseCase` (Mode A writer)

Mode A services are the only ones allowed to upsert on JWT sight.
Pass `sync_user_use_case` to `install_pkg_auth`:

```python
from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)

install_pkg_auth(
    ...,
    sync_user_use_case=SyncUserFromJwtUseCase(          # Mode A — writer
        user_repo=DjangoUserRepository(model=MyUser),
    ),
    ...,
)
```

`sync_user_use_case` and `resolve_user_use_case` are mutually
exclusive.

## Strawberry GraphQL services

Django services using Strawberry GraphQL (e.g. `itq_forms`) can layer
the same `pkg_auth` middleware underneath the GraphQL resolver and use
a small adapter to inject the resolved Django user into mutations. The
typical mutation stack:

```python
import strawberry
import strawberry_django
from accounts.models import User as DjangoUser

def with_django_user(resolver):
    """Inject the resolved Django user into a mutation resolver."""
    async def wrapper(self, info, *args, **kwargs):
        identity = info.context.request.identity   # set by IdentityMiddleware
        if identity is None:
            raise PermissionError("Not authenticated")
        django_user, _ = await DjangoUser.objects.aget_or_create(
            keycloak_sub=identity.subject_str,
            defaults={"email": identity.email_str or "", "username": identity.subject_str},
        )
        return await resolver(self, info, *args, django_user=django_user, **kwargs)
    return wrapper

def check_permission(perm: str):
    """Reject the mutation if the active org context lacks the perm."""
    def deco(resolver):
        async def wrapper(self, info, *args, **kwargs):
            auth_ctx = info.context.request.auth_context  # AuthContextMiddleware
            if auth_ctx is None or not auth_ctx.has(perm):
                raise PermissionError(f"Missing permission {perm!r}")
            return await resolver(self, info, *args, **kwargs)
        return wrapper
    return deco

@strawberry.type
class Mutation:
    @strawberry_django.mutation
    @with_django_user
    @check_permission("courses:create")
    async def create_course(self, info, input: CreateCourseInput, django_user=None):
        ...
```

For org scoping in queries, read `info.context.request.auth_context`
the same way views do. Filter by `auth_ctx.organization_id.value`
unless `is_platform_context(auth_ctx, get_platform_org_id())` returns
`True`, in which case the resolver should return cross-org results.

## Common gotchas

- **`AuthContextMiddleware requires async middleware chain`** — you're
  running under WSGI. Switch to ASGI (`uvicorn`, `daphne`, or
  `manage.py runserver` in async mode).
- **`AppRegistryNotReady`** when importing `mixins` — make sure you
  import from `...django_orm.mixins`, not from the package
  `__init__.py`. The package deliberately does NOT re-export the
  mixins for app-loading-order reasons.
- **`role_name` AttributeError** on `AuthContext` — that field was
  renamed to `role_names: frozenset[str]` in v1.3 (multi-role per
  org). Use `auth_ctx.role_names` or `auth_ctx.has_role("editor")`.
- **Permission catalog `visibility` column missing** — the `is_platform`
  boolean was replaced by a `visibility` column. Apply the bundled Alembic
  migrations: `pkg_auth_acl_0003` migrates `is_platform` → `visibility`
  (`platform_only` / `shared` / `tenant_only`); `pkg_auth_acl_0004` makes
  `description` JSONB (LocalizedText); `pkg_auth_acl_0005` adds the services
  tables. Run `alembic upgrade pkg_auth_acl@head` to get all of them.
- **Role permissions empty after `RoleRepository.create(...)`** —
  the consuming service must register its permission catalog
  *before* anyone calls `create()` with permission keys, otherwise
  the keys won't resolve to existing rows. Run
  `RegisterPermissionCatalogUseCase` at startup.
