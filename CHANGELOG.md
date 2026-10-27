# Changelog

All notable changes to `pkg-auth` are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [3.4.0] — Unreleased

Roleless memberships (`auth:AD-2`, `users:AD-8`, `estate:AD-29`): a
`memberships` row with `role_id` NULL is a **member with no role**. This
release only reads such rows; pkg_auth never writes one.

### Changed — breaking

- **Type: `Membership.role_id` is now `RoleId | None` and
  `Membership.role_name` is now `RoleName | None`.** Both are `None` for a
  roleless row. Code that reads `membership.role_name` (or `role_id`) must
  handle `None`.
- **Behaviour: `is_platform_context` returns `False` for a roleless platform
  context.** It is true only when the context is in the platform
  organization **and** holds at least one role; a roleless member of the
  platform organization is not a platform admin.

### Changed

- **Roleless read semantics, both adapters** (SQLAlchemy and Django ORM):
  `load_auth_context` returns an `AuthContext` for a user whose only active
  row is roleless, with empty `role_names` and `perms`; alongside role rows a
  roleless row adds nothing. `NotAMember` still means "no active row in the
  organization". `get` and `list_for_user` map a roleless row to
  `role_id`/`role_name` `None` instead of raising `AttributeError`.
- `get` returns the first row for `(user, org)`: active rows first, then
  role rows before the roleless one, then by `role_id`. An active roleless
  row therefore beats a suspended or ended role row. The SQLAlchemy adapter
  no longer raises `MultipleResultsFound` for a user with several rows in
  one organization (Django already returned the first).
- **SQLAlchemy `upsert`** now targets the unique key that exists,
  `(user_id, organization_id, role_id)`, and on conflict updates `status`
  only. It no longer reassigns `role_id` on conflict: an upsert with a
  different `role_id` adds a row, matching the Django adapter's existing
  `aupdate_or_create`. The previous target `(user_id, organization_id)`
  matched no unique key, so the old reassigning path errored at runtime
  anyway.
- **Canonical models mirror `users:AD-8`**: `MembershipORM.role_id` /
  `role` and the Django `Membership.role` are nullable; the unique key is
  named `uq_memberships_org_user_role_id` on
  `(organization_id, user_id, role_id)`, plus the partial unique index
  `uq_memberships_org_user_roleless` on `(organization_id, user_id) WHERE
  role_id IS NULL`. The Django model's `unique_together` became the two named
  `UniqueConstraint`s (`managed=False`, so no Django migration).

### Added

- Bundled migration **`pkg_auth_acl_0006`** (revises `pkg_auth_acl_0005`):
  drops `NOT NULL` on `memberships.role_id`, renames the unique constraint
  `uq_memberships_user_org_role` to `uq_memberships_org_user_role_id`
  (column order `organization_id, user_id, role_id`), and creates
  `uq_memberships_org_user_roleless`. Its downgrade is not a rollback path
  once a roleless row exists: it raises `RuntimeError` before touching the
  schema while any `role_id IS NULL` row is present.

## [Unreleased]

### Added

- **Service token**: a service's own Keycloak token, for calling another
  service as itself (client-credentials grant; the caller is its `azp`).
  Additive: nothing existing changes.
- `ServiceCredentials(token_url, client_id, client_secret)`, with
  `for_realm(...)` and `from_env()`, which reads `KEYCLOAK_BASE_URL`,
  `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID` and `KEYCLOAK_CLIENT_SECRET` and
  names every one that is unset. The secret is kept out of `repr`.
- `ServiceTokenProvider`: `get_token()` (sync) and `aget_token()` (async)
  share one cache. A token is reused until 30 s before it expires (half its
  lifetime if shorter), then fetched again; `invalidate()` drops it.
- `ServiceTokenAuth(provider)`: an `httpx.Auth` that sends the token and, on
  a 401, fetches a fresh one and retries once.
- `ServiceTokenError` (an `AuthenticationError`) when Keycloak refuses or
  cannot be reached; the message carries Keycloak's reason, never the secret.

## [3.2.0] — 2026-10-21

### Added

- **Delegated (on-behalf-of) authorization** (`auth:AD-1`): an allowlisted
  agent sends `X-On-Behalf-Of: <target keycloak sub>` and is authorized with
  exactly that user's permissions, only in the orgs on its list. Without the
  header every existing call site behaves as in 3.1.0.
- `ResolveDelegatedAuthContextUseCase(resolve_use_case, user_repo,
  organization_repo, delegators=None)` — the one framework-free place that
  holds the allowlist and makes every refusal. The target is looked up
  read-only through `UserRepository.get_by_keycloak_sub`; delegation never
  creates a user. On success it returns the target's own `AuthContext` (same
  service guard, same cache entry); the caller's perms are never used.
- `delegators`: `{agent_sub: [org_uuid, ...]}`, matched on the verified
  token's `sub` only. Normalized at construction into an immutable map;
  a bare `str`, a blank or padded `sub`, or a non-UUID org raises
  `ValueError`. Unset or empty means nobody delegates (fail closed). The
  platform org is refused unless an entry names it.
- `DelegationRefused` (an `AuthorizationError`) carrying a `DelegationRefusal`
  reason — one per check, never `NotAMember` or `UserNotProvisioned`, so no
  caller can mistake a refused delegation for its own failure.
- `make_get_auth_context(delegation=...)` — pass the use case to honour the
  header. The dependency still returns `(IdentityContext, AuthContext)`: the
  caller's verified identity with the target's context. Refusals map to
  400 (repeated header; empty value from a delegator), 404 (unknown org) or
  403 (everything else, including any value from a non-delegator).
  **Ship it with `delegators` empty**: it stays empty until `estate:AD-27`'s
  audit gate is met (see `docs/FastAPI.md`).
- `AuthContext.acted_by: UserId | None = None` — the caller's ACL id on a
  delegated request, `None` otherwise. Attribution only: `user_id` stays the
  acting principal, and `acted_by` is attached after resolution and never
  cached (the `auth_ctx:{user}:{org}` entry is unchanged).
- `make_get_current_user(*, get_identity, sync_user_use_case=None,
  resolve_user_use_case=None)` — an org-less FastAPI dependency returning the
  caller's ACL `User` (Mode A or Mode B). It refuses `X-On-Behalf-Of`.
- `ON_BEHALF_OF_HEADER` (`"X-On-Behalf-Of"`), exported from
  `pkg_auth.integrations.fastapi`.

### Changed

- **An unsupported `X-On-Behalf-Of` now gets 403 instead of being ignored.**
  Every pkg_auth path that cannot delegate refuses the header (any value):
  - `make_get_auth_context` without `delegation` → 403 after the caller is
    resolved;
  - the Strawberry context getter → 403 before the token is read. It is no
    longer permissive for this header: an anonymous or invalid-token request
    carrying it is refused, not passed through;
  - Django `AuthContextMiddleware` → 403 JSON response before any lookup;
  - `make_get_current_user` → 403 before the token is checked.
- `pkg_auth.__version__` was stuck at `"2.1.0"`; it now reports `"3.2.0"`.
- The `acl-sqlalchemy` and `dev` extras require `sqlalchemy[asyncio]`.
  SQLAlchemy 2.1 no longer installs `greenlet`, so a fresh install failed
  at `import sqlalchemy.ext.asyncio`.

## [3.1.0] — 2026-06-21

### Added

- **Service self-registration** (overlay model): a service registers its own
  identity (`name` + localized `display_label`) when it syncs its permission
  catalog. New `ServiceManifest` (+ `ServiceManifest.make`); a service exports
  one alongside its catalog and passes it via the new `--service-manifest`
  option on `pkg-auth-sync-catalog`. `RegisterPermissionCatalogUseCase` /
  `SyncPermissionCatalogUseCase` now accept an optional `display_label`.
- `ServiceRepository.register_identity(name, display_label=None)` replaces the
  internal `ensure_exists`: inserts a bare row (safe default flags) if absent,
  updates only `display_label` if a non-empty label is given, and never touches
  the vendor flags.

### Changed

- **`pkg-auth-sync-services` no longer prunes by default.** Because each service
  now owns its identity row, the vendor sync became a *flag overlay*: it sets
  `auto_provision` / `saas_available` without clobbering a service-owned
  `display_label`, and leaves services it doesn't list untouched. Pass the new
  `--prune` flag (or `prune=True` to `SyncServiceCatalogUseCase.execute`) for an
  explicit central cleanup. `upsert_many` now preserves an existing row's
  `display_label` (sets it only on insert).

## [3.0.0] — 2026-06-21

### Added

- First-class **service registry**: `Service` and `OrganizationService` domain
  entities, with `ServiceRepository` and `OrganizationServiceRepository` ports
  (SQLAlchemy, Django, and fake implementations).
- **Default-deny service guard** in `ResolveAuthContextUseCase`
  (`membership_repo`, `org_service_repo=None`, `catalog_repo=None`,
  `platform_org_id=None`): a resolved permission is dropped unless its owning
  service is enabled for the org in `organization_services`. The platform org
  bypasses the guard; leaving `org_service_repo`/`catalog_repo` unset disables
  filtering (incremental rollout).
- `ProvisionDefaultServicesUseCase` — enables `auto_provision` services for a
  new organization.
- `SetOrganizationServiceUseCase` — platform-admin toggle that raises
  `ServiceNotSaaSAvailable` when enabling a service the vendor hasn't marked
  `saas_available` (and `UnknownService` for an unknown service).
- `SyncServiceCatalogUseCase` + `ServiceSpec` and the `pkg-auth-sync-services`
  console script for syncing the vendor service registry at deploy time.
- `CachedOrganizationServiceRepository` — caches the per-org enabled-service-name
  set (`org_services:{org_id}`) for the service-guard hot path; invalidated on
  enable/disable/bulk_enable.
- New exceptions: `PermissionVisibilityConflict`, `UnknownService`,
  `ServiceNotSaaSAvailable`, `ServiceNotEnabled`.
- Role cross-visibility validation: `CreateRoleUseCase` / `UpdateRoleUseCase`
  accept an optional `platform_org_id` and raise `PermissionVisibilityConflict`
  when assigning `platform_only` perms to a normal-org role (or `tenant_only`
  perms to a platform-org role).
- `RegisterPermissionCatalogUseCase` / `SyncPermissionCatalogUseCase` accept an
  optional `service_repo`.

### Changed

- Permission **visibility** replaces `is_platform`: `visibility:
  PermissionVisibility` is one of `platform_only` / `shared` (default) /
  `tenant_only`.
- `PermissionScope` gains `'tenant'`: `Literal['org', 'tenant', 'platform',
  'all']`. `platform` → `platform_only ∪ shared`; `tenant`/`org` → `shared ∪
  tenant_only`.
- `Permission.description` is now `LocalizedText` (JSONB `{locale: text}`). The
  default/fallback locale comes from `ACL_DEFAULT_LOCALE` via
  `pkg_auth.authorization.config.default_locale()`. Use `CatalogEntry.make` to
  build entries with localized descriptions.
- Distribution name remains `pkg-auth`; the repository moved to
  `fritill-team/fri_pkg_auth` and the package is now published on PyPI.

### Removed

- `Permission.is_platform` (and `CatalogEntry`'s `is_platform`) — removed with no
  alias. Catalogs must switch to `visibility=`.

### Migrations

- `pkg_auth_acl_0003` — add `permissions.visibility`, backfill
  `is_platform=true → 'platform_only'` else `'shared'`, drop `is_platform`.
- `pkg_auth_acl_0004` — `permissions.description` `TEXT → JSONB`, backfilling
  text to `{ '<ACL_DEFAULT_LOCALE>': <text> }`.
- `pkg_auth_acl_0005` — create the `services` and `organization_services` tables.

## [2.1.0] — 2026-04-20

### Added

- `PermissionCatalogRepository.prune_absent(service_name, keep_keys)` port
  method with SQLAlchemy, Django, and fake implementations. Scoped DELETE
  for a single service; empty `keep_keys` deletes every row for the service.
- `SyncPermissionCatalogUseCase` — upsert declared entries then prune
  anything for the service that is no longer declared. Supports
  `dry_run=True` for a diff-only report. Returns `SyncResult(upserted,
  pruned, dry_run)`.
- `pkg-auth-sync-catalog` console script for deploy-time init containers.
  Factored (`build_arg_parser` / `load_catalog` / `run` / `main`) so
  services can compose their own entrypoint with extra flags or a custom
  catalog loader.

### Notes

- The `role_permissions.permission_id` FK is `ON DELETE CASCADE`: pruning
  a permission silently drops role assignments that referenced it. Run
  `--dry-run` first on shared environments. See
  `docs/Authorization.md` → Syncing permission catalogs.
- Recommended deployment: runtime services keep their existing SELECT-only
  credential and `RegisterPermissionCatalogUseCase`. A separate Vault DB
  role with `INSERT, UPDATE, DELETE` on `permissions` only is minted for
  the init container running the new CLI.

## [2.0.0] — 2026-04-16

### Breaking — Mode B consumers get a reader-only JWT use case

`SyncUserFromJwtUseCase` used to upsert the local `users` row on every
authenticated request, regardless of whether the service owned the
schema. For Mode B (consuming) services whose `ACL_DATABASE_URL`
points at a Mode A peer's database (e.g. `fri_fast_meetings` pointing
at `itq_users`), the bundled adapter's
`INSERT INTO users (keycloak_sub, email, full_name) ...` hit a
`NotNullViolationError` on `id` — and even with a defaulted `id`
would have written nulls into Mode A-owned extension columns,
corrupting the source-of-truth's invariants.

v2.0 splits the use case at the application layer:

- **`SyncUserFromJwtUseCase`** — unchanged, for Mode A (source-of-
  truth) services that own the `users` schema.
- **`ResolveUserFromJwtUseCase`** — new reader-only use case. Calls
  `UserRepository.get_by_keycloak_sub` and raises
  `UserNotProvisioned` (new `AuthorizationError` subclass) when the
  row is missing. Mode B services should use this.

The three integration factories now require exactly one of the two:

- `pkg_auth.integrations.fastapi.make_get_auth_context(...)`
- `pkg_auth.integrations.django.install_pkg_auth(...)`
- `pkg_auth.integrations.strawberry.make_context_getter(...)`

Each accepts `sync_user_use_case: ... | None = None` **xor**
`resolve_user_use_case: ... | None = None`. Passing both (or neither)
raises `ValueError` at factory-call time. No deprecation period — the
old positional-only `sync_user_use_case` signature is gone.

FastAPI and Django map `UserNotProvisioned` to **HTTP 403** (the
source-of-truth hasn't mirrored this user yet). Strawberry's
permissive context getter degrades `ctx.auth_context` to `None`.

### Breaking — example app (`itqadem_courses_app`) switched to Mode B

`examples/itqadem_courses_app/courses_app/deps.py` now wires
`ResolveUserFromJwtUseCase` — `itq_courses` is a Mode B consumer of
the `itq_users`-owned ACL. Mode A wiring is documented in
`docs/FastAPI.md` and `docs/Django.md`.

See `docs/MIGRATION_v2.md` for the full upgrade guide.

## [1.7.0] — 2026-04-15

### Breaking — Mode A and Mode B labels swapped

The two integration modes now match the naming used in the Engram
`pkg_auth Integration Guide` playbook and across the rest of the
itqadem fleet:

- **Mode A = Source-of-truth service** (extends the mixins, owns the
  ACL schema, runs its own migrations). `itq_users` is the canonical
  Mode A service.
- **Mode B = Consuming service** (reads the shared ACL tables via the
  bundled `*ORM` / mirror classes, no schema ownership). Services like
  `itq_courses` are Mode B.

Previous releases had the labels inverted in `docs/Django.md`, the
adapter docstrings, `src/pkg_auth/authorization/domain/entities.py`,
and the Alembic migration file names. All of those now match the
Engram convention. Any code or docs referencing "Mode A / Mode B"
from earlier versions must swap the labels.

### Breaking — bundled ACL tables no longer default to the `acl` schema

- `create_acl_base(schema=None)` is the new default (was `"acl"`).
  `AclBase` now emits unqualified table names, so Postgres resolves
  them via `search_path` — typically `public`, matching where the
  canonical SoT service (`itq_users`) already keeps the ACL tables.
- `src/pkg_auth/authorization/adapters/sqlalchemy/models.py` — the
  bundled `*ORM` classes dropped all `"acl.<table>.id"` FK string
  prefixes. They now reference unqualified names.
- `src/pkg_auth/authorization/adapters/django_orm/models.py` — the
  `managed=False` mirror models dropped the `acl"."` prefix on every
  `db_table`.
- Alembic migration `pkg_auth_acl_0001` renamed from
  `20260410_0001_initial_acl_schema.py` to `20260410_0001_initial_schema.py`.
  The migration no longer runs `CREATE SCHEMA acl` and no longer
  passes `schema="acl"` to any `op.create_table` / `op.create_index`
  / `op.drop_table` call.
- Alembic migration `pkg_auth_acl_0002_add_permission_is_platform`
  dropped `schema="acl"` from its `op.add_column` / `op.drop_column`.

Mode A services on previous versions that followed the bundled
migrations have their tables in the `acl` Postgres schema. They need
a one-off migration to move them into `public` (or their preferred
default schema) before upgrading — consult the SoT service's own
migration history (`itq_users` shipped
`a0b1c2d3e4f5_add_acl_tables_drop_acl_schema.py` for this purpose).

### Fixed — Strawberry integration parses `X-Organization-Id` the same way as FastAPI/Django

`src/pkg_auth/integrations/strawberry/auth.py` previously used a
legacy `raw.isdigit()` BIGINT fast-path that called
`OrgId(int(raw))`, which is unreachable code because `OrgId` wraps
`UUID`, not `int`. Replaced with a UUID-first parse that falls back
to slug lookup — matching the FastAPI `auth_context_dep` and Django
`AuthContextMiddleware` implementations.

## [1.4.0] — 2026-04-12

### Added — `is_platform` permission scope

- `PermissionMixin.is_platform` (`Boolean NOT NULL DEFAULT false`) on the
  SQLAlchemy and Django ORM mixins. Distinguishes permissions that operate
  inside a single organization from permissions that only make sense at
  platform/system level across organizations (e.g. `organizations:create`,
  `organizations:approve`).
- `Permission.is_platform: bool = False` on the domain entity.
- `CatalogEntry` dataclass for permission registration. Replaces the old
  2-tuple `(key, description)` shape with a clearer named structure that
  carries `is_platform`. Re-exported from `pkg_auth.authorization`.
- `PermissionScope` literal type (`"org" | "platform" | "all"`) and
  `scope=` keyword on `PermissionCatalogRepository.list_all()` and
  `PermissionCatalogRepository.list_for_service()`. The SQLAlchemy and
  Django implementations translate the scope to a SQL `WHERE` clause.
- Alembic migration `pkg_auth_acl_0002_add_permission_is_platform` adds
  the column to `acl.permissions` for SoT services.

### Backwards-compatible registration shapes

`RegisterPermissionCatalogUseCase.execute()` now accepts any of:

- `CatalogEntry(PermissionKey("..."), "desc", is_platform=True)`  *(preferred)*
- `(PermissionKey("..."), "desc")`         *(legacy 2-tuple — defaults `is_platform=False`)*
- `(PermissionKey("..."), "desc", True)`   *(legacy 3-tuple)*

Existing services upgrade by bumping `pkg-auth>=1.4.0`, applying the
column-add migration, and optionally migrating to the `CatalogEntry`
shape when they want to mark platform permissions.

### Added — multi-role per organization (Django adapter parity)

The SQLAlchemy adapter shipped multi-role support in v1.3 (unreleased);
v1.4 brings the Django adapter to parity:

- `Membership.unique_together = (("user", "organization", "role"),)` —
  one row per role; users can hold multiple roles in the same org.
- `DjangoMembershipRepository.load_auth_context()` aggregates the union
  of all *active* memberships and returns a single `AuthContext` with
  `role_names: frozenset[str]` and merged `perms`.
- `AuthContext.role_names` (frozenset) replaces the singular
  `role_name`. Use `ctx.has_role("editor")` for membership checks.
- `AuthContext.has(perm)` and `ctx.require(perm)` are unchanged.

### Platform-admin detection — service-level helper, not a flag

`AuthContext` deliberately does **not** carry an `is_platform: bool`
flag. Platform-admin detection is a *service-level* policy: the
consuming service designates one of its organizations as the "platform"
org and grants its members cross-org administrative privileges.

pkg_auth ships a stateless helper:

```python
from pkg_auth.authorization import is_platform_context

@require_permission("users:read")
async def list_users(request):
    auth_ctx = request.auth_context
    if is_platform_context(auth_ctx, cached_platform_org_id):
        users = User.objects.all()
    else:
        users = User.objects.filter(
            memberships__organization_id=auth_ctx.organization_id.value,
        )
    ...
```

The signature is:

```python
def is_platform_context(
    auth_ctx: AuthContext, platform_org_id: OrgId | None,
) -> bool: ...
```

Returns `True` when `auth_ctx.organization_id == platform_org_id`,
`False` otherwise (including when `platform_org_id` is `None`, e.g.
before the cache is initialized).

The consuming service is responsible for caching `platform_org_id`
wherever makes sense — module global, app config, request scope. A
typical pattern resolves the slug once at startup:

```python
_platform_org_id: OrgId | None = None

async def init_platform_org_id() -> None:
    global _platform_org_id
    org = await org_repo.get_by_slug("platform")
    if org is not None:
        _platform_org_id = org.id
```

**Why not a field on `AuthContext`?** Two ways to ask the same
question (a field on the dataclass *and* a helper) creates drift. The
helper-based approach also keeps `pkg_auth` decoupled from "what
counts as a platform admin" — that's a service-level policy, not a
package concern. See `docs/Django.md` for the full pattern.

### Added — Django adapter v1.4

### Added — Django adapter v1.4

- **UUID PKs everywhere.** All Django ORM models now use `UUIDField`
  PKs to match the SQLAlchemy schema (which moved to UUID in v1.2).
- **Abstract Django mixins** (`UserMixin`, `OrganizationMixin`,
  `PermissionMixin`, `RoleMixin`, `MembershipMixin`) under
  `pkg_auth.authorization.adapters.django_orm.mixins`. Mirror the
  SQLAlchemy mixin pattern: consuming services subclass the mixin to
  add their own columns and own the schema. Default `managed=False`
  concrete models in `models.py` inherit the mixins for services that
  don't need to extend.
- **Injectable model classes** on every Django repo
  (`DjangoUserRepository.model`, `DjangoMembershipRepository.role_model`,
  etc.). Lets services pass their own concrete subclasses without
  monkey-patching the package.
- `AuthContextMiddleware` now parses `X-Organization-Id` as a UUID
  first and falls back to slug lookup. The legacy `isdigit()` BIGINT
  fast-path is removed.
### Added — FastAPI adapter parity

- `make_get_auth_context(...)` parses the org header as UUID-or-slug
  instead of `isdigit()`.

### Test suite cleanup

Repaired pre-existing damage from a sed-based v1.2 UUID migration that
left the test suite in a non-collectible state:

- `tests/.../fakes.py` rewritten — type-correct UUIDs throughout,
  multi-role-aware `FakeMembershipRepository`, `CatalogEntry`-aware
  `FakePermissionCatalogRepository` with scope filtering.
- `tests/.../domain/test_value_objects.py` — meaningful equality and
  hashability assertions.
- `tests/.../domain/test_auth_context.py` — uses `role_names`,
  exercises `has_role()`, covers `is_platform`.
- `tests/.../application/test_*.py` — pass real `uuid4()` to
  `UserId/OrgId/RoleId` constructors instead of bare ints.

Test suite goes from 41 collected (6 collection errors, 10 failing) on
the v1.2 baseline to **85 passing / 0 failing** on v1.4.

### Migration guide

Consumers must:

1. Bump `pkg-auth>=1.4.0` in `requirements.txt` / `pyproject.toml`.
2. Run an Alembic migration to add the column on the `permissions` table:

   ```python
   op.add_column(
       "permissions",
       sa.Column(
           "is_platform",
           sa.Boolean(),
           nullable=False,
           server_default=sa.text("false"),
       ),
   )
   ```

   SoT services that re-use the package's Alembic branch can simply
   `alembic upgrade pkg_auth_acl@head`.
3. Migrate the permission catalog declaration to `CatalogEntry` for
   permissions that should be platform-only.
4. Drop any in-code workarounds (frozenset of platform perms, in-Python
   filters) — query the repo with `scope="platform"` instead.

### Notes for Django consumers

- The `default_auto_field` on the package's `AppConfig` is
  `BigAutoField` because Django requires an `AutoField` subclass and
  `UUIDField` isn't one. Every concrete ACL model declares its own
  `UUIDField` PK explicitly so this default is effectively unused.
- Importing the abstract mixins: use the explicit submodule, not the
  package `__init__`:
  `from pkg_auth.authorization.adapters.django_orm.mixins import UserMixin`.
  The `__init__.py` deliberately does NOT import the mixin module so
  Django's app loading order works correctly.

## [1.3.0] — 2026-04-11

### Multi-role per organization

A user can now hold multiple roles in the same organization. The
membership table's uniqueness moves from `(user, organization)` to
`(user, organization, role)`, and the auth context exposes the
union of all active roles' permissions:

- `Membership` schema: `UNIQUE(user_id, organization_id, role_id)`
  in the SQLAlchemy adapter; one row per role.
- `AuthContext.role_names: frozenset[str]` (renamed from singular
  `role_name`) — every active role the user holds in the active org.
- `AuthContext.perms` — union of all active roles' permission keys.
- `AuthContext.has_role(role: str) -> bool` — convenience check.
- `MembershipRepository.load_auth_context()` aggregates the union
  in a single query (with `selectinload`/`prefetch_related`).

### Migration

Consumers must migrate the `memberships` table's unique constraint:

```python
op.drop_constraint("uq_memberships_user_org", "memberships")
op.create_unique_constraint(
    "uq_memberships_user_org_role",
    "memberships",
    ["user_id", "organization_id", "role_id"],
)
```

Handler call sites that read `auth_ctx.role_name` (singular) must
move to `auth_ctx.role_names` (frozenset) or `auth_ctx.has_role(...)`.

## [1.2.0] — 2026-04-10

- UUID primary keys throughout the SQLAlchemy adapter.
- Extensible mixin models — `UserMixin`, `OrganizationMixin`,
  `PermissionMixin`, `RoleMixin`, `MembershipMixin` — under
  `pkg_auth.authorization.adapters.sqlalchemy.mixins`.
- Default concrete `*ORM` models in `models.py` for services that
  don't extend.
- Injectable `model` field on every SQLAlchemy repo.
- Initial Alembic migration (`pkg_auth_acl_0001_initial_acl_schema`).

## [1.1.0] — earlier

- ACL refactor moved into the package: domain entities, value objects,
  ports, application use cases, SQLAlchemy adapter, FastAPI/Django/
  Strawberry integrations.

## [1.0.0] — earlier

- Initial public release. Authentication module (Keycloak JWT decoder,
  IdentityContext) only.
