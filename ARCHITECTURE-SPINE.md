---
name: 'auth'
type: architecture-spine
purpose: build-substrate
altitude: initiative
paradigm: 'a published Python library in src/ layout'
scope: 'invariants binding the shared auth library'
status: draft
created: '2026-08-28'
updated: '2026-10-21'
binds: []
sources: []
companions: []
---

# Architecture Spine — auth

## Design Paradigm

A standalone Python library in `src/` layout, published from `pyproject.toml` and consumed by the services as a pinned dependency. It has no runtime of its own: everything here is imported, so a breaking change is felt at every consumer's next pin and nowhere earlier.

## Inherited Invariants

These are the estate's, listed by their original ids and **not** re-keyed here — a second key
for one decision is the collision the namespace grammar exists to prevent. Where anything below
disagrees with one of these, the inherited decision wins and the disagreement is a conflict to
surface, not a local override.

- `estate:AD-1` — the knowledge base is a routing aid, never the authority
- `estate:AD-2` — a decision lives in the repo it binds
- `estate:AD-3` — every citation is namespaced
- `estate:AD-4` — board automation never moves a card between lists
- `estate:AD-5` — human requests enter through a separate board, and only through triage
- `estate:AD-6` — courses is the system of record for live cohorts
- `estate:AD-7` — one NATS subject grammar: `<service>.<aggregate_type>`, event variant in the payload
- `estate:AD-8` — two ACL database roles: SELECT-only at runtime, write-capable only at deploy
- `estate:AD-14` — the estate targets N>1 replicas; a service is replica-safe or it does not ship
- `estate:AD-24` — the audit write side is `pkg-audit`, embedded, on the caller's transaction
- `estate:AD-26` — each service serves its own audit trail through `pkg-audit[fastapi]`, behind its own permission
- `estate:AD-27` — on-behalf-of authorization is pkg_auth's alone; adopters only configure who may delegate

## Invariants & Rules

### AD-1 — A delegated request is authorized as the acted-for user, resolved once in a framework-free use case

- **Binds:** the `authorization` package and every integration (`fastapi`, `strawberry`,
  `django`).
- **Prevents:**
  - an allowlisted agent acting with its own permissions, or with a union of its own and the
    target's;
  - any path that turns a token into a user silently ignoring the signal, and so serving the
    agent as itself;
  - a compromised agent reaching any user in any organization;
  - integrations drifting on what is refused, or holding their own copy of the allowlist;
  - delegation state leaking through the shared `auth_ctx:{user}:{org}` cache.
- **Rule:**
  - **Signal.** The `X-On-Behalf-Of` request header carries the acted-for user's Keycloak `sub`.
    No header means today's behaviour, unchanged.
  - **Allowlist (`delegators`).** It maps an agent's `sub` to the organization ids that agent
    may delegate in.
    - The key is the Keycloak service-account user's `sub`, not the clientId. It is compared
      against the verified token's `sub` only, never a header.
    - The platform organization is refused unless an entry names it.
    - It is supplied from the service's own config. Empty is the default, and empty means
      nobody delegates.
    - It is normalized when built into an immutable map of exact `sub`s to frozen org-id sets.
      A bare string, a blank `sub` or a non-UUID org raises `ValueError` at startup.
  - **Placement.** One application use case holds `delegators` and does all of the following:
    the allowlist check, the read-only target lookup, and every refusal.
    - Integrations receive that use case, never the list. They only read headers and map its
      errors.
    - The target is looked up through `UserRepository` in Mode A and Mode B alike.
      `SyncUserFromJwtUseCase` is never called with a header value.
  - **Order.** First match wins:

    | # | Case | Result |
    | --- | --- | --- |
    | 1 | `X-Organization-Id` missing | 400, as today |
    | 2 | caller resolved as today (Mode A sync, Mode B resolve); the agent must itself be an ACL user | as today |
    | 3 | `X-On-Behalf-Of` repeated | 400 |
    | 4 | header present (any value, including empty) and caller not in `delegators` | 403 |
    | 5 | header value empty | 400 |
    | 6 | organization unknown | 404 |
    | 7 | organization not in this agent's list | 403 |
    | 8 | target `sub` not provisioned | 403; delegation never creates a user |
    | 9 | target not a member of the organization | 403 |

    Rows 3–9 raise one distinct `DelegationRefused`, never `NotAMember` or `UserNotProvisioned`.
    No integration downgrades that refusal to an empty context or to the caller's context.
  - **Coverage.** Every pkg_auth step that turns a token into a user either resolves delegation
    by this AD or refuses a request carrying `X-On-Behalf-Of` with 403. That includes
    organization-less identity resolution, and `strawberry`/`django` until they implement this
    AD. No step ignores the header.
  - **Shape.** The return is still `(IdentityContext, AuthContext)`. `IdentityContext` is the
    caller's verified token. `AuthContext` is the acted-for user's own context from
    `ResolveAuthContextUseCase`, with the same service guard and the same cache entry.
    - It gains `acted_by: UserId | None`, appended last with default `None`. It holds the
      caller's ACL id on a delegated request.
    - `AuthContext.user_id` is the acting principal for authorization and ownership. `acted_by`
      is attribution only.
  - **Cache.** `acted_by` is attached after resolution (`dataclasses.replace`), and the
    serializer's explicit field list excludes it. The cache stays a pure function of
    `(user, organization)`.
  - **Release.** Ships as 3.2.0. The change is additive except for one new behaviour: an
    unsupported `X-On-Behalf-Of` now gets 403 instead of being ignored. The CHANGELOG states it.
    Published only on the owner's yes.

## Deferred

- Delegation support in the Strawberry and Django integrations: written when the assistant first
  reaches a service using them. Until then they refuse the header (`auth:AD-1`, Coverage).
- Proof that the acted-for user asked, such as a grant signed by their session: revisit before
  the assistant gains write actions beyond drafts, or serves an audience beyond the platform.
- Forwarding `X-On-Behalf-Of` across service-to-service calls: no service calls another on a
  user's behalf yet.
- Recording the caller in audit: an `estate:AD-24` amendment, built in `pkg_audit`, not this
  package (see `estate:AD-27`).
