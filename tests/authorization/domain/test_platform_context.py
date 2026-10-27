"""``is_platform_context`` helper tests."""
from uuid import uuid4

from pkg_auth.authorization import (
    AuthContext,
    OrgId,
    UserId,
    is_platform_context,
)


def _ctx_in_org(org_id: OrgId) -> AuthContext:
    return AuthContext(
        user_id=UserId(uuid4()),
        organization_id=org_id,
        role_names=frozenset({"platform-admin"}),
        perms=frozenset({"organizations:create"}),
    )


def test_returns_true_when_request_org_matches_platform_org():
    platform_org = OrgId(uuid4())
    ctx = _ctx_in_org(platform_org)
    assert is_platform_context(ctx, platform_org) is True


def test_returns_false_when_request_org_differs():
    platform_org = OrgId(uuid4())
    other_org = OrgId(uuid4())
    ctx = _ctx_in_org(other_org)
    assert is_platform_context(ctx, platform_org) is False


def test_returns_false_when_platform_org_id_is_none():
    """Cache-uninitialized case — service has no designated platform org."""
    ctx = _ctx_in_org(OrgId(uuid4()))
    assert is_platform_context(ctx, None) is False


def test_roleless_member_of_platform_org_is_not_platform_context():
    """auth:AD-2 — a platform context requires at least one role."""
    platform_org = OrgId(uuid4())
    ctx = AuthContext(
        user_id=UserId(uuid4()),
        organization_id=platform_org,
        role_names=frozenset(),  # no roles
        perms=frozenset(),         # no perms
    )
    assert is_platform_context(ctx, platform_org) is False


def test_platform_context_needs_a_role_not_a_perm():
    """One role with no permissions is enough; perms are not inspected."""
    platform_org = OrgId(uuid4())
    ctx = AuthContext(
        user_id=UserId(uuid4()),
        organization_id=platform_org,
        role_names=frozenset({"platform-viewer"}),
        perms=frozenset(),
    )
    assert is_platform_context(ctx, platform_org) is True
