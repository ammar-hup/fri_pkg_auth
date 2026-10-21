"""AuthContext.has() / .require() behavior."""
from uuid import uuid4

import pytest

from pkg_auth.authorization import (
    AuthContext,
    MissingPermission,
    OrgId,
    UserId,
)


def _make_ctx(*perms: str, role: str = "editor") -> AuthContext:
    return AuthContext(
        user_id=UserId(uuid4()),
        organization_id=OrgId(uuid4()),
        role_names=frozenset({role}),
        perms=frozenset(perms),
    )


def test_has_returns_true_for_granted_perm():
    ctx = _make_ctx("course:edit", "course:view")
    assert ctx.has("course:edit") is True
    assert ctx.has("course:view") is True


def test_has_returns_false_for_missing_perm():
    ctx = _make_ctx("course:view")
    assert ctx.has("course:edit") is False


def test_has_returns_false_for_empty_perms():
    ctx = _make_ctx()
    assert ctx.has("anything:at_all") is False


def test_require_silent_when_granted():
    ctx = _make_ctx("course:edit")
    ctx.require("course:edit")  # should not raise


def test_require_raises_when_missing():
    ctx = _make_ctx("course:view")
    with pytest.raises(MissingPermission, match="course:edit"):
        ctx.require("course:edit")


def test_require_error_message_includes_org_and_role():
    org_id = OrgId(uuid4())
    ctx = AuthContext(
        user_id=UserId(uuid4()),
        organization_id=org_id,
        role_names=frozenset({"viewer"}),
        perms=frozenset(),
    )
    with pytest.raises(MissingPermission) as exc_info:
        ctx.require("course:edit")
    msg = str(exc_info.value)
    assert "course:edit" in msg
    assert str(org_id) in msg
    assert "viewer" in msg


def test_auth_context_is_frozen():
    ctx = _make_ctx("course:edit")
    with pytest.raises(Exception):
        ctx.perms = frozenset()  # type: ignore[misc]


def test_has_role_returns_true_for_held_role():
    ctx = _make_ctx("course:edit", role="editor")
    assert ctx.has_role("editor") is True
    assert ctx.has_role("viewer") is False


def test_perms_are_union_of_all_roles():
    ctx = AuthContext(
        user_id=UserId(uuid4()),
        organization_id=OrgId(uuid4()),
        role_names=frozenset({"editor", "approver"}),
        perms=frozenset({"course:edit", "course:approve"}),
    )
    assert ctx.has("course:edit")
    assert ctx.has("course:approve")
    assert ctx.has_role("editor")
    assert ctx.has_role("approver")


def test_auth_context_has_no_is_platform_field():
    """Platform-admin detection is a service-level concern.

    pkg_auth deliberately does not carry an ``is_platform`` flag on
    AuthContext — services use :func:`is_platform_context` against
    their own cached platform org id instead. This test pins that
    decision so a future refactor doesn't quietly re-add the field.
    """
    ctx = _make_ctx("course:edit")
    assert not hasattr(ctx, "is_platform")


def test_acted_by_defaults_to_none():
    assert _make_ctx("course:view").acted_by is None


def test_replace_sets_acted_by_without_touching_perms():
    from dataclasses import replace

    ctx = _make_ctx("course:view")
    agent = UserId(uuid4())
    delegated = replace(ctx, acted_by=agent)
    assert delegated.acted_by == agent
    assert delegated.user_id == ctx.user_id
    assert delegated.perms == ctx.perms
    assert ctx.acted_by is None


def test_cache_serializer_drops_acted_by():
    from dataclasses import replace

    from pkg_auth.authorization.adapters.cache.decorators import (
        _deserialize_auth_context,
        _serialize_auth_context,
    )

    ctx = AuthContext(
        user_id=UserId(uuid4()),
        organization_id=OrgId(uuid4()),
        role_names=frozenset({"editor"}),
        perms=frozenset({"course:edit"}),
    )
    blob = _serialize_auth_context(replace(ctx, acted_by=UserId(uuid4())))
    assert b"acted_by" not in blob
    assert _deserialize_auth_context(blob) == ctx
