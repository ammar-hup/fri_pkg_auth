"""DjangoMembershipRepository reads a roleless membership (auth:AD-2).

A row with ``role_id`` NULL is a member with no role: it yields an
``AuthContext`` with empty role names and perms, and maps to a
``Membership`` whose ``role_id``/``role_name`` are ``None``.
"""
from __future__ import annotations

import uuid

import pytest
from asgiref.sync import sync_to_async
from django.apps import apps
from django.db import IntegrityError, connection

from pkg_auth.authorization import NotAMember, OrgId, RoleId, RoleName, UserId
from pkg_auth.authorization.adapters.django_orm import models as m
from pkg_auth.authorization.adapters.django_orm.repositories.membership import (
    DjangoMembershipRepository,
)
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)

_MODELS = tuple(apps.get_app_config("pkg_auth_acl").get_models())


def _create_schema() -> None:
    existing = set(connection.introspection.table_names())
    with connection.schema_editor() as editor:
        for model in _MODELS:
            if model._meta.db_table not in existing:
                editor.create_model(model)


def _reset() -> None:
    for model in _MODELS:
        model.objects.all().delete()


@pytest.fixture
async def repo():
    await sync_to_async(_create_schema)()
    await sync_to_async(_reset)()
    return DjangoMembershipRepository()


def _pk(low: bool) -> uuid.UUID:
    """A membership id that sorts first (low) or last, so pk order alone
    would pick the wrong row and only ``get``'s ``order_by`` can pass."""
    prefix = "00000000" if low else "ffffffff"
    return uuid.UUID(prefix + uuid.uuid4().hex[8:])


def _seed_sync(
    *, roleless_orgs=(), role_orgs=(), status="active", role_status=None,
    role_pk_low=False,
):
    user = m.User.objects.create(
        keycloak_sub=f"sub-{uuid.uuid4()}", email="a@example.com",
    )
    perm = m.Permission.objects.create(
        key=f"course:edit:{uuid.uuid4()}", service_name="courses",
    )
    orgs = {}
    for label in {*roleless_orgs, *role_orgs}:
        orgs[label] = m.Organization.objects.create(
            slug=f"org-{uuid.uuid4()}", name=label,
        )
    for label in roleless_orgs:
        m.Membership.objects.create(
            id=_pk(low=not role_pk_low),
            user=user, organization=orgs[label], role=None, status=status,
        )
    roles = {}
    for label in role_orgs:
        role = m.Role.objects.create(organization=orgs[label], name="editor")
        m.RolePermission.objects.create(role=role, permission=perm)
        m.Membership.objects.create(
            id=_pk(low=role_pk_low),
            user=user, organization=orgs[label], role=role,
            status=role_status or status,
        )
        roles[label] = role
    return user, orgs, roles, perm


_seed = sync_to_async(_seed_sync)


def _ids(user, org):
    return UserId(user.id), OrgId(org.id)


async def test_roleless_only_resolves_member_with_no_roles(repo):
    user, orgs, _, _ = await _seed(roleless_orgs=["A"])
    uid, oid = _ids(user, orgs["A"])

    ctx = await repo.load_auth_context(uid, oid)
    assert ctx is not None
    assert ctx.role_names == frozenset()
    assert ctx.perms == frozenset()

    resolved = await ResolveAuthContextUseCase(membership_repo=repo).execute(uid, oid)
    assert resolved.role_names == frozenset() and resolved.perms == frozenset()


async def test_roleless_plus_role_same_org_adds_nothing(repo):
    user, orgs, roles, perm = await _seed(roleless_orgs=["A"], role_orgs=["A"])
    uid, oid = _ids(user, orgs["A"])

    ctx = await repo.load_auth_context(uid, oid)
    assert ctx.role_names == frozenset({"editor"})
    assert ctx.perms == frozenset({perm.key})

    got = await repo.get(uid, oid)
    assert got.role_id == RoleId(roles["A"].id)
    assert got.role_name == RoleName("editor")


async def test_roleless_and_role_in_other_orgs(repo):
    user, orgs, roles, _ = await _seed(roleless_orgs=["A"], role_orgs=["B"])
    uid = UserId(user.id)

    listed = {mm.organization_id.value: mm for mm in await repo.list_for_user(uid)}
    assert set(listed) == {orgs["A"].id, orgs["B"].id}
    assert listed[orgs["A"].id].role_id is None
    assert listed[orgs["A"].id].role_name is None
    assert listed[orgs["B"].id].role_id == RoleId(roles["B"].id)
    assert listed[orgs["B"].id].role_name == RoleName("editor")

    roleless = await repo.get(uid, OrgId(orgs["A"].id))
    assert roleless.role_id is None and roleless.role_name is None


@pytest.mark.parametrize("role_status", ["suspended", "ended"])
async def test_get_prefers_active_roleless_over_inactive_role_row(repo, role_status):
    user, orgs, _, _ = await _seed(
        roleless_orgs=["A"], role_orgs=["A"], role_status=role_status,
        role_pk_low=True,
    )
    uid, oid = _ids(user, orgs["A"])

    got = await repo.get(uid, oid)
    assert got.status == "active"
    assert got.role_id is None and got.role_name is None


@pytest.mark.parametrize("status", ["suspended", "ended"])
async def test_inactive_roleless_is_not_a_member(repo, status):
    user, orgs, _, _ = await _seed(roleless_orgs=["A"], status=status)
    uid, oid = _ids(user, orgs["A"])

    assert await repo.load_auth_context(uid, oid) is None
    with pytest.raises(NotAMember):
        await ResolveAuthContextUseCase(membership_repo=repo).execute(uid, oid)


async def test_absent_row_is_not_a_member(repo):
    user, orgs, _, _ = await _seed(role_orgs=["B"])
    other = await sync_to_async(m.Organization.objects.create)(slug="x", name="x")
    uid, oid = _ids(user, other)

    assert await repo.load_auth_context(uid, oid) is None
    with pytest.raises(NotAMember):
        await ResolveAuthContextUseCase(membership_repo=repo).execute(uid, oid)


async def test_upsert_conflict_updates_status_on_existing_role_row(repo):
    user, orgs, roles, _ = await _seed(roleless_orgs=["A"], role_orgs=["A"])
    uid, oid = _ids(user, orgs["A"])

    updated = await repo.upsert(
        user_id=uid, org_id=oid, role_id=RoleId(roles["A"].id), status="suspended",
    )
    assert updated.status == "suspended"
    rows = await sync_to_async(list)(
        m.Membership.objects.filter(user=user, organization=orgs["A"])
        .values_list("role_id", "status")
    )
    assert sorted(rows, key=lambda r: r[0] is None) == [
        (roles["A"].id, "suspended"), (None, "active"),
    ]


async def test_second_roleless_row_for_pair_is_rejected(repo):
    user, orgs, _, _ = await _seed(roleless_orgs=["A"])
    with pytest.raises(IntegrityError):
        await sync_to_async(m.Membership.objects.create)(
            user=user, organization=orgs["A"], role=None, status="ended",
        )


def test_model_mirrors_users_ad_8_schema():
    role = m.Membership._meta.get_field("role")
    assert role.null is True
    constraints = {c.name: c for c in m.Membership._meta.constraints}
    assert set(constraints) == {
        "uq_memberships_org_user_role_id", "uq_memberships_org_user_roleless",
    }
    assert constraints["uq_memberships_org_user_role_id"].fields == (
        "organization", "user", "role",
    )
    roleless = constraints["uq_memberships_org_user_roleless"]
    assert roleless.fields == ("organization", "user")
    assert roleless.condition.children == [("role__isnull", True)]
    assert m.Membership._meta.unique_together == ()
