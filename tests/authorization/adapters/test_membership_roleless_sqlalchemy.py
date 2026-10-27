"""SqlAlchemyMembershipRepository reads a roleless membership (auth:AD-2).

No Postgres here: a fake session returns pre-built rows, so these cover the
repository's mapping and aggregation, and the compiled SQL for ``get``'s
ordering and ``upsert``'s conflict target. The real-database path is
covered by ``test_roleless_membership_integration.py``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import Index, UniqueConstraint
from sqlalchemy.dialects import postgresql

from pkg_auth.authorization import NotAMember, OrgId, RoleId, RoleName, UserId
from pkg_auth.authorization.adapters.sqlalchemy.models import MembershipORM
from pkg_auth.authorization.adapters.sqlalchemy.repositories.membership import (
    SqlAlchemyMembershipRepository,
)
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)

USER = uuid4()


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalar_one(self):
        (row,) = self._rows
        return row


class _Session:
    def __init__(self, results):
        self._results = list(results)
        self.statements = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt):
        self.statements.append(stmt)
        return _Result(self._results.pop(0))

    async def commit(self):
        pass


def _repo(*results):
    session = _Session(results)
    return SqlAlchemyMembershipRepository(session_factory=lambda: session), session


def _role(name="editor", perms=("course:edit",)):
    return SimpleNamespace(
        id=uuid4(), name=name, permissions=[SimpleNamespace(key=k) for k in perms],
    )


def _row(org, role=None, status="active"):
    return SimpleNamespace(
        id=uuid4(),
        user_id=USER,
        organization_id=org,
        role_id=role.id if role is not None else None,
        role=role,
        status=status,
        joined_at=datetime.now(timezone.utc),
    )


def _sql(stmt) -> str:
    return str(
        stmt.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True},
        )
    )


async def test_roleless_only_resolves_member_with_no_roles():
    org = uuid4()
    repo, _ = _repo([_row(org)], [_row(org)])

    ctx = await repo.load_auth_context(UserId(USER), OrgId(org))
    assert ctx is not None
    assert ctx.role_names == frozenset() and ctx.perms == frozenset()

    resolved = await ResolveAuthContextUseCase(membership_repo=repo).execute(
        UserId(USER), OrgId(org),
    )
    assert resolved.role_names == frozenset() and resolved.perms == frozenset()


async def test_roleless_plus_role_same_org_adds_nothing():
    org = uuid4()
    role = _role()
    repo, _ = _repo([_row(org), _row(org, role)])

    ctx = await repo.load_auth_context(UserId(USER), OrgId(org))
    assert ctx.role_names == frozenset({"editor"})
    assert ctx.perms == frozenset({"course:edit"})


async def test_roleless_and_role_in_other_orgs():
    org_a, org_b = uuid4(), uuid4()
    role = _role()
    repo, _ = _repo([_row(org_a), _row(org_b, role)], [_row(org_a)])

    listed = {
        mm.organization_id.value: mm
        for mm in await repo.list_for_user(UserId(USER))
    }
    assert set(listed) == {org_a, org_b}
    assert listed[org_a].role_id is None and listed[org_a].role_name is None
    assert listed[org_b].role_id == RoleId(role.id)
    assert listed[org_b].role_name == RoleName("editor")

    got = await repo.get(UserId(USER), OrgId(org_a))
    assert got.role_id is None and got.role_name is None


_GET_ORDER = (
    "ORDER BY memberships.status != 'active', memberships.role_id IS NULL, "
    "memberships.role_id"
)


async def test_get_sorts_active_then_role_rows_before_roleless_and_takes_one():
    org = uuid4()
    role = _role()
    repo, session = _repo([_row(org, role)])

    got = await repo.get(UserId(USER), OrgId(org))
    assert got.role_name == RoleName("editor")
    sql = _sql(session.statements[0])
    assert _GET_ORDER in sql
    assert "LIMIT 1" in sql


@pytest.mark.parametrize("role_status", ["suspended", "ended"])
async def test_get_prefers_active_roleless_over_inactive_role_row(role_status):
    """Status sorts before role presence, so the active roleless row is
    the one Postgres returns first; the fake returns that row."""
    org = uuid4()
    repo, session = _repo([_row(org)])

    got = await repo.get(UserId(USER), OrgId(org))
    assert got.status == "active" and got.role_id is None
    sql = _sql(session.statements[0])
    assert sql.index("memberships.status != 'active'") < sql.index(
        "memberships.role_id IS NULL"
    )


async def test_no_active_row_is_not_a_member():
    org = uuid4()
    repo, _ = _repo([], [])

    assert await repo.load_auth_context(UserId(USER), OrgId(org)) is None
    with pytest.raises(NotAMember):
        await ResolveAuthContextUseCase(membership_repo=repo).execute(
            UserId(USER), OrgId(org),
        )


async def test_upsert_conflict_target_is_the_role_id_key():
    org = uuid4()
    role = _role()
    row = _row(org, role, status="suspended")
    repo, session = _repo([row], [role])

    got = await repo.upsert(
        user_id=UserId(USER), org_id=OrgId(org), role_id=RoleId(role.id),
        status="suspended",
    )
    assert got.status == "suspended" and got.role_name == RoleName("editor")
    sql = _sql(session.statements[0])
    assert (
        "ON CONFLICT (user_id, organization_id, role_id) DO UPDATE SET "
        "status = 'suspended' RETURNING"
    ) in sql

    target = {"user_id", "organization_id", "role_id"}
    keys = [
        {c.name for c in con.columns}
        for con in MembershipORM.__table__.constraints
        if isinstance(con, UniqueConstraint)
    ]
    assert target in keys


def test_model_mirrors_users_ad_8_schema():
    table = MembershipORM.__table__
    assert table.c.role_id.nullable is True

    uniques = {
        c.name: [col.name for col in c.columns]
        for c in table.constraints
        if isinstance(c, UniqueConstraint)
    }
    assert uniques == {
        "uq_memberships_org_user_role_id": ["organization_id", "user_id", "role_id"],
    }

    (roleless,) = [
        i for i in table.indexes
        if isinstance(i, Index) and i.name == "uq_memberships_org_user_roleless"
    ]
    assert roleless.unique is True
    assert [c.name for c in roleless.columns] == ["organization_id", "user_id"]
    assert str(roleless.dialect_options["postgresql"]["where"]) == "role_id IS NULL"
