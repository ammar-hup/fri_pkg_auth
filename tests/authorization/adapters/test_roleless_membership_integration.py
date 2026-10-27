"""Roleless memberships against real Postgres, through migration 0006.

Run with: ``pytest -m integration`` (requires Docker for testcontainers).
"""
from __future__ import annotations

from uuid import uuid4

import pytest

pytestmark = pytest.mark.integration

pytest.importorskip("sqlalchemy")
pytest.importorskip("asyncpg")
pytest.importorskip("alembic")
testcontainers_pg = pytest.importorskip("testcontainers.postgres")

from alembic import command  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    async_sessionmaker,
    create_async_engine,
)

from pkg_auth.authorization import (  # noqa: E402
    NotAMember,
    OrgId,
    RoleId,
    RoleName,
    UserId,
)
from pkg_auth.authorization.adapters.sqlalchemy.repositories.membership import (  # noqa: E402
    SqlAlchemyMembershipRepository,
)
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (  # noqa: E402
    ResolveAuthContextUseCase,
)

from .test_services_integration import _alembic_config, _urls  # noqa: E402


@pytest.fixture(scope="module")
def pg():
    with testcontainers_pg.PostgresContainer("postgres:16") as container:
        yield container


async def test_chain_through_0006_reads_roleless_rows(pg, tmp_path):
    sync_url, async_url = _urls(pg)
    cfg = _alembic_config(tmp_path, sync_url)
    command.upgrade(cfg, "pkg_auth_acl_0006")

    engine = create_async_engine(async_url)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    user, org_a, org_b, org_c, role, role_c, perm = (uuid4() for _ in range(7))

    async with engine.begin() as conn:
        names = {
            r[0]
            for r in await conn.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conrelid = 'memberships'::regclass AND contype = 'u' "
                    "UNION SELECT indexname FROM pg_indexes "
                    "WHERE tablename = 'memberships'"
                )
            )
        }
        assert "uq_memberships_org_user_role_id" in names
        assert "uq_memberships_org_user_roleless" in names
        assert "uq_memberships_user_org_role" not in names
        nullable = (
            await conn.execute(
                text(
                    "SELECT is_nullable FROM information_schema.columns "
                    "WHERE table_name = 'memberships' AND column_name = 'role_id'"
                )
            )
        ).scalar_one()
        assert nullable == "YES"

        # The bundled 0001 gives memberships.id no default; the ORM model
        # (and the live itq_users table) does. Mirror it so upsert can insert.
        await conn.execute(
            text("ALTER TABLE memberships ALTER COLUMN id SET DEFAULT gen_random_uuid()")
        )
        await conn.execute(
            text("INSERT INTO users (id, keycloak_sub, email) VALUES (:u, :s, 'a@x')"),
            {"u": user, "s": f"sub-{user}"},
        )
        for org in (org_a, org_b, org_c):
            await conn.execute(
                text("INSERT INTO organizations (id, slug, name) VALUES (:o, :s, 'O')"),
                {"o": org, "s": f"org-{org}"},
            )
        await conn.execute(
            text("INSERT INTO roles (id, organization_id, name) VALUES (:r, :o, 'editor')"),
            {"r": role, "o": org_b},
        )
        await conn.execute(
            text("INSERT INTO roles (id, organization_id, name) VALUES (:r, :o, 'editor')"),
            {"r": role_c, "o": org_c},
        )
        await conn.execute(
            text(
                "INSERT INTO permissions (id, key, service_name) "
                "VALUES (:p, 'course:edit', 'courses')"
            ),
            {"p": perm},
        )
        await conn.execute(
            text("INSERT INTO role_permissions (role_id, permission_id) VALUES (:r, :p)"),
            {"r": role, "p": perm},
        )
        # Roleless in A; roleless + role in B; active roleless + suspended
        # role in C (the role row's id sorts first, so pk order is wrong).
        rows = (
            (uuid4(), org_a, None, "active"),
            (uuid4(), org_b, None, "active"),
            (uuid4(), org_b, role, "active"),
            (uuid4(), org_c, role_c, "suspended"),
            (uuid4(), org_c, None, "active"),
        )
        for mid, org, role_id, status in rows:
            await conn.execute(
                text(
                    "INSERT INTO memberships (id, user_id, organization_id, "
                    "role_id, status) VALUES (:i, :u, :o, :r, :s)"
                ),
                {"i": mid, "u": user, "o": org, "r": role_id, "s": status},
            )

    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO memberships (user_id, organization_id, role_id, status) "
                    "VALUES (:u, :o, NULL, 'ended')"
                ),
                {"u": user, "o": org_a},
            )

    repo = SqlAlchemyMembershipRepository(session_factory=sf)
    resolve = ResolveAuthContextUseCase(membership_repo=repo)
    uid = UserId(user)

    ctx_a = await resolve.execute(uid, OrgId(org_a))
    assert ctx_a.role_names == frozenset() and ctx_a.perms == frozenset()
    ctx_b = await repo.load_auth_context(uid, OrgId(org_b))
    assert ctx_b.role_names == frozenset({"editor"})
    assert ctx_b.perms == frozenset({"course:edit"})

    listed = await repo.list_for_user(uid)
    assert len(listed) == 5
    assert sum(1 for mm in listed if mm.role_id is None) == 3

    got_c = await repo.get(uid, OrgId(org_c))
    assert got_c.status == "active" and got_c.role_id is None

    got_a = await repo.get(uid, OrgId(org_a))
    assert got_a.role_id is None and got_a.role_name is None
    got_b = await repo.get(uid, OrgId(org_b))
    assert got_b.role_id == RoleId(role) and got_b.role_name == RoleName("editor")

    updated = await repo.upsert(
        user_id=uid, org_id=OrgId(org_b), role_id=RoleId(role), status="suspended",
    )
    assert updated.status == "suspended"
    assert len(await repo.list_for_user(uid)) == 5

    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE memberships SET status = 'ended' WHERE organization_id = :o"),
            {"o": org_a},
        )
    with pytest.raises(NotAMember):
        await resolve.execute(uid, OrgId(org_a))

    await engine.dispose()

    # Roleless rows exist, so the downgrade refuses before touching schema.
    with pytest.raises(RuntimeError, match="forward-only"):
        command.downgrade(cfg, "pkg_auth_acl_0005")
    engine = create_async_engine(async_url)
    async with engine.connect() as conn:
        version = (
            await conn.execute(text("SELECT version_num FROM alembic_version"))
        ).scalar_one()
        index = (
            await conn.execute(
                text(
                    "SELECT 1 FROM pg_indexes WHERE tablename = 'memberships' "
                    "AND indexname = 'uq_memberships_org_user_roleless'"
                )
            )
        ).scalar_one_or_none()
    await engine.dispose()
    assert version == "pkg_auth_acl_0006"
    assert index == 1
