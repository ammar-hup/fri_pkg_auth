"""SQLAlchemy implementation of MembershipRepository (UUID PKs, injectable model)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from ....domain.entities import AuthContext, Membership
from ....domain.value_objects import (
    OrgId,
    RoleId,
    RoleName,
    UserId,
)
from ..models import MembershipORM as DefaultMembershipORM
from ..models import RoleORM as DefaultRoleORM


def _role_name(row: Any) -> str | None:
    return row.role.name if row.role is not None else None


def _to_membership(row: Any, role_name: str | None) -> Membership:
    """A roleless row (``role_id`` NULL) maps to ``role_id``/``role_name`` None."""
    return Membership(
        id=row.id,
        user_id=UserId(row.user_id),
        organization_id=OrgId(row.organization_id),
        role_id=RoleId(row.role_id) if row.role_id is not None else None,
        role_name=RoleName(role_name) if role_name is not None else None,
        status=row.status,
        joined_at=row.joined_at,
    )


@dataclass(slots=True)
class SqlAlchemyMembershipRepository:
    session_factory: async_sessionmaker[AsyncSession]
    model: type = field(default=DefaultMembershipORM)
    role_model: type = field(default=DefaultRoleORM)

    async def get(
        self, user_id: UserId, org_id: OrgId
    ) -> Membership | None:
        """First row for (user, org): active rows first, then role rows
        before the roleless one, then ``role_id`` for determinism."""
        async with self.session_factory() as session:
            row = (
                await session.execute(
                    select(self.model)
                    .options(selectinload(self.model.role))
                    .where(
                        self.model.user_id == user_id.value,
                        self.model.organization_id == org_id.value,
                    )
                    .order_by(
                        self.model.status != "active",
                        self.model.role_id.is_(None),
                        self.model.role_id,
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()
            return _to_membership(row, _role_name(row)) if row is not None else None

    async def upsert(
        self,
        *,
        user_id: UserId,
        org_id: OrgId,
        role_id: RoleId,
        status: str,
    ) -> Membership:
        stmt = (
            pg_insert(self.model)
            .values(
                user_id=user_id.value,
                organization_id=org_id.value,
                role_id=role_id.value,
                status=status,
            )
            .on_conflict_do_update(
                index_elements=["user_id", "organization_id", "role_id"],
                set_={"status": status},
            )
            .returning(self.model)
        )
        async with self.session_factory() as session:
            result = await session.execute(stmt)
            await session.commit()
            row = result.scalar_one()
            role = (
                await session.execute(
                    select(self.role_model).where(
                        self.role_model.id == row.role_id
                    )
                )
            ).scalar_one()
            return _to_membership(row, role.name)

    async def delete(self, user_id: UserId, org_id: OrgId) -> None:
        async with self.session_factory() as session:
            await session.execute(
                delete(self.model).where(
                    self.model.user_id == user_id.value,
                    self.model.organization_id == org_id.value,
                )
            )
            await session.commit()

    async def load_auth_context(
        self, user_id: UserId, org_id: OrgId
    ) -> AuthContext | None:
        """Multi-role: fetch ALL active memberships for (user, org),
        merge their roles' permissions into a single AuthContext.

        A roleless row still makes the user a member (a context is
        returned) but adds no role name and no permission.
        """
        async with self.session_factory() as session:
            stmt = (
                select(self.model)
                .options(
                    selectinload(self.model.role).selectinload(
                        self.role_model.permissions
                    )
                )
                .where(
                    self.model.user_id == user_id.value,
                    self.model.organization_id == org_id.value,
                    self.model.status == "active",
                )
            )
            rows = (await session.execute(stmt)).scalars().all()
            if not rows:
                return None
            role_names: set[str] = set()
            all_perms: set[str] = set()
            for row in rows:
                if row.role is None:
                    continue
                role_names.add(row.role.name)
                all_perms.update(p.key for p in row.role.permissions)
            return AuthContext(
                user_id=UserId(rows[0].user_id),
                organization_id=OrgId(rows[0].organization_id),
                role_names=frozenset(role_names),
                perms=frozenset(all_perms),
            )

    async def list_for_user(self, user_id: UserId) -> list[Membership]:
        async with self.session_factory() as session:
            rows = (
                await session.execute(
                    select(self.model)
                    .options(selectinload(self.model.role))
                    .where(self.model.user_id == user_id.value)
                )
            ).scalars().all()
            return [_to_membership(r, _role_name(r)) for r in rows]
