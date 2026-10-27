"""Default concrete ORM models for the bundled ACL (UUID PKs).

.. warning::
   **Mode B only.** These concrete ``*ORM`` classes inherit from
   ``AclBase`` — the bundled declarative base whose ``MetaData``
   emits unqualified table names (resolving via the database
   ``search_path``). They are ready to use out of the box for
   *consuming* services (Mode B) that point their own sessionmaker
   at the shared ACL database.

   **Do NOT import any class from this module into a Mode A service**
   (one that extends the mixins to add service-specific columns, e.g.
   ``itq_users``). Mode A services own the ACL schema and define
   their own concrete models against their own ``DeclarativeBase``.
   Accidentally importing ``UserORM`` / ``OrganizationORM`` / … into
   a Mode A service splits its models across two metadata objects
   and breaks ``metadata.create_all`` / migration tooling.

   Mode A services must:

   - Import the abstract column mixins from
     ``pkg_auth.authorization.adapters.sqlalchemy.mixins`` (NOT from
     this module or ``base.py``)
   - Define their own concrete ``*ORM`` classes against their own
     ``DeclarativeBase``
   - Write their own Alembic migrations

   See ``docs/Django.md`` for the Mode A vs Mode B distinction.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import AclBase
from .mixins import (
    MembershipMixin,
    OrganizationMixin,
    OrganizationServiceMixin,
    PermissionMixin,
    RoleMixin,
    ServiceMixin,
    UserMixin,
)


class UserORM(AclBase, UserMixin):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    memberships: Mapped[list["MembershipORM"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class OrganizationORM(AclBase, OrganizationMixin):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    memberships: Mapped[list["MembershipORM"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    roles: Mapped[list["RoleORM"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )


class PermissionORM(AclBase, PermissionMixin):
    __tablename__ = "permissions"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )


class ServiceORM(AclBase, ServiceMixin):
    __tablename__ = "services"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )


class OrganizationServiceORM(AclBase, OrganizationServiceMixin):
    __tablename__ = "organization_services"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "service_name",
            name="uq_org_services_org_service",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
    )


class RoleORM(AclBase, RoleMixin):
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_roles_org_name"),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
    )

    organization: Mapped[OrganizationORM | None] = relationship(
        back_populates="roles"
    )
    permissions: Mapped[list[PermissionORM]] = relationship(
        secondary="role_permissions"
    )
    memberships: Mapped[list["MembershipORM"]] = relationship(
        back_populates="role"
    )


class RolePermissionORM(AclBase):
    __tablename__ = "role_permissions"

    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )


class MembershipORM(AclBase, MembershipMixin):
    """Mirrors ``users:AD-8``: ``role_id`` NULL is a roleless member, at
    most one per ``(organization_id, user_id)``."""

    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "user_id", "role_id",
            name="uq_memberships_org_user_role_id",
        ),
        Index(
            "uq_memberships_org_user_roleless",
            "organization_id", "user_id",
            unique=True,
            postgresql_where=text("role_id IS NULL"),
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
    )
    role_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(32), server_default="active")

    user: Mapped[UserORM] = relationship(back_populates="memberships")
    organization: Mapped[OrganizationORM] = relationship(
        back_populates="memberships"
    )
    role: Mapped[RoleORM | None] = relationship(back_populates="memberships")


class MembershipInvitationORM(AclBase):
    __tablename__ = "membership_invitations"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
    )
    email: Mapped[str] = mapped_column(String(255), index=True)
    role_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("roles.id", ondelete="RESTRICT"),
    )
    token: Mapped[str] = mapped_column(String(64), unique=True)
    invited_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuthAuditLogORM(AclBase):
    __tablename__ = "auth_audit_log"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    actor_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    action: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )
    request_id: Mapped[str | None] = mapped_column(String(64))
