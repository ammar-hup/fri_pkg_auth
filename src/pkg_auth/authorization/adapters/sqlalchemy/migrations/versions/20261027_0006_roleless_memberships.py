"""Allow roleless memberships and mirror itq_users' constraint names.

Revision ID: pkg_auth_acl_0006
Revises: pkg_auth_acl_0005
Create Date: 2026-10-27 00:00:00.000000

Mirrors ``users:AD-8``: ``memberships.role_id`` becomes nullable (a NULL
role is a member with no role), the multi-role unique constraint takes
the live name ``uq_memberships_org_user_role_id`` on
``(organization_id, user_id, role_id)``, and the partial unique index
``uq_memberships_org_user_roleless`` allows one roleless row per
``(organization_id, user_id)``.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "pkg_auth_acl_0006"
down_revision: Union[str, None] = "pkg_auth_acl_0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "memberships", "role_id", existing_type=sa.Uuid(as_uuid=True), nullable=True,
    )
    op.drop_constraint(
        "uq_memberships_user_org_role", "memberships", type_="unique",
    )
    op.create_unique_constraint(
        "uq_memberships_org_user_role_id",
        "memberships",
        ["organization_id", "user_id", "role_id"],
    )
    op.create_index(
        "uq_memberships_org_user_roleless",
        "memberships",
        ["organization_id", "user_id"],
        unique=True,
        postgresql_where=sa.text("role_id IS NULL"),
    )


def downgrade() -> None:
    """Restore the pre-0006 schema.

    This is NOT a rollback path once a roleless row exists: the change is
    forward-only (``estate:AD-29``). Restoring ``NOT NULL`` on ``role_id``
    fails while any ``role_id IS NULL`` row is present, and deleting those
    rows to make it pass would silently remove memberships. It therefore
    refuses before touching the schema while any roleless row exists.
    """
    roleless = op.get_bind().execute(
        sa.text("SELECT 1 FROM memberships WHERE role_id IS NULL LIMIT 1")
    ).first()
    if roleless is not None:
        raise RuntimeError(
            "pkg_auth_acl_0006 is forward-only once roleless memberships "
            "exist: memberships has rows with role_id IS NULL, so role_id "
            "cannot be made NOT NULL again. Downgrade refused; schema unchanged."
        )
    op.drop_index("uq_memberships_org_user_roleless", table_name="memberships")
    op.drop_constraint(
        "uq_memberships_org_user_role_id", "memberships", type_="unique",
    )
    op.create_unique_constraint(
        "uq_memberships_user_org_role",
        "memberships",
        ["user_id", "organization_id", "role_id"],
    )
    op.alter_column(
        "memberships", "role_id", existing_type=sa.Uuid(as_uuid=True), nullable=False,
    )
