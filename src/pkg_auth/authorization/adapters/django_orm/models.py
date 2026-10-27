"""Default concrete Django ORM mirror models for the ACL (UUID PKs).

.. warning::
   **Mode B only.** These models declare ``Meta.managed = False`` and
   map to the default ACL table names (``users``, ``organizations``,
   …) so consuming services (Mode B) can read the shared ACL tables
   via Django's ORM without owning the schema. The schema is owned
   by the source-of-truth service.

   **Do NOT import any class from this module into a Mode A service**
   (one that extends the mixins to add service-specific columns, e.g.
   a Django version of ``itq_users``). Mode A services own the ACL
   schema, run their own migrations with ``Meta.managed = True``, and
   define their own concrete models.

   Mode A services must:

   - Import the abstract column mixins from
     ``pkg_auth.authorization.adapters.django_orm.mixins`` (NOT from
     this module)
   - Define their own concrete models with their own ``db_table`` and
     ``Meta.managed = True``
   - Run their own ``manage.py migrate`` (not ``alembic upgrade``)
   - Inject their concrete model classes into the package repos via
     ``DjangoUserRepository(model=MyUser)`` etc.

   See ``docs/Django.md`` for the Mode A vs Mode B distinction.
"""
from __future__ import annotations

import uuid

from django.db import models

from .mixins import (
    MembershipMixin,
    OrganizationMixin,
    OrganizationServiceMixin,
    PermissionMixin,
    RoleMixin,
    ServiceMixin,
    UserMixin,
)


class User(UserMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        managed = False
        db_table = "users"
        app_label = "pkg_auth_acl"


class Organization(OrganizationMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        managed = False
        db_table = "organizations"
        app_label = "pkg_auth_acl"


class Permission(PermissionMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        managed = False
        db_table = "permissions"
        app_label = "pkg_auth_acl"


class Service(ServiceMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        managed = False
        db_table = "services"
        app_label = "pkg_auth_acl"


class OrganizationService(OrganizationServiceMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        db_column="organization_id",
        related_name="services",
    )

    class Meta:
        managed = False
        db_table = "organization_services"
        app_label = "pkg_auth_acl"
        unique_together = (("organization", "service_name"),)


class Role(RoleMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        db_column="organization_id",
        related_name="roles",
    )
    permissions = models.ManyToManyField(
        Permission,
        through="RolePermission",
        related_name="roles",
    )

    class Meta:
        managed = False
        db_table = "roles"
        app_label = "pkg_auth_acl"
        unique_together = (("organization", "name"),)


class RolePermission(models.Model):
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        db_column="role_id",
        related_name="role_permissions",
    )
    permission = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        db_column="permission_id",
        related_name="role_permissions",
    )

    class Meta:
        managed = False
        db_table = "role_permissions"
        app_label = "pkg_auth_acl"
        unique_together = (("role", "permission"),)


class Membership(MembershipMixin):
    """Multi-role-aware: ``UNIQUE(organization, user, role)``.

    A user can hold multiple memberships in the same organization (one row
    per role); ``DjangoMembershipRepository.load_auth_context`` aggregates
    them into the union of all active roles' permissions.

    ``role`` NULL is a roleless member (``users:AD-8``): at most one such
    row per ``(organization, user)``, contributing no role and no
    permission.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        db_column="user_id",
        related_name="memberships",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        db_column="organization_id",
        related_name="memberships",
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        db_column="role_id",
        related_name="memberships",
    )
    status = models.CharField(max_length=32, default="active")

    class Meta:
        managed = False
        db_table = "memberships"
        app_label = "pkg_auth_acl"
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "user", "role"],
                name="uq_memberships_org_user_role_id",
            ),
            models.UniqueConstraint(
                fields=["organization", "user"],
                condition=models.Q(role__isnull=True),
                name="uq_memberships_org_user_roleless",
            ),
        ]


class MembershipInvitation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        db_column="organization_id",
    )
    email = models.CharField(max_length=255)
    role = models.ForeignKey(
        Role,
        on_delete=models.PROTECT,
        db_column="role_id",
    )
    token = models.CharField(max_length=64, unique=True)
    invited_by_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        db_column="invited_by_user_id",
    )
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed = False
        db_table = "membership_invitations"
        app_label = "pkg_auth_acl"


class AuthAuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        db_column="actor_user_id",
    )
    action = models.CharField(max_length=128)
    target_type = models.CharField(max_length=64)
    target_id = models.CharField(max_length=64)
    payload = models.JSONField()
    occurred_at = models.DateTimeField(auto_now_add=True)
    request_id = models.CharField(max_length=64, null=True)

    class Meta:
        managed = False
        db_table = "auth_audit_log"
        app_label = "pkg_auth_acl"
