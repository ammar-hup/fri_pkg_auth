"""Configure Django once for this package, with the ACL app and SQLite.

Configured here (before any module in this directory is imported) so the
ACL mirror models can be imported and queried by the repository tests.
"""
from __future__ import annotations

import os
import tempfile

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        DEFAULT_CHARSET="utf-8",
        ALLOWED_HOSTS=["*"],
        USE_TZ=True,
        INSTALLED_APPS=["pkg_auth.authorization.adapters.django_orm"],
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": os.path.join(
                    tempfile.mkdtemp(prefix="pkg_auth_django_"), "acl.sqlite3"
                ),
            }
        },
    )
    django.setup()
