"""FastAPI integration for pkg_auth (identity + ACL)."""
from __future__ import annotations

try:
    import fastapi  # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pkg_auth.integrations.fastapi requires fastapi. "
        "Install with: pip install pkg-auth[fastapi]"
    ) from exc

from .auth_factory import Authentication, create_authentication
from .auth_context_dep import ON_BEHALF_OF_HEADER, make_get_auth_context
from .decorators import require_permission
from .errors import install_exception_handlers
from .identity_dep import bearer_scheme, extract_token_from_request

__all__ = [
    "Authentication",
    "create_authentication",
    "make_get_auth_context",
    "ON_BEHALF_OF_HEADER",
    "require_permission",
    "install_exception_handlers",
    "bearer_scheme",
    "extract_token_from_request",
]
