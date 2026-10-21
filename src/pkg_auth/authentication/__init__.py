"""Authentication module: JWT validation and identity projection.

Public API:

    IdentityContext             — frozen identity snapshot from a JWT
    Subject, EmailAddress, RealmName  — identity value objects
    TokenDecoder                — Protocol port for token verification
    AuthenticateTokenUseCase    — token → IdentityContext
    AuthenticationError, TokenExpiredError, InvalidTokenError, ServiceTokenError
"""
from __future__ import annotations

from .application.use_cases.authenticate import AuthenticateTokenUseCase
from .domain.entities import IdentityContext
from .domain.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    ServiceTokenError,
    TokenExpiredError,
)
from .domain.ports import TokenDecoder
from .domain.value_objects import EmailAddress, RealmName, Subject

__all__ = [
    "IdentityContext",
    "Subject",
    "EmailAddress",
    "RealmName",
    "TokenDecoder",
    "AuthenticateTokenUseCase",
    "AuthenticationError",
    "TokenExpiredError",
    "InvalidTokenError",
    "ServiceTokenError",
]
