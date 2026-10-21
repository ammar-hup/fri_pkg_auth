"""Authentication exceptions.

Authorization-related exceptions live in
``pkg_auth.authorization.domain.exceptions`` (added in M2).
"""
from __future__ import annotations


class AuthenticationError(Exception):
    """Base for all authentication failures."""


class TokenExpiredError(AuthenticationError):
    """The token's ``exp`` claim is in the past."""


class InvalidTokenError(AuthenticationError):
    """Token is malformed, has an invalid signature, or fails verification."""


class ServiceTokenError(AuthenticationError):
    """Keycloak did not issue this service's own (client-credentials) token."""
