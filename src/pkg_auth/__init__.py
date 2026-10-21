"""pkg_auth: clean-architecture identity + ACL for Python services.

Importing this top-level package gives you only the version. Reach for
specific surfaces via the sub-packages:

    from pkg_auth.authentication import IdentityContext, AuthenticateTokenUseCase
    from pkg_auth.authentication.adapters.keycloak import JWTTokenDecoder

Authorization (ACL) and framework integrations (FastAPI, Django,
Strawberry) are available via sub-packages.
"""

__version__ = "3.2.0"

__all__ = ["__version__"]
