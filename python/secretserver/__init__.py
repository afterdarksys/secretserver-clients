"""SecretServer.io Python client library."""

from .client import (
    AuthError,
    ConflictError,
    ETagDict,
    NotFoundError,
    PermissionError,
    SecretServerClient,
    SecretServerError,
)

__all__ = [
    "SecretServerClient",
    "SecretServerError",
    "AuthError",
    "ConflictError",
    "ETagDict",
    "NotFoundError",
    "PermissionError",
]

__version__ = "1.3.0"
