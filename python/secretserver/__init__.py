"""SecretServer.io Python client library."""

from .client import SecretServerClient, SecretServerError, AuthError, NotFoundError, PermissionError

__all__ = [
    "SecretServerClient",
    "SecretServerError",
    "AuthError",
    "NotFoundError",
    "PermissionError",
]

__version__ = "1.0.0"
