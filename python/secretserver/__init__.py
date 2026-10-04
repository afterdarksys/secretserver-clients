"""SecretServer.io Python client library."""

from .client import (
    AuthError,
    CliCredentialProvider,
    ConflictError,
    ETagDict,
    NotFoundError,
    PermissionError,
    SecretServerClient,
    RemoteSigningKey,
    SecretServerError,
    cli_credential_provider,
)

__all__ = [
    "SecretServerClient",
    "RemoteSigningKey",
    "SecretServerError",
    "AuthError",
    "CliCredentialProvider",
    "cli_credential_provider",
    "ConflictError",
    "ETagDict",
    "NotFoundError",
    "PermissionError",
]

__version__ = "1.4.0"
