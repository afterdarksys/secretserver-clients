"""SecretServer.io Python client."""

from __future__ import annotations

import os
import json
import urllib.request
import urllib.error
import ssl
from typing import Any, Dict, List, Optional, Union


class SecretServerError(Exception):
    """Base exception for SecretServer client errors."""
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


class AuthError(SecretServerError):
    """Raised on 401 Unauthorized."""


class PermissionError(SecretServerError):
    """Raised on 403 Forbidden."""


class NotFoundError(SecretServerError):
    """Raised on 404 Not Found."""


class SecretServerClient:
    """
    SecretServer.io API client.

    Usage::

        from secretserver import SecretServerClient

        ss = SecretServerClient(api_key="sk_...")
        value = ss.secret("production/database-password")
        print(value)

    Authentication:
        api_key — API key (or set SS_API_KEY env var)
        api_url — Base URL (or set SS_API_URL env var, default https://api.secretserver.io)
    """

    DEFAULT_URL = "https://api.secretserver.io"
    USER_AGENT = "secretserver-python/1.2.0"

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: int = 10,
        verify_ssl: bool = True,
    ):
        self.api_key = api_key or os.environ.get("SS_API_KEY", "")
        self.api_url = (api_url or os.environ.get("SS_API_URL", self.DEFAULT_URL)).rstrip("/")
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()

        if not self.api_key:
            raise AuthError("No API key provided. Set api_key= or SS_API_KEY env var.")

    # ------------------------------------------------------------------
    # Core HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.USER_AGENT,
        }

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
    ) -> Any:
        url = f"{self.api_url}/api/v1{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                detail = json.loads(raw).get("error", str(e))
            except Exception:
                detail = str(e)
            if e.code == 401:
                raise AuthError(detail, status_code=401) from e
            if e.code == 403:
                raise PermissionError(detail, status_code=403) from e
            if e.code == 404:
                raise NotFoundError(detail, status_code=404) from e
            raise SecretServerError(detail, status_code=e.code) from e
        except urllib.error.URLError as e:
            raise SecretServerError(f"Connection error: {e.reason}") from e

    def _get(self, path: str) -> Any:
        return self._request("GET", path)

    def _post(self, path: str, body: Any = None) -> Any:
        return self._request("POST", path, body)

    def _put(self, path: str, body: Any = None) -> Any:
        return self._request("PUT", path, body)

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    # ------------------------------------------------------------------
    # Path-based secret access (primary interface)
    # ------------------------------------------------------------------

    def secret(self, path: str) -> str:
        """
        Get a secret value by path: container/key or container/key/version.

        >>> ss.secret("production/db-password")
        'hunter2'
        >>> ss.secret("production/db-password/2")  # previous version
        'old-hunter2'
        """
        parts = path.strip("/").split("/")
        if len(parts) == 1:
            data = self._get(f"/secrets/{parts[0]}")
            return data.get("value", data.get("data", {}).get("value", ""))
        elif len(parts) == 2:
            data = self._get(f"/s/{parts[0]}/{parts[1]}")
            return data.get("value", "")
        else:
            data = self._get(f"/s/{parts[0]}/{parts[1]}/{parts[2]}")
            return data.get("value", "")

    def get_secret(self, path: str) -> Dict[str, Any]:
        """Get full secret metadata + value dict for a path."""
        parts = path.strip("/").split("/")
        if len(parts) == 1:
            return self._get(f"/secrets/{parts[0]}")
        return self._get(f"/s/{'/'.join(parts)}")

    # ------------------------------------------------------------------
    # Secrets
    # ------------------------------------------------------------------

    def list_secrets(self) -> List[Dict]:
        return self._get("/secrets") or []

    def create_secret(self, name: str, value: str, description: str = "", container_id: str = "") -> Dict:
        body: Dict[str, Any] = {"name": name, "data": {"value": value}}
        if description:
            body["description"] = description
        if container_id:
            body["container_id"] = container_id
        return self._post("/secrets", body)

    def update_secret(self, name: str, value: str) -> Dict:
        return self._put(f"/secrets/{name}", {"data": {"value": value}})

    def delete_secret(self, name: str) -> None:
        self._delete(f"/secrets/{name}")

    # ------------------------------------------------------------------
    # Containers
    # ------------------------------------------------------------------

    def list_containers(self) -> List[Dict]:
        return self._get("/containers") or []

    def create_container(self, name: str, slug: str = "", description: str = "") -> Dict:
        body: Dict[str, Any] = {"name": name}
        if slug:
            body["slug"] = slug
        if description:
            body["description"] = description
        return self._post("/containers", body)

    # ------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------

    def list_certificates(self) -> List[Dict]:
        return self._get("/certificates") or []

    def get_certificate(self, cert_id: str) -> Dict:
        return self._get(f"/certificates/{cert_id}")

    def enroll_certificate(self, name: str, common_name: str, sans: Optional[List[str]] = None, auto_renew: bool = True) -> Dict:
        return self._post("/certificates/enroll", {
            "name": name,
            "common_name": common_name,
            "sans": sans or [],
            "auto_renew": auto_renew,
        })

    def renew_certificate(self, cert_id: str) -> Dict:
        return self._post(f"/certificates/{cert_id}/renew")

    # ------------------------------------------------------------------
    # SSH Keys
    # ------------------------------------------------------------------

    def list_ssh_keys(self) -> List[Dict]:
        return self._get("/ssh-keys") or []

    def generate_ssh_key(self, name: str, key_type: str = "ed25519", comment: str = "") -> Dict:
        return self._post("/ssh-keys/generate", {"name": name, "key_type": key_type, "comment": comment})

    def import_ssh_key(self, name: str, private_key: str) -> Dict:
        return self._post("/ssh-keys/import", {"name": name, "private_key": private_key})

    def export_ssh_key(self, key_id: str) -> Dict:
        return self._get(f"/ssh-keys/{key_id}/export")

    # ------------------------------------------------------------------
    # Passwords
    # ------------------------------------------------------------------

    def list_passwords(self) -> List[Dict]:
        return self._get("/passwords") or []

    def create_password(self, name: str, username: str, password: str, url: str = "") -> Dict:
        body: Dict[str, Any] = {"name": name, "username": username, "password": password}
        if url:
            body["url"] = url
        return self._post("/passwords", body)

    def generate_password(self, length: int = 32, special: bool = True) -> str:
        data = self._post("/passwords/generate", {"length": length, "include_symbols": special})
        return data.get("password", "")

    # ------------------------------------------------------------------
    # API Tokens
    # ------------------------------------------------------------------

    def list_api_tokens(self) -> List[Dict]:
        return self._get("/api-tokens") or []

    def create_api_token(self, name: str, service: str, token: str) -> Dict:
        return self._post("/api-tokens", {"name": name, "service": service, "token": token})

    def rotate_api_token(self, token_id: str) -> Dict:
        return self._post(f"/api-tokens/{token_id}/rotate")

    # ------------------------------------------------------------------
    # Version history
    # ------------------------------------------------------------------

    def get_history(self, secret_type: str, secret_id: str) -> List[Dict]:
        data = self._get(f"/{secret_type}/{secret_id}/history")
        return data.get("versions", [])

    def get_version(self, secret_type: str, secret_id: str, version: int) -> Dict:
        return self._get(f"/{secret_type}/{secret_id}/history/{version}")

    # ------------------------------------------------------------------
    # Sharing & temp access
    # ------------------------------------------------------------------

    def share(self, secret_type: str, secret_id: str, email: str, permission: str = "read", expires_hours: Optional[int] = 72) -> Dict:
        body: Dict[str, Any] = {"shared_with_email": email, "permission": permission}
        if expires_hours is not None:
            from datetime import datetime, timedelta, timezone
            body["expires_at"] = (datetime.now(timezone.utc) + timedelta(hours=expires_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self._post(f"/{secret_type}/{secret_id}/shares", body)

    def create_temp_access(self, secret_type: str, secret_id: str, duration_seconds: int = 900) -> Dict:
        """Returns dict with 'token' and 'expires_at'."""
        return self._post(f"/{secret_type}/{secret_id}/temp-access", {"duration_seconds": duration_seconds})

    # ------------------------------------------------------------------
    # Intelligence
    # ------------------------------------------------------------------

    def check_breach(self, value: str) -> Dict:
        return self._post("/intelligence/check-breach", {"password": value})

    # ------------------------------------------------------------------
    # Transform
    # ------------------------------------------------------------------

    def encode(self, data: str, format: str = "base64") -> str:
        result = self._post("/transform/encode", {"input": data, "target_type": format})
        return result.get("result", "")

    def decode(self, data: str, format: str = "base64") -> str:
        result = self._post("/transform/decode", {"input": data, "source_type": format})
        return result.get("result", "")

    # ------------------------------------------------------------------
    # GPG Keys
    # ------------------------------------------------------------------

    def list_gpg_keys(self) -> List[Dict]:
        return self._get("/gpg-keys") or []

    def get_gpg_key(self, key_id: str) -> Dict:
        return self._get(f"/gpg-keys/{key_id}")

    def generate_gpg_key(self, name: str, email: str, key_type: str = "rsa4096", expires_days: Optional[int] = None) -> Dict:
        body: Dict[str, Any] = {"name": name, "email": email, "key_type": key_type}
        if expires_days is not None:
            body["expires_in_days"] = expires_days
        return self._post("/gpg-keys/generate", body)

    def import_gpg_key(self, name: str, email: str, private_key: str) -> Dict:
        return self._post("/gpg-keys/import", {"name": name, "email": email, "private_key": private_key})

    def export_gpg_key(self, key_id: str) -> Dict:
        return self._get(f"/gpg-keys/{key_id}/export")

    def delete_gpg_key(self, key_id: str) -> None:
        self._delete(f"/gpg-keys/{key_id}")

    # ------------------------------------------------------------------
    # Extended credential types (generic helper)
    # ------------------------------------------------------------------

    def credentials(self, resource: str) -> 'CredentialResource':
        """
        Generic CRUD accessor for extended credential types.

        Usage:
            ss.credentials("computer-credentials").list()
            ss.credentials("wifi-credentials").create({...})
            ss.credentials("disk-credentials").get(id)

        Supported resources:
            - computer-credentials
            - wifi-credentials
            - windows-credentials
            - social-credentials
            - disk-credentials
            - service-config
            - root-credentials
            - ldap-bind-credentials
            - integrations
            - code-signing-keys
        """
        return CredentialResource(self, resource)

    # ------------------------------------------------------------------
    # OpenSSL Keys
    # ------------------------------------------------------------------

    def list_openssl_keys(self) -> List[Dict]:
        return self._get("/openssl-keys") or []

    def get_openssl_key(self, key_id: str) -> Dict:
        return self._get(f"/openssl-keys/{key_id}")

    def generate_openssl_key(self, name: str, key_type: str = "rsa", bits: int = 4096) -> Dict:
        return self._post("/openssl-keys/generate", {"name": name, "key_type": key_type, "bits": bits})

    def import_openssl_key(self, name: str, private_key: str) -> Dict:
        return self._post("/openssl-keys/import", {"name": name, "private_key": private_key})

    def export_openssl_key(self, key_id: str) -> Dict:
        return self._get(f"/openssl-keys/{key_id}/export")

    def delete_openssl_key(self, key_id: str) -> None:
        self._delete(f"/openssl-keys/{key_id}")

    # ------------------------------------------------------------------
    # NTLM Hashes
    # ------------------------------------------------------------------

    def list_ntlm_hashes(self) -> List[Dict]:
        return self._get("/ntlm") or []

    def get_ntlm_hash(self, hash_id: str) -> Dict:
        return self._get(f"/ntlm/{hash_id}")

    def create_ntlm_hash(self, name: str, username: str, hash_value: str) -> Dict:
        return self._post("/ntlm", {"name": name, "username": username, "hash": hash_value})

    def update_ntlm_hash(self, hash_id: str, data: Dict) -> Dict:
        return self._put(f"/ntlm/{hash_id}", data)

    def delete_ntlm_hash(self, hash_id: str) -> None:
        self._delete(f"/ntlm/{hash_id}")

    # ------------------------------------------------------------------
    # Certificates (extended operations)
    # ------------------------------------------------------------------

    def revoke_certificate(self, cert_id: str) -> Dict:
        return self._post(f"/certificates/{cert_id}/revoke")

    def download_certificate(self, cert_id: str) -> Dict:
        return self._get(f"/certificates/{cert_id}/download")

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------

    def list_webhooks(self) -> List[Dict]:
        return self._get("/webhooks") or []

    def create_webhook(self, name: str, url: str, events: List[str], auth_type: str = "none") -> Dict:
        return self._post("/webhooks", {
            "name": name,
            "url": url,
            "events": events,
            "auth_type": auth_type,
        })

    def get_webhook_deliveries(self, webhook_id: str) -> List[Dict]:
        return self._get(f"/webhooks/{webhook_id}/deliveries") or []

    def test_webhook(self, webhook_id: str) -> Dict:
        return self._post(f"/webhooks/{webhook_id}/test")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_to_keychain(self, items: List[Dict]) -> Dict:
        return self._post("/export/keychain", {"items": items})

    def export_to_credential_manager(self, items: List[Dict]) -> Dict:
        return self._post("/export/credential-manager", {"items": items})

    def export_to_json(self, items: List[Dict]) -> Dict:
        return self._post("/export/json", {"items": items})

    # ------------------------------------------------------------------
    # Audit logs
    # ------------------------------------------------------------------

    def get_audit_logs(self, limit: int = 100, offset: int = 0, action: str = "") -> Dict:
        params = {"limit": str(limit), "offset": str(offset)}
        if action:
            params["action"] = action
        query = "&".join([f"{k}={v}" for k, v in params.items()])
        return self._get(f"/audit/logs?{query}")

    def export_audit_logs(self) -> Dict:
        return self._get("/audit/logs/export")

    # ------------------------------------------------------------------
    # TOTP Authenticators
    # ------------------------------------------------------------------

    def list_totp_tokens(self) -> List[Dict]:
        """List all TOTP authenticator tokens."""
        return self._get("/totp-tokens") or []

    def get_totp_token(self, id: str) -> Dict:
        """Get a specific TOTP token by ID."""
        return self._get(f"/totp-tokens/{id}")

    def create_totp_token(
        self,
        name: str,
        issuer: str,
        account_name: str,
        secret_key: str,
        algorithm: str = "SHA1",
        digits: int = 6,
        period: int = 30
    ) -> Dict:
        """
        Create a new TOTP token.

        Args:
            name: Display name for the token
            issuer: Issuer name (e.g., "GitHub", "AWS")
            account_name: Account identifier (e.g., email or username)
            secret_key: Base32-encoded secret key
            algorithm: Hash algorithm (SHA1, SHA256, SHA512)
            digits: Number of digits in the code (6 or 8)
            period: Time period in seconds (default 30)
        """
        return self._post("/totp-tokens", {
            "name": name,
            "issuer": issuer,
            "account_name": account_name,
            "secret_key": secret_key,
            "algorithm": algorithm,
            "digits": digits,
            "period": period,
        })

    def update_totp_token(self, id: str, data: Dict) -> Dict:
        """Update a TOTP token."""
        return self._put(f"/totp-tokens/{id}", data)

    def delete_totp_token(self, id: str) -> None:
        """Delete a TOTP token."""
        self._delete(f"/totp-tokens/{id}")

    def generate_totp_code(self, id: str) -> Dict:
        """
        Generate a TOTP code for the given token.

        Returns dict with 'code' and 'expires_in' (seconds remaining).
        """
        return self._post(f"/totp-tokens/{id}/generate")

    # ------------------------------------------------------------------
    # YubiKey OTP Credentials
    # ------------------------------------------------------------------

    def list_yubikeys(self) -> List[Dict]:
        return self._get("/yubikeys") or []

    def get_yubikey(self, yubikey_id: str) -> Dict:
        return self._get(f"/yubikeys/{yubikey_id}")

    def create_yubikey(self, name: str, public_id: str, client_id: str, api_key: str,
                       serial_number: str = "", validation_server: str = "", notes: str = "") -> Dict:
        body: Dict[str, Any] = {"name": name, "public_id": public_id, "client_id": client_id, "api_key": api_key}
        if serial_number:
            body["serial_number"] = serial_number
        if validation_server:
            body["validation_server"] = validation_server
        if notes:
            body["notes"] = notes
        return self._post("/yubikeys", body)

    def update_yubikey(self, yubikey_id: str, data: Dict) -> Dict:
        return self._put(f"/yubikeys/{yubikey_id}", data)

    def delete_yubikey(self, yubikey_id: str) -> None:
        self._delete(f"/yubikeys/{yubikey_id}")

    def validate_yubikey_otp(self, yubikey_id: str, otp: str) -> Dict:
        """Validate a Yubico OTP. Returns dict with 'valid' (bool) and 'checked_at'."""
        return self._post(f"/yubikeys/{yubikey_id}/validate", {"otp": otp})

    def import_totp_from_uri(self, uri: str) -> Dict:
        """
        Import a TOTP token from an otpauth:// URI.

        Args:
            uri: otpauth://totp/... URI string

        Returns the created TOTP token.
        """
        return self._post("/totp-tokens/import", {"uri": uri})

    def export_totp_to_uri(self, id: str) -> Dict:
        """
        Export a TOTP token to an otpauth:// URI.

        Returns dict with 'uri' and 'qr_code' (base64-encoded PNG).
        """
        return self._get(f"/totp-tokens/{id}/export")


# -----------------------------------------------------------------------
# Credential resource helper
# -----------------------------------------------------------------------

class CredentialResource:
    """Helper class for CRUD operations on extended credential types."""

    def __init__(self, client: 'SecretServerClient', resource: str):
        self._client = client
        self._resource = resource

    def list(self) -> List[Dict]:
        return self._client._get(f"/{self._resource}") or []

    def get(self, id: str) -> Dict:
        return self._client._get(f"/{self._resource}/{id}")

    def create(self, data: Dict) -> Dict:
        return self._client._post(f"/{self._resource}", data)

    def update(self, id: str, data: Dict) -> Dict:
        return self._client._put(f"/{self._resource}/{id}", data)

    def delete(self, id: str) -> None:
        self._client._delete(f"/{self._resource}/{id}")
