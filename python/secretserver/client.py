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
    USER_AGENT = "secretserver-python/1.0.0"

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
            from datetime import datetime, timedelta
            body["expires_at"] = (datetime.utcnow() + timedelta(hours=expires_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self._post(f"/{secret_type}/{secret_id}/shares", body)

    def create_temp_access(self, secret_type: str, secret_id: str, duration_seconds: int = 900) -> Dict:
        """Returns dict with 'token' and 'expires_at'."""
        return self._post(f"/{secret_type}/{secret_id}/temp-access", {"duration_seconds": duration_seconds})

    # ------------------------------------------------------------------
    # Intelligence
    # ------------------------------------------------------------------

    def check_breach(self, value: str) -> Dict:
        return self._post("/intelligence/check-breach", {"value": value})

    # ------------------------------------------------------------------
    # Transform
    # ------------------------------------------------------------------

    def encode(self, data: str, format: str = "base64") -> str:
        result = self._post("/transform/encode", {"data": data, "format": format})
        return result.get("result", "")

    def decode(self, data: str, format: str = "base64") -> str:
        result = self._post("/transform/decode", {"data": data, "format": format})
        return result.get("result", "")
