"""SecretServer.io Python client."""

from __future__ import annotations

import os
import base64
import threading
import json
import re
import urllib.request
import urllib.error
import ssl
import uuid
from datetime import datetime, timezone
from urllib.parse import quote, urlencode, urlsplit
from typing import Any, Callable, Dict, List, Optional, Union

_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_RAW_BYTES = 16 * 1024 * 1024
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")

# A strong or weak entity tag (RFC 9110 section 8.8.3). Only an ETag the
# server sent proves it applies partial updates; servers before 3075630
# ignore If-Match and treat PUT as a full replace.
_ENTITY_TAG = re.compile(r'(?:W/)?"[\x21\x23-\x7e\x80-\xff]*"')
_PARTIAL_UPDATES_REQUIRED = (
    "partial updates require secretserver.io 3075630 or newer; "
    "pass an ETag from get() as if_match or enable partial_updates"
)

# Marks an optional update argument the caller did not pass: it is omitted
# from the request, so the server keeps the stored value. ``None`` is sent as
# JSON null, which clears the field.
_UNSET: Any = object()

# Values accepted by the server for :type in history, share and temp-access routes.
SECRET_TYPES = frozenset({
    "secret", "password", "ssh_key", "gpg_key", "api_token", "openssl_key", "ntlm_hash",
    "certificate", "computer_credential", "wifi_credential", "windows_credential",
    "social_credential", "disk_credential", "service_config_credential", "root_credential",
    "ldap_bind_credential", "integration_credential", "code_signing_key",
})


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


class ConflictError(SecretServerError):
    """Raised on 409 Conflict, e.g. a stale If-Match on an update.

    ``etag`` is the resource's current ETag from the response header (or
    None when the server sent none); re-read the resource and retry with it.
    """
    def __init__(self, message: str, status_code: int = 409, etag: Optional[str] = None):
        super().__init__(message, status_code)
        self.etag = etag


class ETagDict(dict):
    """A response object that also carries the response's ``ETag`` header.

    It behaves exactly like the dict the server returned; ``etag`` is the
    header value (for example ``'"2026-09-27T10:00:00.123456789Z"'``) or None
    when the server sent none. Pass it back as ``if_match`` to make an update
    conditional.
    """
    def __init__(self, data: Dict[str, Any], etag: Optional[str] = None):
        super().__init__(data)
        self.etag = etag


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_base_url(api_url: str) -> str:
    """Return the normalized base URL or raise ValueError.

    Only https is accepted, except plain http to a loopback host. URLs that
    carry credentials, a query or a fragment are rejected. The message never
    echoes the URL, which may contain credentials.
    """
    url = api_url.strip().rstrip("/")
    if url.endswith("/api/v1"):
        url = url[:-7]
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - raises ValueError on an invalid port
    except ValueError:
        raise ValueError("api_url is not a valid URL") from None
    if "@" in parts.netloc:
        raise ValueError("api_url must not contain credentials")
    if parts.query or parts.fragment or not host:
        raise ValueError("api_url must be a plain https base URL")
    scheme = parts.scheme.lower()
    if scheme == "https" or (scheme == "http" and host in _LOOPBACK_HOSTS):
        return url
    raise ValueError("api_url must use https (plain http is allowed only for localhost)")


def _seg(value: Any) -> str:
    """Percent-encode one caller-supplied path segment."""
    text = str(value)
    if text in ("", ".", ".."):
        raise ValueError("path segment must not be empty, '.' or '..'")
    return quote(text, safe="")


def _if_match(value: Any, allow_version: bool = False) -> Optional[str]:
    """Validate an If-Match value: an ETag string or, where allowed, a version number."""
    if value is None:
        return None
    if allow_version and isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if not isinstance(value, str) or not value.strip() or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError("if_match must be a non-empty ETag string" + (" or a version number" if allow_version else ""))
    return value


def _secret_type(secret_type: str) -> str:
    if secret_type not in SECRET_TYPES:
        raise ValueError("unsupported secret_type")
    return secret_type


def _uuid(value: Any, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        raise ValueError(f"{field} must be a UUID") from None


def _timestamp(value: Any) -> str:
    """RFC 3339 string for a datetime (naive values are treated as UTC) or a passthrough string."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def _audit_filters(**filters: Any) -> Dict[str, str]:
    params: Dict[str, str] = {}
    for key, value in filters.items():
        if value is None or value == "":
            continue
        if key in ("resource_id", "user_id"):
            params[key] = _uuid(value, key)
        elif key in ("start_date", "end_date"):
            params[key] = _timestamp(value)
        else:
            params[key] = str(value)
    return params


def _secret_route(path: str) -> str:
    """API route for name, container/key or container/key/version (1..12)."""
    parts = path.strip("/").split("/")
    if len(parts) == 1:
        return f"/secrets/{_seg(parts[0])}"
    if len(parts) == 2:
        return f"/s/{_seg(parts[0])}/{_seg(parts[1])}"
    if len(parts) == 3:
        try:
            version = int(parts[2])
        except ValueError:
            raise ValueError("version must be an integer") from None
        if not 1 <= version <= 12:
            raise ValueError("version must be between 1 and 12")
        return f"/s/{_seg(parts[0])}/{_seg(parts[1])}/{version}"
    raise ValueError("path must be name, container/key or container/key/version")


def _scalar(payload):
    if not isinstance(payload, dict):
        raise SecretServerError("Invalid secret response")
    data = payload.get("data", payload)
    if isinstance(data, dict):
        for key in ("value", "password", "token", "key", "passphrase", "bind_password", "certificate"):
            if isinstance(data.get(key), str):
                return data[key]
    raise SecretServerError("Secret response has no supported scalar field")


class _Credential:
    """Best-effort owned-buffer cleanup, not locked memory or erasure of prior copies."""
    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = bytearray(value, "utf-8")

    def text(self) -> str:
        return self._value.decode("utf-8")

    def close(self):
        self._value[:] = b"\0" * len(self._value)
        self._value.clear()

    def __repr__(self):
        return "<redacted credential>"

    def __reduce__(self):
        raise TypeError("credentials cannot be serialized")


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
        api_url — Base URL (or set SS_API_URL env var, default https://api.secretserver.io).
                  Must be https; plain http is accepted only for localhost.
        ca_file — PEM bundle used to trust a private CA. It is added to the
                  system trust store (public CAs remain trusted). TLS
                  verification cannot be disabled; ``verify_ssl=False`` raises
                  ValueError.

    Partial updates (minimum server: secretserver.io 3075630):
        ``update_secret``, ``update_jks_keystore`` and ``update_yubikey`` send
        only the fields you pass. Older servers treat that PUT as a full
        replace and silently blank the omitted fields, so these methods refuse
        to send unless the client was built with ``partial_updates=True`` (or
        env SS_PARTIAL_UPDATES=1 when the argument is omitted) or the call
        passes an ETag (``"..."`` or ``W/"..."``) from a previous get() as
        ``if_match``.
    """

    DEFAULT_URL = "https://api.secretserver.io"
    USER_AGENT = "secretserver-python/1.3.0"

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: int = 10,
        verify_ssl: bool = True,
        ca_file: Optional[str] = None,
        partial_updates: Optional[bool] = None,
        credential_provider: Optional[Callable[[], str]] = None,
    ):
        if verify_ssl is not True:
            raise ValueError("TLS verification cannot be disabled; pass ca_file to trust a private CA")
        if credential_provider is not None and (not callable(credential_provider) or api_key is not None):
            raise ValueError("provide either api_key or a callable credential_provider")
        self._credential_lock = threading.RLock()
        self._closed = False
        self._credential_provider = credential_provider
        self._credential = _Credential("" if credential_provider is not None else (api_key or os.environ.get("SS_API_KEY", "")))
        self.api_url = _validate_base_url(api_url or os.environ.get("SS_API_URL", self.DEFAULT_URL))
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if partial_updates is None:
            partial_updates = os.environ.get("SS_PARTIAL_UPDATES", "") == "1"
        self.partial_updates = partial_updates is True
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context()
        if ca_file:
            self._ssl_ctx.load_verify_locations(cafile=ca_file)
        self._ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if self._credential_provider is None and not self.api_key:
            raise AuthError("No API key provided. Set api_key= or SS_API_KEY env var.")
        if any(ch in self.api_key for ch in "\r\n\0"):
            raise ValueError("api_key contains invalid characters")

    # ------------------------------------------------------------------
    # Core HTTP helpers
    # ------------------------------------------------------------------

    @property
    def api_key(self) -> str:
        """Compatibility accessor; explicitly creates an ordinary string copy."""
        with self._credential_lock:
            return self._credential.text()

    @api_key.setter
    def api_key(self, value: str):
        with self._credential_lock:
            if self._closed:
                raise SecretServerError("client is closed")
            if not isinstance(value, str) or any(ch in value for ch in "\r\n\0"):
                raise ValueError("invalid API key")
            self._credential.close()
            self._credential = _Credential(value)

    def close(self):
        with self._credential_lock:
            self._closed = True
            self._credential.close()
            self._credential_provider = None

    def __enter__(self):
        if self._closed:
            raise SecretServerError("client is closed")
        return self

    def __exit__(self, *_args):
        self.close()

    def __repr__(self):
        return "<SecretServerClient closed=%s credentials=redacted>" % self._closed

    def __reduce__(self):
        raise TypeError("authenticated clients cannot be serialized")

    def _headers(self) -> Dict[str, str]:
        with self._credential_lock:
            if self._closed:
                raise SecretServerError("client is closed")
            provider = self._credential_provider
            key = self.api_key if provider is None else None
        try:
            if provider is not None:
                key = provider()
        except Exception:
            raise AuthError("credential provider failed") from None
        if self._closed:
            raise SecretServerError("client is closed")
        if not isinstance(key, str) or not key or any(ch in key for ch in "\r\n\0"):
            raise AuthError("credential provider returned an invalid credential")
        return {
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.USER_AGENT,
        }

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
    ) -> Any:
        """Call any REST endpoint using a path relative to ``/api/v1``.

        ``path`` may be supplied as ``/secrets`` or ``/api/v1/secrets``.
        This public escape hatch keeps the client usable as the REST API grows
        before a convenience method is added. Callers must percent-encode any
        path segments and query values they interpolate into ``path``.
        """
        return self._send(method, path, body)

    def _send(self, method: str, path: str, body: Optional[Any] = None, raw: bool = False,
              if_match: Optional[str] = None, with_etag: bool = False, pdf: Optional[bytes] = None) -> Any:
        method = method.upper()
        if not path.startswith("/"):
            path = "/" + path
        if path == "/api/v1":
            path = ""
        elif path.startswith("/api/v1/"):
            path = path[7:]
        url = f"{self.api_url}/api/v1{path}"
        data = pdf if pdf is not None else (json.dumps(body).encode() if body is not None else None)
        headers = self._headers()
        if pdf is not None:
            headers["Content-Type"] = "application/pdf"
        if raw:
            headers["Accept"] = "*/*"
        if if_match is not None:
            headers["If-Match"] = if_match
        limit = _MAX_RAW_BYTES if raw else _MAX_JSON_BYTES
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=self._ssl_ctx))
            with opener.open(req, timeout=self.timeout) as resp:
                payload = resp.read(limit + 1)
                resp_headers = getattr(resp, "headers", None)
            if len(payload) > limit:
                raise SecretServerError("Response too large")
            if raw:
                return payload
            result = json.loads(payload) if payload else None
            if with_etag:
                return result, resp_headers.get("ETag") if resp_headers is not None else None
            return result
        except urllib.error.HTTPError as e:
            e.close()
            detail = f"SecretServer request failed (HTTP {e.code})"
            if e.code == 401:
                raise AuthError(detail, status_code=401) from None
            if e.code == 403:
                raise PermissionError(detail, status_code=403) from None
            if e.code == 404:
                raise NotFoundError(detail, status_code=404) from None
            if e.code == 409:
                raise ConflictError(detail, etag=e.headers.get("ETag") if e.headers is not None else None) from None
            raise SecretServerError(detail, status_code=e.code) from None
        except (ValueError, UnicodeError):
            raise SecretServerError("Invalid server response") from None
        except OSError:
            raise SecretServerError("SecretServer connection failed") from None

    def list_documents(self) -> Any:
        return self._get("/documents")

    def get_document(self, document_id: str) -> Any:
        return self._get(f"/documents/{_seg(document_id)}")

    def upload_document(self, name: str, pdf: bytes) -> Any:
        """Upload raw PDF bytes (maximum 8 MiB); never reads a local file."""
        if not isinstance(pdf, bytes) or not 0 < len(pdf) <= 8 * 1024 * 1024:
            raise ValueError("PDF must be bytes, between 1 byte and 8 MiB")
        return self._send("POST", "/documents?" + urlencode({"name": name}), pdf=pdf)

    def download_document(self, document_id: str) -> bytes:
        return self._send("GET", f"/documents/{_seg(document_id)}/download", raw=True)

    def preview_document(self, document_id: str, page: int = 1, *, for_print: bool = False) -> bytes:
        if type(page) is not int or not 1 <= page <= 50:
            raise ValueError("Page must be an integer from 1 to 50")
        return self._send("GET", f"/documents/{_seg(document_id)}/pages/{page}" + ("?purpose=print" if for_print else ""), raw=True)

    def grant_document(self, document_id: str, expires_at: str, *, user_id: Optional[str] = None,
                       recipient_email: Optional[str] = None, allow_download: bool = False,
                       allow_print: bool = False) -> Any:
        if bool(user_id) == bool(recipient_email):
            raise ValueError("Specify exactly one user_id or recipient_email")
        body = {"expires_at": expires_at, "allow_download": allow_download, "allow_print": allow_print}
        body["user_id" if user_id else "recipient_email"] = user_id or recipient_email
        return self._post(f"/documents/{_seg(document_id)}/grants", body)

    def list_document_grants(self, document_id: str) -> Any:
        return self._get(f"/documents/{_seg(document_id)}/grants")

    def revoke_document_grant(self, document_id: str, grant_id: str) -> Any:
        return self._delete(f"/documents/{_seg(document_id)}/grants/{_seg(grant_id)}")

    # Retained for compatibility with code which subclassed the client.
    def _request(self, method: str, path: str, body: Optional[Any] = None) -> Any:
        return self.request(method, path, body)

    def _get(self, path: str) -> Any:
        return self._request("GET", path)

    def _post(self, path: str, body: Any = None) -> Any:
        return self._request("POST", path, body)

    def _put(self, path: str, body: Any = None) -> Any:
        return self._request("PUT", path, body)

    def _patch(self, path: str, body: Any = None) -> Any:
        return self._request("PATCH", path, body)

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    def _etag_call(self, method: str, path: str, body: Optional[Any] = None,
                   if_match: Optional[str] = None) -> ETagDict:
        result, etag = self._send(method, path, body, if_match=if_match, with_etag=True)
        if not isinstance(result, dict):
            raise SecretServerError("Invalid server response")
        return ETagDict(result, etag)

    def _require_partial_updates(self, if_match: Optional[str]) -> None:
        """Refuse a partial PUT unless the caller opted in or holds a server ETag."""
        if self.partial_updates:
            return
        if isinstance(if_match, str) and _ENTITY_TAG.fullmatch(if_match):
            return
        raise SecretServerError(_PARTIAL_UPDATES_REQUIRED)

    def _get_list(self, path: str, *envelope_keys: str) -> List[Dict[str, Any]]:
        data = self._get(path) or []
        if isinstance(data, list):
            return data
        for key in envelope_keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
        return []

    # ------------------------------------------------------------------
    # Path-based secret access (primary interface)
    # ------------------------------------------------------------------

    def assign_variable(self, name: str, secret_type: str, secret_id: str, field: str) -> Dict:
        """Bind a %%NAME%% variable to a secret field (PUT /variables/:name, needs admin:all)."""
        return self._put("/variables/" + _seg(name), {"secret_type": secret_type, "secret_id": secret_id, "field": field})

    def get_variable(self, name: str) -> Dict:
        """Get a variable binding (needs admin:all)."""
        return self._get("/variables/" + _seg(name))

    def list_variables(self) -> List[Dict]:
        """List variable bindings (needs admin:all)."""
        return self._get("/variables")["variables"]

    def delete_variable(self, name: str) -> None:
        """Delete a variable binding (needs admin:all)."""
        self._delete("/variables/" + _seg(name))

    def render(self, template: str) -> str:
        result = self._post("/variables/resolve", {"template": template})
        if not isinstance(result, dict) or not isinstance(result.get("rendered"), str):
            raise SecretServerError("Invalid rendered response")
        return result["rendered"]

    def resolve_document(self, document: Any) -> Any:
        result = self._post("/variables/resolve", {"document": document})
        if not isinstance(result, dict) or "document" not in result:
            raise SecretServerError("Invalid document response")
        return result["document"]

    def secret(self, path: str) -> str:
        """
        Get a secret value by name, container/key or container/key/version.

        Versions are 1 (current) to 12; any other shape raises ValueError.

        >>> ss.secret("production/db-password")
        'hunter2'
        >>> ss.secret("production/db-password/2")  # previous version
        'old-hunter2'
        """
        return _scalar(self._get(_secret_route(path)))

    def get_secret(self, path: str) -> ETagDict:
        """Get the full secret record for a name, container/key or container/key/version.

        The result's ``etag`` attribute holds the ETag header (reads by name
        carry one; pass it as ``update_secret(..., if_match=...)``).
        """
        return self._etag_call("GET", _secret_route(path))

    # ------------------------------------------------------------------
    # Secrets
    # ------------------------------------------------------------------

    def list_secrets(self) -> List[Dict]:
        return self._get_list("/secrets", "secrets")

    def create_secret(self, name: str, value: str, description: str = "", container_id: str = "") -> Dict:
        """Create a secret. ``container_id`` must be a container UUID, not its slug."""
        body: Dict[str, Any] = {"name": name, "data": {"value": value}}
        if description:
            body["description"] = description
        if container_id:
            body["container_id"] = container_id
        return self._post("/secrets", body)

    def update_secret(
        self,
        name: str,
        value: str = _UNSET,
        description: Optional[str] = _UNSET,
        tags: Optional[List[str]] = _UNSET,
        container_id: Optional[str] = _UNSET,
        if_match: Union[str, int, None] = None,
        expected_version: Optional[int] = None,
    ) -> ETagDict:
        """Partially update a secret; only the arguments you pass are sent.

        An omitted argument keeps the stored value; ``None`` sends JSON null,
        which clears it (``container_id=None`` detaches the secret from its
        container). Omitting ``value`` leaves the stored value untouched; it
        cannot be cleared. Needs only secrets:write and never reads the value.

        ``if_match`` (an ETag from ``get_secret(...).etag`` or a version
        number) and ``expected_version`` make the update conditional; a stale
        precondition raises ConflictError carrying the current ETag. The
        result's ``etag`` attribute is the updated record's ETag.

        Minimum server: secretserver.io 3075630 (partial, conditional
        updates). Raises SecretServerError without sending a request unless
        the client has ``partial_updates`` enabled or ``if_match`` is an ETag
        (``"..."`` or ``W/"..."``); a version number, ``*`` or
        ``expected_version`` alone does not qualify.
        """
        body: Dict[str, Any] = {}
        if value is not _UNSET:
            if value is None:
                raise ValueError("value cannot be cleared; omit it to keep the current value")
            body["data"] = {"value": value}
        for key, arg in (("description", description), ("tags", tags), ("container_id", container_id)):
            if arg is not _UNSET:
                body[key] = arg
        if expected_version is not None:
            if not isinstance(expected_version, int) or isinstance(expected_version, bool):
                raise ValueError("expected_version must be an integer")
            body["expected_version"] = expected_version
        header = _if_match(if_match, allow_version=True)
        self._require_partial_updates(header)
        return self._etag_call("PUT", f"/secrets/{_seg(name)}", body, header)

    def delete_secret(self, name: str) -> None:
        self._delete(f"/secrets/{_seg(name)}")

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
        return self._get_list("/certificates", "certificates")

    def get_certificate(self, cert_id: str) -> Dict:
        return self._get(f"/certificates/{_seg(cert_id)}")

    def enroll_certificate(self, name: str, common_name: str, sans: Optional[List[str]] = None, auto_renew: bool = True) -> Dict:
        return self._post("/certificates/enroll", {
            "name": name,
            "common_name": common_name,
            "dns_names": sans or [],
            "auto_renew": auto_renew,
        })

    def renew_certificate(self, cert_id: str) -> Dict:
        return self._post(f"/certificates/{_seg(cert_id)}/renew")

    # ------------------------------------------------------------------
    # Operation-only cryptographic backends
    # ------------------------------------------------------------------

    def signing_key(self, key_id: str, backend: str = "pkcs11") -> "RemoteSigningKey":
        """Bind a server-side key reference. This handle never contains private key bytes."""
        if backend not in ("pkcs11", "ehsm") or not key_id:
            raise ValueError("use a configured operation-only backend and key ID")
        return RemoteSigningKey(self, backend, key_id)

    def list_crypto_backends(self) -> List[Dict[str, Any]]:
        """List configured backends and their non-secret capabilities."""
        return self._get("/crypto/backends") or []

    def list_signing_keys(self, backend: str = "pkcs11") -> List[Dict[str, Any]]:
        return self._get("/crypto/signing-keys?" + urlencode({"backend": backend})) or []

    def sign(self, backend: str, key_id: str, message_b64: str, purpose: str) -> Dict[str, Any]:
        """Sign base64-encoded bytes without exporting private key material."""
        return self._post("/crypto/sign", {
            "backend": backend,
            "key_id": key_id,
            "message": message_b64,
            "purpose": purpose,
        })

    # ------------------------------------------------------------------
    # JKS keystores
    # ------------------------------------------------------------------

    def list_jks_keystores(self) -> List[Dict[str, Any]]:
        return self._get("/jks-keystores") or []

    def get_jks_keystore(self, keystore_id: str) -> ETagDict:
        """Get a keystore; the result's ``etag`` attribute holds its ETag."""
        return self._etag_call("GET", f"/jks-keystores/{_seg(keystore_id)}")

    def create_jks_keystore(self, name: str, store_type: str = "managed", **options: Any) -> Dict[str, Any]:
        return self._post("/jks-keystores", {"name": name, "store_type": store_type, **options})

    def update_jks_keystore(self, keystore_id: str, data: Dict[str, Any],
                            if_match: Optional[str] = None) -> ETagDict:
        """Partially update a keystore with exactly the fields in ``data``.

        A key absent from ``data`` keeps the stored value; a key set to None is
        sent as JSON null and clears ``notes``, ``tags`` or ``container_id``.
        ``jks`` (raw keystores) must come with ``password``; ``password`` alone
        rotates the stored keystore password. ``if_match`` (an ETag from
        ``get_jks_keystore(...).etag``) makes the update conditional; a stale
        one raises ConflictError. The result's ``etag`` is the new ETag.

        Minimum server: secretserver.io 3075630. Raises SecretServerError
        without sending a request unless ``partial_updates`` is enabled or
        ``if_match`` is an ETag (``"..."`` or ``W/"..."``).
        """
        if not isinstance(data, dict):
            raise ValueError("data must be a dict")
        header = _if_match(if_match)
        self._require_partial_updates(header)
        return self._etag_call("PUT", f"/jks-keystores/{_seg(keystore_id)}", dict(data), header)

    def delete_jks_keystore(self, keystore_id: str) -> None:
        self._delete(f"/jks-keystores/{_seg(keystore_id)}")

    def export_jks_keystore(self, keystore_id: str) -> Dict[str, Any]:
        return self._get(f"/jks-keystores/{_seg(keystore_id)}/export")

    def list_jks_entries(self, keystore_id: str) -> List[Dict[str, Any]]:
        return self._get(f"/jks-keystores/{_seg(keystore_id)}/entries") or []

    def create_jks_entry(self, keystore_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return self._post(f"/jks-keystores/{_seg(keystore_id)}/entries", data)

    def delete_jks_entry(self, keystore_id: str, alias: str) -> None:
        self._delete(
            f"/jks-keystores/{_seg(keystore_id)}/entries/{_seg(alias)}"
        )

    # ------------------------------------------------------------------
    # Provider credentials and key taxonomy
    # ------------------------------------------------------------------

    def list_integration_providers(self) -> List[Dict[str, Any]]:
        """Return categorized, allowlisted provider credential schemas."""
        return self._get("/integration-providers") or []

    def list_key_catalog(self) -> List[Dict[str, Any]]:
        """Return supported key types, formats, algorithms, and maturity."""
        return self._get("/key-catalog") or []

    def create_integration_credential(
        self, name: str, provider: str, credentials: Dict[str, str],
        auth_type: str = "", endpoint: str = "", tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return self._post("/integrations", {
            "name": name, "provider": provider, "credentials": credentials,
            "auth_type": auth_type, "endpoint": endpoint, "tags": tags or [],
        })

    def get_integration_credential(self, credential_id: str, reveal: bool = False) -> Dict[str, Any]:
        """Get redacted metadata; reveal requires the export:read permission."""
        path = f"/integrations/{_seg(credential_id)}"
        if reveal:
            path += "?reveal=true"
        return self._get(path)

    # ------------------------------------------------------------------
    # SSH Keys
    # ------------------------------------------------------------------

    def list_ssh_keys(self) -> List[Dict]:
        return self._get_list("/ssh-keys", "ssh_keys", "keys")

    def generate_ssh_key(self, name: str, key_type: str = "ed25519", comment: str = "") -> Dict:
        return self._post("/ssh-keys/generate", {"name": name, "key_type": key_type, "comment": comment})

    def import_ssh_key(self, name: str, private_key: str) -> Dict:
        return self._post("/ssh-keys/import", {"name": name, "private_key": private_key})

    def export_ssh_key(self, key_id: str) -> Dict:
        return self._get(f"/ssh-keys/{_seg(key_id)}/export")

    # ------------------------------------------------------------------
    # Passwords
    # ------------------------------------------------------------------

    def list_passwords(self) -> List[Dict]:
        return self._get_list("/passwords", "passwords")

    def create_password(self, name: str, username: str, value: str, url: str = "",
                        description: str = "", tags: Optional[List[str]] = None) -> Dict:
        body: Dict[str, Any] = {"name": name, "username": username, "value": value}
        if url:
            body["url"] = url
        if description:
            body["description"] = description
        if tags:
            body["tags"] = tags
        return self._post("/passwords", body)

    def generate_password(
        self,
        name: str,
        length: int = 32,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        username: str = "",
        url: str = "",
        description: str = "",
        tags: Optional[List[str]] = None,
    ) -> Dict:
        """Generate and store a password record named ``name``.

        Returns the created password record; the generated secret is in ``value``.
        """
        if not 8 <= length <= 128:
            raise ValueError("length must be between 8 and 128")
        body: Dict[str, Any] = {
            "name": name,
            "length": length,
            "use_lowercase": use_lowercase,
            "use_uppercase": use_uppercase,
            "use_digits": use_digits,
            "use_symbols": use_symbols,
        }
        for key, value in (("username", username), ("url", url), ("description", description)):
            if value:
                body[key] = value
        if tags:
            body["tags"] = tags
        return self._post("/passwords/generate", body)

    # ------------------------------------------------------------------
    # API Tokens
    # ------------------------------------------------------------------

    def list_api_tokens(self) -> List[Dict]:
        return self._get_list("/api-tokens", "tokens")

    API_TOKEN_ENVIRONMENTS = ("production", "staging", "development")

    def create_api_token(self, name: str, service: str, value: str, environment: str,
                         description: str = "", expires_at: Any = None) -> Dict:
        """Store a third-party API token. ``environment`` is production, staging or development."""
        if environment not in self.API_TOKEN_ENVIRONMENTS:
            raise ValueError("environment must be production, staging or development")
        body: Dict[str, Any] = {"name": name, "service": service, "value": value, "environment": environment}
        if description:
            body["description"] = description
        if expires_at is not None:
            body["expires_at"] = _timestamp(expires_at)
        return self._post("/api-tokens", body)

    def rotate_api_token(self, token_id: str, value: str) -> Dict:
        """Replace a stored token with ``value``."""
        return self._post(f"/api-tokens/{_seg(token_id)}/rotate", {"value": value})

    # ------------------------------------------------------------------
    # Version history
    # ------------------------------------------------------------------

    def get_history(self, secret_type: str, secret_id: str) -> List[Dict]:
        """List prior versions. ``secret_type`` must be one of SECRET_TYPES."""
        data = self._get(f"/{_secret_type(secret_type)}/{_uuid(secret_id, 'secret_id')}/history")
        if data is None:
            return []
        if not isinstance(data, list):
            raise SecretServerError("Invalid history response")
        return data

    def get_version(self, secret_type: str, secret_id: str, version: int) -> Dict:
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise ValueError("version must be a positive integer")
        return self._get(f"/{_secret_type(secret_type)}/{_uuid(secret_id, 'secret_id')}/history/{version}")

    # ------------------------------------------------------------------
    # Sharing & temp access
    # ------------------------------------------------------------------

    def share(
        self,
        secret_type: str,
        secret_id: str,
        user_id: Optional[str] = None,
        group_id: Optional[str] = None,
        permission: str = "read",
        expires_at: Any = None,
    ) -> Dict:
        """Share with exactly one user or group (UUIDs). ``permission`` is read or manage.

        ``expires_at`` may be a datetime or an RFC 3339 string.
        """
        if (user_id is None) == (group_id is None):
            raise ValueError("specify exactly one of user_id or group_id")
        if permission not in ("read", "manage"):
            raise ValueError("permission must be read or manage")
        body: Dict[str, Any] = {"permission": permission}
        if user_id is not None:
            body["shared_with_user_id"] = _uuid(user_id, "user_id")
        else:
            body["shared_with_group_id"] = _uuid(group_id, "group_id")
        if expires_at is not None:
            body["expires_at"] = _timestamp(expires_at)
        return self._post(f"/{_secret_type(secret_type)}/{_uuid(secret_id, 'secret_id')}/shares", body)

    def create_temp_access(self, secret_type: str, secret_id: str, duration_seconds: int = 900) -> Dict:
        """Returns dict with 'token' and 'expires_at'. Duration is 60..86400 seconds."""
        if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int) or not 60 <= duration_seconds <= 86400:
            raise ValueError("duration_seconds must be between 60 and 86400")
        return self._post(
            f"/{_secret_type(secret_type)}/{_uuid(secret_id, 'secret_id')}/temp-access",
            {"duration_seconds": duration_seconds},
        )

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

    def decode(self, data: str, format: str = "base64") -> Any:
        """Decode ``data``. Returns a string, or an object for jwt/json sources."""
        result = self._post("/transform/decode", {"input": data, "source_type": format})
        if not isinstance(result, dict) or "result" not in result:
            raise SecretServerError("Invalid decode response")
        return result["result"]

    # ------------------------------------------------------------------
    # GPG Keys
    # ------------------------------------------------------------------

    def list_gpg_keys(self) -> List[Dict]:
        return self._get_list("/gpg-keys", "keys")

    def get_gpg_key(self, key_id: str) -> Dict:
        return self._get(f"/gpg-keys/{_seg(key_id)}")

    GPG_ALGORITHMS = ("RSA2048", "RSA4096", "ED25519")

    def generate_gpg_key(self, name: str, email: str, algorithm: str = "RSA4096",
                         comment: str = "", passphrase: str = "") -> Dict:
        """Generate a GPG key. ``algorithm`` is RSA2048, RSA4096 or ED25519 (no expiry)."""
        if algorithm not in self.GPG_ALGORITHMS:
            raise ValueError("algorithm must be RSA2048, RSA4096 or ED25519")
        body: Dict[str, Any] = {"name": name, "email": email, "algorithm": algorithm}
        if comment:
            body["comment"] = comment
        if passphrase:
            body["passphrase"] = passphrase
        return self._post("/gpg-keys/generate", body)

    def import_gpg_key(self, armored_key: str, passphrase: str = "", name: str = "") -> Dict:
        body: Dict[str, Any] = {"armored_key": armored_key}
        if passphrase:
            body["passphrase"] = passphrase
        if name:
            body["name"] = name
        return self._post("/gpg-keys/import", body)

    def export_gpg_key(self, key_id: str, format: str = "public") -> Dict:
        """Returns {key, format, fingerprint, key_id}; ``format`` is public or private."""
        if format not in ("public", "private"):
            raise ValueError("format must be public or private")
        return self._get(f"/gpg-keys/{_seg(key_id)}/export?" + urlencode({"format": format}))

    def delete_gpg_key(self, key_id: str) -> None:
        self._delete(f"/gpg-keys/{_seg(key_id)}")

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
        return self._get_list("/openssl-keys", "openssl_keys", "keys")

    def get_openssl_key(self, key_id: str) -> Dict:
        return self._get(f"/openssl-keys/{_seg(key_id)}")

    OPENSSL_ALGORITHMS = ("rsa", "ecdsa", "ed25519")

    def generate_openssl_key(self, name: str, algorithm: str = "rsa", key_size: int = 4096,
                             curve: str = "", description: str = "") -> Dict:
        """Generate a key pair. ``key_size`` applies to rsa, ``curve`` (e.g. P-256) to ecdsa."""
        if algorithm not in self.OPENSSL_ALGORITHMS:
            raise ValueError("algorithm must be rsa, ecdsa or ed25519")
        body: Dict[str, Any] = {"name": name, "algorithm": algorithm}
        if algorithm == "rsa":
            body["key_size"] = key_size
        if curve:
            body["curve"] = curve
        if description:
            body["description"] = description
        return self._post("/openssl-keys/generate", body)

    def import_openssl_key(self, name: str, algorithm: str, private_key: str,
                           public_key: str = "", passphrase: str = "") -> Dict:
        if algorithm not in self.OPENSSL_ALGORITHMS:
            raise ValueError("algorithm must be rsa, ecdsa or ed25519")
        body: Dict[str, Any] = {"name": name, "algorithm": algorithm, "private_key": private_key}
        if public_key:
            body["public_key"] = public_key
        if passphrase:
            body["passphrase"] = passphrase
        return self._post("/openssl-keys/import", body)

    def export_openssl_key(self, key_id: str) -> Dict:
        return self._get(f"/openssl-keys/{_seg(key_id)}/export")

    def delete_openssl_key(self, key_id: str) -> None:
        self._delete(f"/openssl-keys/{_seg(key_id)}")

    # ------------------------------------------------------------------
    # NTLM Hashes
    # ------------------------------------------------------------------

    def list_ntlm_hashes(self) -> List[Dict]:
        return self._get_list("/ntlm", "ntlm_hashes", "hashes")

    def get_ntlm_hash(self, hash_id: str) -> Dict:
        return self._get(f"/ntlm/{_seg(hash_id)}")

    def create_ntlm_hash(self, name: str, username: str, hash_value: str) -> Dict:
        return self._post("/ntlm", {"name": name, "username": username, "hash": hash_value})

    def update_ntlm_hash(self, hash_id: str, data: Dict) -> Dict:
        return self._put(f"/ntlm/{_seg(hash_id)}", data)

    def delete_ntlm_hash(self, hash_id: str) -> None:
        self._delete(f"/ntlm/{_seg(hash_id)}")

    # ------------------------------------------------------------------
    # Certificates (extended operations)
    # ------------------------------------------------------------------

    def revoke_certificate(self, cert_id: str) -> Dict:
        return self._post(f"/certificates/{_seg(cert_id)}/revoke")

    CERT_DOWNLOAD_FORMATS = ("pem", "pem-bundle", "key", "pfx", "p12")

    def download_certificate(self, cert_id: str, format: str = "pem", password: Optional[str] = None) -> bytes:
        """Download raw certificate material (PEM text or PKCS#12 bytes).

        ``format`` is pem, pem-bundle, key, pfx or p12. PEM formats use GET.
        pfx/p12 require a 1-1024 character ``password`` and are sent as POST
        with the password in the JSON body, so it never appears in a URL.
        """
        if format not in self.CERT_DOWNLOAD_FORMATS:
            raise ValueError("format must be pem, pem-bundle, key, pfx or p12")
        path = f"/certificates/{_seg(cert_id)}/download"
        if format in ("pfx", "p12"):
            if not password or len(password) > 1024:
                raise ValueError("a 1-1024 character password is required for pfx/p12 downloads")
            return self._send("POST", path, {"format": format, "password": password}, raw=True)
        if password is not None:
            raise ValueError("password is only used with pfx/p12 downloads")
        return self._send("GET", path + "?" + urlencode({"format": format}), raw=True)

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------

    def list_webhooks(self) -> List[Dict]:
        return self._get_list("/webhooks", "webhooks")

    def create_webhook(self, name: str, url: str, events: List[str], secret: str = "") -> Dict:
        """Create a webhook; ``secret`` is the optional delivery signing secret."""
        body: Dict[str, Any] = {"name": name, "url": url, "events": events}
        if secret:
            body["secret"] = secret
        return self._post("/webhooks", body)

    def get_webhook_deliveries(self, webhook_id: str) -> List[Dict]:
        return self._get_list(f"/webhooks/{_seg(webhook_id)}/deliveries", "deliveries")

    def test_webhook(self, webhook_id: str) -> Dict:
        return self._post(f"/webhooks/{_seg(webhook_id)}/test")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    # Exports are tenant-wide. With every include_* flag False the server
    # exports all four kinds; ``tags`` narrows the result.

    @staticmethod
    def _export_body(include_passwords: bool, include_secrets: bool, include_ssh_keys: bool,
                     include_certificates: bool, tags: Optional[List[str]]) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "include_passwords": include_passwords,
            "include_secrets": include_secrets,
            "include_ssh_keys": include_ssh_keys,
            "include_certificates": include_certificates,
        }
        if tags:
            body["tags"] = tags
        return body

    def export_to_keychain(self, include_passwords: bool = False, include_secrets: bool = False,
                           include_ssh_keys: bool = False, include_certificates: bool = False,
                           tags: Optional[List[str]] = None) -> Dict:
        return self._post("/export/keychain", self._export_body(
            include_passwords, include_secrets, include_ssh_keys, include_certificates, tags))

    def export_to_credential_manager(self, include_passwords: bool = False, include_secrets: bool = False,
                                     include_ssh_keys: bool = False, include_certificates: bool = False,
                                     tags: Optional[List[str]] = None) -> Dict:
        return self._post("/export/credential-manager", self._export_body(
            include_passwords, include_secrets, include_ssh_keys, include_certificates, tags))

    def export_to_json(self, include_passwords: bool = False, include_secrets: bool = False,
                       include_ssh_keys: bool = False, include_certificates: bool = False,
                       tags: Optional[List[str]] = None) -> Dict:
        return self._post("/export/json", self._export_body(
            include_passwords, include_secrets, include_ssh_keys, include_certificates, tags))

    # ------------------------------------------------------------------
    # Audit logs
    # ------------------------------------------------------------------

    def get_audit_logs(self, limit: int = 100, offset: int = 0, action: str = "", resource: str = "",
                       resource_id: Optional[str] = None, user_id: Optional[str] = None,
                       start_date: Any = None, end_date: Any = None) -> Dict:
        """Query audit logs. Dates may be datetimes or RFC 3339 strings; empty filters are omitted.

        ``resource_id``/``user_id`` are sent as UUIDs; server builds whose query
        binder cannot parse UUIDs answer those filters with HTTP 400.
        """
        params = _audit_filters(limit=limit, offset=offset, action=action, resource=resource,
                                resource_id=resource_id, user_id=user_id,
                                start_date=start_date, end_date=end_date)
        return self._get("/audit/logs?" + urlencode(params))

    def export_audit_logs(self, format: str = "csv", action: str = "", resource: str = "",
                          resource_id: Optional[str] = None, user_id: Optional[str] = None,
                          start_date: Any = None, end_date: Any = None) -> Any:
        """Export audit logs. ``format="csv"`` returns CSV text; ``"json"`` returns parsed JSON."""
        if format not in ("csv", "json"):
            raise ValueError("format must be csv or json")
        params = _audit_filters(format=format, action=action, resource=resource,
                                resource_id=resource_id, user_id=user_id,
                                start_date=start_date, end_date=end_date)
        raw = self._send("GET", "/audit/logs/export?" + urlencode(params), raw=True)
        try:
            text = raw.decode("utf-8")
            return json.loads(text) if format == "json" else text
        except (ValueError, UnicodeError):
            raise SecretServerError("Invalid server response") from None

    # ------------------------------------------------------------------
    # TOTP Authenticators
    # ------------------------------------------------------------------

    def list_totp_tokens(self) -> List[Dict]:
        """List all TOTP authenticator tokens (secret keys are never returned)."""
        return self._get_list("/totp-tokens", "tokens")

    def get_totp_token(self, id: str) -> Dict:
        """Get a specific TOTP token by ID."""
        return self._get(f"/totp-tokens/{_seg(id)}")

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
        return self._put(f"/totp-tokens/{_seg(id)}", data)

    def delete_totp_token(self, id: str) -> None:
        """Delete a TOTP token."""
        self._delete(f"/totp-tokens/{_seg(id)}")

    def generate_totp_code(self, id: str) -> Dict:
        """
        Generate a TOTP code for the given token.

        Returns dict with 'code' and 'expires_in' (seconds remaining).
        """
        return self._post(f"/totp-tokens/{_seg(id)}/generate")

    # ------------------------------------------------------------------
    # YubiKey OTP Credentials
    # ------------------------------------------------------------------

    def list_yubikeys(self) -> List[Dict]:
        return self._get("/yubikeys") or []

    def get_yubikey(self, yubikey_id: str) -> ETagDict:
        """Get a YubiKey; the result's ``etag`` attribute holds its ETag."""
        return self._etag_call("GET", f"/yubikeys/{_seg(yubikey_id)}")

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

    def update_yubikey(self, yubikey_id: str, data: Dict[str, Any],
                       if_match: Optional[str] = None) -> ETagDict:
        """Partially update a YubiKey with exactly the fields in ``data``.

        A key absent from ``data`` keeps the stored value; a key set to None is
        sent as JSON null and clears ``serial_number``, ``notes``, ``tags`` or
        ``container_id``. ``api_key`` replaces the stored key; ``public_id``
        must be 12 characters. ``if_match`` (an ETag from
        ``get_yubikey(...).etag``) makes the update conditional; a stale one
        raises ConflictError. The result's ``etag`` is the new ETag.

        Minimum server: secretserver.io 3075630. Raises SecretServerError
        without sending a request unless ``partial_updates`` is enabled or
        ``if_match`` is an ETag (``"..."`` or ``W/"..."``).
        """
        if not isinstance(data, dict):
            raise ValueError("data must be a dict")
        header = _if_match(if_match)
        self._require_partial_updates(header)
        return self._etag_call("PUT", f"/yubikeys/{_seg(yubikey_id)}", dict(data), header)

    def delete_yubikey(self, yubikey_id: str) -> None:
        self._delete(f"/yubikeys/{_seg(yubikey_id)}")

    def validate_yubikey_otp(self, yubikey_id: str, otp: str) -> Dict:
        """Validate a Yubico OTP. Returns dict with 'valid' (bool) and 'checked_at'."""
        return self._post(f"/yubikeys/{_seg(yubikey_id)}/validate", {"otp": otp})

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

        Returns dict with 'uri'.
        """
        return self._get(f"/totp-tokens/{_seg(id)}/export")


# -----------------------------------------------------------------------
# Credential resource helper
# -----------------------------------------------------------------------

class CredentialResource:
    """Helper class for CRUD operations on extended credential types."""

    def __init__(self, client: 'SecretServerClient', resource: str):
        self._client = client
        self._resource = resource

    def list(self) -> List[Dict]:
        return self._client._get(f"/{_seg(self._resource)}") or []

    def get(self, id: str) -> Dict:
        return self._client._get(f"/{_seg(self._resource)}/{_seg(id)}")

    def create(self, data: Dict) -> Dict:
        return self._client._post(f"/{_seg(self._resource)}", data)

    def update(self, id: str, data: Dict) -> Dict:
        return self._client._put(f"/{_seg(self._resource)}/{_seg(id)}", data)

    def delete(self, id: str) -> None:
        self._client._delete(f"/{_seg(self._resource)}/{_seg(id)}")


class RemoteSigningKey:
    """Operation handle, not local key material. Parent client owns authentication."""
    __slots__ = ("_client", "_backend", "_key_id")

    def __init__(self, client: SecretServerClient, backend: str, key_id: str):
        self._client, self._backend, self._key_id = client, backend, key_id

    def sign(self, message: bytes, purpose: str) -> Dict[str, Any]:
        if not isinstance(message, bytes) or not 0 < len(message) <= 1024 * 1024:
            raise ValueError("message must be bytes between 1 byte and 1 MiB")
        return self._client.sign(self._backend, self._key_id, base64.b64encode(message).decode("ascii"), purpose)

    def __repr__(self):
        return "<RemoteSigningKey operation-only>"

    def __reduce__(self):
        raise TypeError("authenticated signing handles cannot be serialized")
