# SecretServer Python client

Python client for the SecretServer REST API. The client has no runtime dependencies outside the standard library.

```python
from secretserver import SecretServerClient

client = SecretServerClient(api_key="scoped-token", api_url="https://your-server.example")
client.create_secret("example", "value")
value = client.secret("example")
client.delete_secret("example")
```

## Use your `ss login`

Instead of an API key, reuse the SSO session of the `ss` CLI:

```python
from secretserver import SecretServerClient, cli_credential_provider

client = SecretServerClient(credential_provider=cli_credential_provider())
```

The provider runs `ss auth print-access-token --format json` (`cli_path=`, else
`SS_CLI_PATH`, else `ss` on `PATH`) with `shell=False`, a 30 s timeout
(`timeout=`) and a 64 KiB output cap, and caches the token in memory until 60 s
before it expires. If the CLI is not logged in it raises `AuthError` asking you
to run `ss login`. Without `api_url=` or `SS_API_URL` the client uses the API URL
the CLI is logged in to (the CLI runs once when the client is created). Tokens
never appear in exceptions.

Use protected configuration for credentials; avoid logging returned values. Path reads use `container/name`, and history uses `container/name/2`. Generic request helpers support newer REST endpoints. Requests have a configurable timeout and do not automatically retry mutations. HTTP failures expose a status code without echoing response bodies.

**Minimum server: secretserver.io 3075630 (partial, conditional updates).** Older servers treat `PUT` on secrets, JKS keystores and YubiKeys as a full replace and ignore `If-Match`, so a partial body silently blanks every omitted field. The three update methods therefore refuse to send (raising `SecretServerError` before any request) unless you opt in, or the call passes an ETag the server returned:

```python
client = SecretServerClient(api_key="scoped-token", api_url="https://your-server.example",
                            partial_updates=True)   # or export SS_PARTIAL_UPDATES=1
client.update_secret("example", description="new")  # allowed: opted in

legacy_safe = SecretServerClient(api_key="scoped-token", api_url="https://your-server.example")
record = legacy_safe.get_secret("example")
legacy_safe.update_secret("example", "new-value", if_match=record.etag)  # allowed: ETag proves 3075630+
```

Only an entity tag (`"..."` or `W/"..."`) satisfies the check; a version number, `*`, an unquoted value or `expected_version` alone does not. `SS_PARTIAL_UPDATES` is read only when `partial_updates` is not passed, and only the value `1` enables it.

Updates are partial. `update_secret`, `update_jks_keystore` and `update_yubikey` send one `PUT` containing only what you supply: an omitted argument (or a key absent from the `data` dict) keeps the stored value, and `None` is sent as JSON `null`, which clears the field. A secret's value cannot be cleared; omit `value` to change only metadata. `update_secret` needs only `secrets:write` and never reads the secret.

```python
client.update_secret("example", description=None)          # clear the description, keep everything else
client.update_jks_keystore(ks_id, {"notes": None, "password": "new"})  # clear notes, rotate password
client.update_yubikey(yk_id, {"serial_number": None})
```

Optimistic concurrency: `get_secret`, `get_jks_keystore`, `get_yubikey` and the three update methods return an `ETagDict`, a plain `dict` whose `.etag` attribute is the response's `ETag` header (None when the server sends none). Pass it back as `if_match=`; `update_secret` also accepts a version number there, or `expected_version=`. A stale precondition raises `ConflictError` (a `SecretServerError`, status 409) whose `.etag` is the current ETag.

```python
record = client.get_secret("example")
try:
    client.update_secret("example", "new-value", if_match=record.etag)
except ConflictError as exc:
    ...  # re-read (exc.etag is the current ETag) and retry
```

Transport policy: `api_url` must be `https://` (plain `http://` is accepted only for `localhost`, `127.0.0.1` or `::1`), URLs with embedded credentials are rejected, TLS 1.2 is the minimum and certificate verification cannot be disabled (`verify_ssl=False` raises `ValueError`). To trust a private CA pass `ca_file="/path/to/ca.pem"`; the bundle is added to the system trust store, so public CAs stay trusted. Redirects are never followed, JSON responses are capped at 4 MiB (raw downloads at 16 MiB), and every caller-supplied path segment is percent-encoded.

This source checkout includes fixes not yet published. See the repository compatibility matrix for validation scope.


## Protected PDF documents

The DarkStorage integration adds encrypted PDF storage and account-member sharing.
Use the Secret Server API origin and a key scoped to `documents:manage` (or `admin:*`).
Recipient grants require an interactive user session; API keys do not inherit grants.
Go exposes `client.Documents.{List,Get,Upload,Preview,Download,Grant,Grants,Revoke}`.
Python exposes `list_documents`, `get_document`, `upload_document`, `preview_document`,
`download_document`, `grant_document`, `list_document_grants`, `revoke_document_grant`.
Node/PHP use camelCase equivalents (`listDocuments`, `uploadDocument`, etc.).
Upload takes a name and raw PDF bytes (8 MiB maximum). Preview returns PNG bytes,
with an explicit print-purpose argument; download returns original PDF bytes.
Nothing is saved to disk automatically. Grants specify exactly one `user_id` or
`recipient_email` plus a future RFC3339 `expires_at` within 30 days. Download and
print default to false. Lists preserve the server envelope and effective permissions;
Go `Grants` returns its grant slice. Configure an 80-second HTTP timeout for these
operations (Go `Config.HTTPClient.Timeout`, Python/PHP constructor `timeout`, Node
`timeoutMs`). SDK defaults are unchanged for existing callers.

The desktop GUI Documents tab opens the web manager with a separate sign-in;
self-hosted users enter their web console URL. Ansible, Terraform and MCP do not
implicitly deliver or cache protected PDFs. View-only access withholds originals,
but visible pixels can still be captured. See https://secretserver.io/docs/documents.
