# Client compatibility verification

**Verified:** 2026-09-27
**Backend:** `secretserver.io` branch `prod-readiness-2026-09-26` at `3075630` (partial, conditional updates), clean detached worktree built from source. Earlier passes ran against origin/main `086b727`.
**REST contract:** `/api/v1`
**Method:** static contract audit of every client method against the server's registered gin routes and handler bind structs, plus live runs against a disposable server.

> **Minimum server: secretserver.io `3075630` (partial, conditional updates).**
> Secret, JKS keystore and YubiKey updates in every client are partial and are
> refused client-side (no request sent) unless the client opts in
> (Python `partial_updates=True`, Node `partialUpdates: true`, PHP
> `partialUpdates: true`, Go `Config.PartialUpdates`, or `SS_PARTIAL_UPDATES=1`
> for Python/Node/PHP) or the call carries an ETag previously returned by the
> server as If-Match. Older servers (e.g. `086b727`) treat PUT as a full replace
> and ignore If-Match, so a partial body would silently blank omitted fields;
> they never emit an ETag, which is why only a real ETag or an explicit opt-in
> unlocks updates. All other operations work against `086b727`.

## Result

| Client | Build / lint | Unit tests | Live (disposable server) |
|---|---|---|---|
| Go SDK (`go/`) | gofmt clean, `go vet` clean, staticcheck v0.8.1 clean | `go test -race` pass | Pass (`go/cmd/platform-smoke`) |
| Go GUI (`go-gui/`) | gofmt, vet, staticcheck clean | `go test -race` pass (keychain, extractor naming) | Not run: desktop GUI; its API calls go through the Go SDK, which was verified live |
| MCP bridge (`mcp/`) | gofmt, vet, staticcheck clean | `go test -race` pass | Pass (`TestLive`, resolves an allowlisted variable through the MCP tool layer) |
| Python 1.3.0 (`python/`) | ruff `E9,F,B` clean | pytest: python+ansible 68 pass; system Python unittest 50 OK | Pass (`python/tests/live.py`) |
| Ansible lookup (`ansible/`) | ruff `E9,F,B` clean | pytest (included above) | Pass (`ansible/tests/live.yml`) |
| Node.js 1.3.0 (`node/`) | `tsc --strict` build (lockfile, `npm ci`) | contract and security tests pass | Pass (`node/tests/live.mjs`) |
| PHP 1.3.0 (`php/`) | `php -l` on all files | `composer test`: 138 checks pass | Pass (`php/tests/live.php`) |
| Cache service | n/a: design documents only, no code | n/a | n/a |

The harness shows `NOT VERIFIED` instead of `PASS` for a client that passed every
check it ran but printed `SKIP`/`NOT VERIFIED` lines. Latest run against
`3075630`: exit 0, no failures; mcp and ansible PASS; go, python, node and php
NOT VERIFIED solely because of SKIP lines for external dependencies (Yubico OTP
validation, HSM signing, LDAP server, a second tenant user for sharing, a public
webhook receiver). No server-defect tolerances remain.

The live flows cover:

- Authentication, and rejection of a wrong key without the key appearing in the error.
- Creating and listing secrets, and reading them by name.
- Path reads (`/s/prod/<name>`, including historical versions) after an update, with the container preserved.
- Named variables: assign, get, list, render, resolve a document, delete.
- Passwords (create, generate), API token create and rotate, OpenSSL generate, SSH generate, export and import.
- Audit query and export, export with include flags, history and temp access.
- Extraction and LDAP import (dry run) and export.

Each run also checks that the API key never appears in the server log.

## How to reproduce

```bash
git -C ../secretserver.io worktree add --detach /tmp/ss-main 3075630   # or any later server commit with partial updates
SECRETSERVER_SRC=/tmp/ss-main scripts/live-integration.sh     # prints a per-client PASS/FAIL table

(cd go && go vet ./... && go test -race ./...)
(cd go-gui && go vet ./... && go test -race ./...)
(cd mcp && go vet ./... && go test -race ./...)
(cd node && npm ci && npm test)
PYTHONPATH=python python3 -m pytest python/tests ansible/tests
(cd php && composer test)
```

The harness needs `initdb`, `pg_ctl`, `vault`, `go`, `node`, `php`, `python3` and `ansible-playbook`. PostgreSQL and Vault listen on loopback. The API binary binds its port on all interfaces, because the server offers no way to set the bind address. Every run uses fresh CSPRNG credentials and deletes all state on exit.

## Contract corrections in this pass

**Secrets**

- `PUT /secrets/:name`, `/jks-keystores/:id` and `/yubikeys/:id` are partial updates on the server (as of `3075630`). Every client now sends only the fields the caller provided, with no pre-read GET. Convention in all clients: **omitted = keep, explicit null = clear** (Python `None` vs the `_UNSET` default; Node `null` vs `undefined`, `""` is a literal value; PHP key present with `null` vs absent; Go nil = keep and field names in `Clear` are sent as null).
- Update and get methods expose the response `ETag`; updates accept an optional If-Match (ETag, or for secrets a version number / `expected_version`). HTTP 409 raises a typed conflict error (`ConflictError` / `ConflictException`) carrying the current ETag.
- Live-verified in Go, Python, Node and PHP: a `secrets:write`-only key can update a value (no 403) and the update produces no `secret.read` audit entry; explicit null clears a field while omitted fields survive; a stale If-Match is rejected with the conflict error.
- Go SDK: `Get` rejects the ignored `version` parameter, and tags are filtered client-side because the server ignores the tags query. `ContainerID` survives edits in both the SDK and the GUI.

**Passwords and tokens**

- `create_password` sends `value`.
- `generate_password` sends `name` and the four `use_*` flags, and returns the stored record with the secret in `value`.
- API token create sends `value` and `environment`. Rotate sends `{value}`.

**Sharing, history and temp access**

- Sharing uses `shared_with_user_id` or `shared_with_group_id` (exactly one). The server has no email field.
- History is a bare array, not a `versions` envelope. It previously crashed in Python and returned empty in Node and PHP.
- `:type` is validated against the server's 18 singular type keys. Temp-access duration is bounded to 60 to 86400 seconds.

**Keys, TOTP and certificates**

- GPG generate sends `algorithm`, import sends `armored_key`, and export takes `?format=public|private`.
- OpenSSL generate and import send `algorithm`, `key_size` and `curve`.
- The TOTP list is unwrapped from its `tokens` envelope.
- Certificate download returns raw PEM or PKCS#12 bytes, not JSON.
- Go SDK:
  - SSH generate always sends `key_type`, and import requires `private_key`.
  - SSH export decodes the numeric `bits` field.
  - Certificate struct fields now match the server, and `GetWithPEM` was added.

**Audit and export**

- Audit export requests `format=json`, because the server defaults to CSV.
- Audit query parameters are URL-encoded, and empty values are dropped.
- The export endpoints take `include_*` flags and `tags`. The `items` parameter they used before was ignored, and the server exported the whole tenant.

**Other endpoints**

- Webhook create sends `secret`. The server has no `auth_type` field.
- Go SDK:
  - Extraction and LDAP import use multipart uploads.
  - LDAP search sends `filter` and `base_dn`.
  - LDAP export streams LDIF.
  - The signing-keys backend parameter is sent only when it is set.
- MCP: a reverse-proxy path prefix in `SECRETSERVER_URL` is preserved.

## Security posture (all clients)

**Transport**

- Base URLs must be HTTPS. HTTP is allowed only for loopback hosts. Userinfo, query and fragment are rejected.
- TLS verification cannot be disabled. The legacy switches now fail closed: Python `verify_ssl=False`, PHP `$verifySsl=false`, the Ansible `SS_INSECURE=1`, and a Go `HTTPClient` with `InsecureSkipVerify`.
- For a private CA, use Python `ca_file`, PHP `caFile`, Ansible `ca_path`, or Node `NODE_EXTRA_CA_CERTS`. TLS 1.2 is the minimum version.
- Redirects are never followed.

**Responses and errors**

- Responses are capped at 4 MiB for JSON and 16 MiB for raw downloads.
- A successful response that is not valid JSON is an error.
- Errors never contain the API key or the response body.

**Request paths**

- Every path segment is percent-encoded. Empty, `.` and `..` segments are rejected (Go uses a shared `seg()` helper, like the other clients).
- Raw downloads (Go) are fully buffered and size-checked before anything is written to the caller's writer; on overflow nothing is written.
- Go refuses caller HTTP clients whose transport is not an inspectable `*http.Transport` (wrapping RoundTrippers, custom TLS dialers) or that disable verification, and checks `http.DefaultTransport` when no transport is set.
- Real TLS handshake tests (untrusted self-signed server must fail before any request) exist for Go, Python, Ansible and PHP. Python `ca_file` and Ansible `ca_path` add the CA to the system trust store rather than replacing it.

**Go GUI**

- The API key is stored in the OS keychain. Any existing plaintext key in preferences is migrated to the keychain and deleted.

**MCP bridge**

- By default the bridge exposes only the signing-key tools, which cannot return secret material.
- `resolve_secret_template` requires both `SECRETSERVER_ENABLE_SECRET_RESOLUTION=1` and an explicit `SECRETSERVER_RESOLVE_ALLOW` allowlist. Templates that reference unlisted or malformed variables are refused before any request is sent.

**Tooling**

- `scripts/sync.sh` no longer copies the server's SDK and plugin over the clients, which would have reintroduced the `SS_INSECURE` TLS bypass. It now reports drift only.

## Breaking changes and migration (since `90033ae`)

**All clients**

- Base URLs must be `https://` (plain `http://` only for localhost/127.0.0.1/::1); URLs with userinfo, query or fragment are rejected.
- TLS verification cannot be disabled: Python `verify_ssl=False` raises, PHP `$verifySsl=false` throws, Ansible `SS_INSECURE` is gone, and Go refuses caller transports that are not an inspectable `*http.Transport` or that set `InsecureSkipVerify`. Use Python `ca_file`, PHP `caFile`, Ansible `ca_path` (both added to the system trust store), Node `NODE_EXTRA_CA_CERTS`, or a Go `*http.Transport` with `RootCAs`.
- Updates of secrets, JKS keystores and YubiKeys are **partial**: only the fields you pass are sent. Omitted = keep, explicit null = clear. They require server `3075630`+ and are refused unless you opt in or pass an ETag (see the banner above). Get/update results expose the ETag; HTTP 409 raises `ConflictError` (PHP `ConflictException`) with the current ETag.
- Request/response shapes now match the server: sharing takes a user or group UUID (no email); `generate_password` needs a name, stores the password and returns it in `value`; API token create needs `value` + `environment` and rotate needs the new value; GPG uses `algorithm`/`armored_key`/`?format=`; OpenSSL uses `algorithm`/`key_size`/`curve`; certificate download returns raw bytes/text; export methods take `include_*` flags and `tags` instead of `items`; webhook create takes `secret` instead of `auth_type`; history returns a list; TOTP list is unwrapped.

**Go**

- `SecretUpdateRequest`: `Description *string`, `Tags *[]string`, `ContainerID *string`, new `Clear []string`, `IfMatch`, `ExpectedVersion`; the `Name` field is removed. `Update` refuses an update that neither opts in (`Config.PartialUpdates`) nor carries an ETag (`ErrPartialUpdatesUnconfirmed`).
- `JKS.Update(ctx, id, *JKSKeystoreUpdate) (etag string, err error)` replaces the raw-map version.
- `Certificates.Download(ctx, id, *CertificateDownloadOptions, io.Writer) error`; `SSHKeys.Export` returns `*SSHKey`; `Extraction.ExtractFromDB`, `LDAP.Import`, `LDAP.Search`, `LDAP.Export` take readers/typed options; `Certificate.ChainPEM`/`PrivateKeyPEM` and `ImportSSHKeyRequest.PublicKey` are removed; `Secrets.Get` rejects `Version`.
- go-gui: `App.ReloadClient` returns an error; the API key moves from preferences to the OS keychain automatically.

**Python**

- `update_secret(name, value=_UNSET, description=_UNSET, tags=_UNSET, container_id=_UNSET, if_match=None, expected_version=None)`: `None` now **clears**; omit an argument to keep it. `update_jks_keystore`/`update_yubikey` send only the keys in the dict. The three return `ETagDict` (a dict with `.etag`).
- New constructor argument `partial_updates`; `SS_PARTIAL_UPDATES=1` also opts in.
- The intermediate `YUBIKEY_FIELDS` constant (never in a release) is gone.

**Node**

- `null` now **clears** a field; `""` is sent as a literal empty value (previously `""` cleared the description). `undefined` keeps.
- `updateSecret(name, value?, opts)`, `updateJKSKeystore(id, input, {ifMatch})`, `updateYubikey(id, input, {ifMatch})`; the latter two return `{message, etag}`. New `partialUpdates` config option.

**PHP**

- `updateSecret(string $name, ?string $value = null, array $opts = [], string|int|null $ifMatch = null)`, `updateJKSKeystore($id, $data, ?string $ifMatch = null)`, `updateYubikey($id, $data, ?string $ifMatch = null)`: a key present with `null` clears, an absent key keeps; unknown keys are rejected. The ETag is returned under `SecretServerClient::ETAG_KEY` (`_etag`).
- New constructor parameter `partialUpdates` (named) / `setPartialUpdates()`; `SS_PARTIAL_UPDATES=1` also opts in. New optional `caFile`.

**MCP bridge**

- `resolve_secret_template` now also requires `SECRETSERVER_RESOLVE_ALLOW`; the bridge refuses to start without it when resolution is enabled.

## Not verified live

| Area | Reason |
|---|---|
| YubiKey OTP validation | Calls the external Yubico validation service |
| Crypto signing (PKCS#11/eHSM) | Needs an operator-provisioned crypto backend and signing-key binding |
| LDAP search | Needs a reachable LDAP server behind a stored bind credential |
| Sharing | Recipient must be an active user or group of the tenant; the harness provisions none |
| Webhook create/test | The server's SSRF guard rejects loopback/private receivers |
| Audit `resource_id`/`user_id` filters | On `086b727` gin could not bind `*uuid.UUID` from a query string (HTTP 400); not re-checked on `3075630` |
| GraphQL / gRPC | Documented by the backend as design artifacts, not operational transports |

GPG, TOTP, certificate enroll/download, JKS keystores and `/export/json` secret
contents, which failed on `086b727`, are exercised for real against `3075630`.

Server-side observation, not a client issue: `hasExportPermission` in `handlers/ssh.go` always returns true, and the SSH export and certificate download routes are not wrapped in `RequirePermissions(PermExportRead)`.
