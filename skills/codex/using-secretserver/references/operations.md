# SecretServer operations

## MCP

The standalone bridge in `mcp/` currently advertises only:

- `list_key_metadata(backend)` for `pkcs11` or `ehsm`; requires `keys:sign`.
- `sign_with_key(backend, key_id, message, purpose)`; `message` is base64 and decoded size is limited to 1 MiB; requires `keys:sign`.

Do not assume `decrypt_with_key` or `use_provider_credential` exists until the server advertises it.

Configure Codex:

```bash
codex mcp add \
  --env SECRETSERVER_URL=https://api.secretserver.io \
  --env SECRETSERVER_TOKEN_FILE=/absolute/path/to/agent-token \
  secretserver \
  -- /absolute/path/to/secretserver-mcp
```

Configure Claude Code:

```bash
claude mcp add --transport stdio --scope user secretserver \
  --env SECRETSERVER_URL=https://api.secretserver.io \
  --env SECRETSERVER_TOKEN_FILE=/absolute/path/to/agent-token \
  -- /absolute/path/to/secretserver-mcp
```

The token file must be a regular owner-only file. Use an absolute path. Put only a short-lived `keys:sign` API identity in it.

Alternative for interactive use on a developer machine: log in once with `ss login` (browser SSO) and set `SECRETSERVER_USE_CLI_LOGIN=1` instead of `SECRETSERVER_TOKEN_FILE` (setting both is refused). The bridge runs `ss auth print-access-token --format json` (binary from `SS_CLI_PATH`, else `ss` on `PATH`) and follows the CLI's refreshes; `SECRETSERVER_URL` is optional and defaults to the URL the CLI is logged in to. If the CLI has no session the bridge exits with "run `ss login`" — ask the user to run it in a terminal; never ask for or handle the token yourself.

```bash
claude mcp add --transport stdio --scope user secretserver \
  --env SECRETSERVER_USE_CLI_LOGIN=1 \
  -- /absolute/path/to/secretserver-mcp
# Codex: codex mcp add --env SECRETSERVER_USE_CLI_LOGIN=1 secretserver -- /absolute/path/to/secretserver-mcp
```

Trade-off: `ss login` is the user's full session, not a key scoped to `keys:sign`. Prefer a scoped token file for unattended or shared agents.

## REST metadata

- `GET /api/v1/key-catalog` lists key and secret types.
- `GET /api/v1/integration-providers` lists provider credential schemas.
- `GET /api/v1/integrations` lists stored integration metadata.
- `GET /api/v1/crypto/backends` checks configured cryptographic backends.
- `GET /api/v1/crypto/signing-keys?backend=pkcs11` lists signing-key metadata.
- `POST /api/v1/crypto/sign` signs inside the selected backend.

Integration reads are redacted by default. Treat `?reveal=true` as an explicit export requiring `export:read` and an approved destination.

## Client selection

- Go: `go/`
- Node.js/TypeScript: `node/`
- Python: `python/`
- PHP: `php/`
- Ansible lookup: `ansible/`

Client authentication: for interactive use, borrow the developer's `ss login` session instead of storing an API key — Go `secretserver.NewCLIClient(ctx, nil)`, Node `cliCredentialProvider()`, Python `cli_credential_provider()`, PHP `CliCredentialProvider`, Ansible `use_cli_login=true`, GUI "Sign in with ss login". Use a scoped API key for CI and servers.

Use path-safe SDK methods instead of constructing resource URLs manually. Never pass a secret on a command line because process listings and shell histories may retain it.

## Permission selection

- Metadata: `credentials:read` or the resource-specific read permission.
- Store/update provider credentials: `credentials:write`.
- Use provider credentials without export when supported: `credentials:use`.
- HSM/smart-card signing: `keys:sign`.
- Explicit secret/key export: `export:read`.
- Destructive operations: the resource-specific delete or revoke permission.
