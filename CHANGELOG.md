# Changelog

## 1.4.0 — unreleased

Use your `ss login` (browser SSO) session from every client instead of storing
an API key. Contract: `ss auth print-access-token --format json` (see
`secretserver.io/docs/CLI_SSO_LOGIN.md` §2–3).

### Added

- **Go** (`go/`): `Config.TokenProvider` (mutually exclusive with `APIKey`),
  `CLICredentials()` / `CLICredentialProvider` (`Token`, `APIURL`, `TenantID`),
  `NewCLIClient(ctx, cfg)`, `ErrCLINotLoggedIn`, `NormalizeAPIURL`.
- **Node** (`node/`): `cliCredentialProvider()` for `credentialProvider`.
- **Python** (`python/`): `cli_credential_provider()` for `credential_provider`.
- **PHP** (`php/`): `$credentialProvider` callable and `CliCredentialProvider`.
- **Ansible lookup**: `use_cli_login: true` (uses the Python helper).
- **MCP bridge** (`mcp/`): `SECRETSERVER_USE_CLI_LOGIN=1` as an alternative to
  `SECRETSERVER_TOKEN_FILE` (setting both is refused); `SECRETSERVER_URL`
  defaults to the CLI's API URL.
- **Desktop GUI** (`go-gui/`): Settings → "Sign in with ss login" next to the
  keychain API key. Only the choice (and an optional API URL) is stored; the
  status line shows API URL and tenant, never the token.

Every provider runs the CLI from an argv array (no shell; binary from
`SS_CLI_PATH`, else `ss`), with a 30 s timeout and 64 KiB output cap, caches the
token in memory until 60 s before expiry, maps exit 2 to "run `ss login`", and
never puts tokens in errors or logs.

### Security

- Every client refuses to send an `ss login` token to an API URL other than the
  one the session was issued for (comparison after normalizing case, default
  port and trailing slash).
- MCP `securemem`: locked pages are budgeted against `RLIMIT_MEMLOCK` (minus
  headroom; 16 MiB when unlimited). An allocation that does not fit fails with
  `ErrExhausted` and existing buffers stay valid, instead of MemGuard purging
  every buffer (including the service token). A dependency failure now exits
  with status 70 for a supervised restart.

### Docs

- `ss login` documented for every client, the MCP skill references
  (`skills/*/using-secretserver/references/operations.md`) and the MCP README;
  corrected the API-key creation instructions.
- Offline cache service README: how a future implementation should obtain
  credentials (CLI provider or scoped API key).
