# SecretServer MCP bridge

This standalone stdio MCP server exposes operation-only SecretServer tools:

- `list_key_metadata` lists non-exportable PKCS#11 or eHSM signing keys.
- `sign_with_key` signs a bounded base64 message inside the configured device and returns a signature plus audit correlation ID.

By default, the two signing tools do not expose private keys, PINs, passwords, provider credentials, or decrypted plaintext. The API identity is read from an owner-only file into locked memory (or, opt-in, taken from your `ss login` session). The bridge refuses non-loopback plaintext HTTP.

## Build

```bash
go build -o secretserver-mcp .
```

Create a short-lived SecretServer API key with only `keys:sign`, store it in a mode `0600` file, and configure either client:

```bash
codex mcp add \
  --env SECRETSERVER_URL=https://api.secretserver.io \
  --env SECRETSERVER_TOKEN_FILE=/absolute/path/to/agent-token \
  secretserver \
  -- /absolute/path/to/secretserver-mcp

claude mcp add --transport stdio --scope user secretserver \
  --env SECRETSERVER_URL=https://api.secretserver.io \
  --env SECRETSERVER_TOKEN_FILE=/absolute/path/to/agent-token \
  -- /absolute/path/to/secretserver-mcp
```

Do not place the API key itself in MCP configuration or environment variables.

### Use your `ss login` instead of a token file

For interactive use on a developer machine, set `SECRETSERVER_USE_CLI_LOGIN=1`
(and no `SECRETSERVER_TOKEN_FILE`; setting both is refused). The bridge then
runs `ss auth print-access-token --format json` (the binary from `SS_CLI_PATH`,
else `ss` on `PATH`; argv only, 30 s timeout, 64 KiB output cap) at startup and
whenever the short-lived access token is within 60 s of expiry, so it follows
the CLI's refreshes. `SECRETSERVER_URL` is optional in this mode and defaults to
the API URL the CLI is logged in to. The bridge exits at startup with "run
`ss login`" if the CLI has no session.

```bash
claude mcp add --transport stdio --scope user secretserver \
  --env SECRETSERVER_USE_CLI_LOGIN=1 \
  -- /absolute/path/to/secretserver-mcp
```

Trade-off: the identity is your full user session rather than a key scoped to
`keys:sign`, and the access token is cached in ordinary process memory, not the
locked memory used for the token file. Prefer a scoped token file for unattended
or shared agents.

## Optional variable resolution

Set `SECRETSERVER_ENABLE_SECRET_RESOLUTION=1` together with
`SECRETSERVER_RESOLVE_ALLOW=NAME[,NAME...]` to register
`resolve_secret_template` with input `{"template":"%%LOG_SERVER_TX1_S%%"}`.
The bridge refuses to start if resolution is enabled without an allowlist, and
the tool refuses (without contacting the server) any template that references a
variable outside the allowlist or is malformed. This bounds what a
prompt-injected model can pull into its context to the variables the operator
chose. The tool intentionally returns resolved plaintext into the calling
model's context. Its API identity must have read/export permission on the
underlying credential. The default signing-only configuration does not register
this tool. Variable syntax and permissions match the REST
`/api/v1/variables/resolve` API.

## Transport safety

The bridge never follows HTTP redirects (so the bearer token cannot be replayed
to another origin), requires TLS 1.2 or newer, bounds responses to 4 MiB, and
validates signing inputs (key id and purpose 1-256 characters, message at most
1 MiB decoded) before any request is sent. A reverse-proxy path prefix in
`SECRETSERVER_URL` is preserved.
