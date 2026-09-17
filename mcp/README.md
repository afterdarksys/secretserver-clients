# SecretServer MCP bridge

This standalone stdio MCP server exposes operation-only SecretServer tools:

- `list_key_metadata` lists non-exportable PKCS#11 or eHSM signing keys.
- `sign_with_key` signs a bounded base64 message inside the configured device and returns a signature plus audit correlation ID.

By default, the two signing tools do not expose private keys, PINs, passwords, provider credentials, or decrypted plaintext. The API identity is read from an owner-only file into locked memory. The bridge refuses non-loopback plaintext HTTP.

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

## Optional variable resolution

Set `SECRETSERVER_ENABLE_SECRET_RESOLUTION=1` to register
`resolve_secret_template` with input `{"template":"%%LOG_SERVER_TX1_S%%"}`.
This tool intentionally returns resolved plaintext into the calling model's
context. Its API identity must have read/export permission on the underlying
credential. The default signing-only configuration does not register this tool.
Variable syntax and permissions match the REST `/api/v1/variables/resolve` API.
