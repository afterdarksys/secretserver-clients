# secretserver (Node.js / TypeScript)

Zero-dependency client for SecretServer.io. Node.js 18+ (native fetch).

```ts
import { SecretServerClient } from "secretserver";

const ss = new SecretServerClient({ apiKey: process.env.SS_API_KEY });
const value = await ss.secret("production/db-password");
```

## Use your `ss login`

Instead of an API key, reuse the SSO session of the `ss` CLI:

```ts
import { SecretServerClient, cliCredentialProvider, AuthError } from "secretserver";

const ss = new SecretServerClient({ credentialProvider: cliCredentialProvider() });
// AuthError "... run `ss login`" when the CLI has no valid session.
```

The provider runs `ss auth print-access-token --format json` (the binary from
`SS_CLI_PATH`, else `ss` on `PATH`; options `cliPath`, `timeoutMs`) through
`execFile` without a shell, with a 30 s timeout and a 64 KiB output cap. It
caches the token in memory until 60 s before expiry. When neither `apiUrl` nor
`SS_API_URL` is set, the client uses the API URL the CLI is logged in to.
Tokens never appear in errors.

## Partial updates

**Minimum server: secretserver.io 3075630 (partial, conditional updates).**

`updateSecret`, `updateJKSKeystore` and `updateYubikey` send only the fields
you pass. Older servers treat these PUTs as a full replace and silently blank
every omitted field, so the client refuses to send them (no request is made)
unless one of these holds:

- the client opted in: `new SecretServerClient({ ..., partialUpdates: true })`,
  or `SS_PARTIAL_UPDATES=1` in the environment when the client is constructed
  (an explicit `partialUpdates: false` wins over the environment);
- `ifMatch` is an ETag the server returned (`"..."` or `W/"..."`), e.g. the
  `etag` of `getSecret()`, `getJKSKeystore()` or `getYubikey()`. A version
  number, `*`, an unquoted value or `expectedVersion` alone does not qualify.

```ts
const current = await ss.getSecret("db-password");
await ss.updateSecret("db-password", "new-value", { ifMatch: current.etag });
```

Field semantics in the update inputs: `undefined` (omitted) keeps the stored
value, `null` clears it (nullable fields only), and `""` is stored as a literal
empty string, not a clear. A stale `ifMatch` throws `ConflictError`, whose
`etag` is the current one.


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
