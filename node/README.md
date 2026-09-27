# secretserver (Node.js / TypeScript)

Zero-dependency client for SecretServer.io. Node.js 18+ (native fetch).

```ts
import { SecretServerClient } from "secretserver";

const ss = new SecretServerClient({ apiKey: process.env.SS_API_KEY });
const value = await ss.secret("production/db-password");
```

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
