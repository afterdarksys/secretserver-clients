
## Authentication

Pass exactly one of `Config.APIKey` or `Config.TokenProvider`
(`func(ctx context.Context) (string, error)`, called before every request).

To reuse your `ss login` SSO session instead of an API key:

```go
client, err := secretserver.NewCLIClient(ctx, nil) // runs `ss auth print-access-token --format json`
if err != nil { /* errors.Is(err, secretserver.ErrCLINotLoggedIn): run `ss login` */ }
```

`NewCLIClient`'s `*Config` may set `APIURL` to pin a different host; it must
not set `APIKey` or `TokenProvider`. Or set `Config{TokenProvider:
secretserver.CLICredentials().Token}` with your own `APIURL`. The CLI is
taken from `SS_CLI_PATH`, else `ss` on `PATH` (override with
`CLICredentialProvider.Path`), run without a shell, limited to 30 s and 64 KiB
of output. Tokens are cached in memory until 60 s before they expire and
never appear in errors.


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
