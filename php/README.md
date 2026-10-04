# SecretServer.io PHP client

```bash
composer require afterdark/secretserver
```

Requires PHP 8.0+ with the curl and json extensions.

## Use your `ss login`

Instead of an API key, pass a credential provider. `CliCredentialProvider`
reuses the SSO session of the `ss` CLI:

```php
use SecretServer\CliCredentialProvider;
use SecretServer\SecretServerClient;

$ss = new SecretServerClient(credentialProvider: new CliCredentialProvider());
```

It runs `ss auth print-access-token --format json` (first constructor argument,
else `SS_CLI_PATH`, else `ss` on `PATH`) through `proc_open` with an argv array
(no shell), a 30 s timeout (second argument) and a 64 KiB output cap, and caches
the token in memory until 60 s before it expires. If the CLI is not logged in it
throws `AuthException` asking you to run `ss login`. Without `$apiUrl` or
`SS_API_URL` the client uses the API URL the CLI is logged in to (the CLI runs
once when the client is created). Any callable returning a token works as
`$credentialProvider` (mutually exclusive with `$apiKey`); tokens never appear
in exceptions.

## Partial updates

**Minimum server: secretserver.io 3075630 (partial, conditional updates).**

`updateSecret()`, `updateJKSKeystore()` and `updateYubikey()` send only the
fields you pass. Older servers treat these requests as a full replace and
silently blank the omitted fields, so the client refuses to send them (no
request is made) unless one of the following holds:

- the client opted in: constructor argument `partialUpdates: true`,
  `$ss->setPartialUpdates(true)`, or the environment variable
  `SS_PARTIAL_UPDATES=1`;
- `$ifMatch` is an ETag previously returned by the server, either strong
  (`"..."`) or weak (`W/"..."`). A version number, `*`, an unquoted value or
  `expected_version` alone does not count, because an old server ignores them.

```php
use SecretServer\SecretServerClient;

// Opt in when the server is 3075630 or newer.
$ss = new SecretServerClient(getenv('SS_API_KEY'), partialUpdates: true);
$ss->updateSecret('db-password', 'new-value');

// Or prove support per call with the ETag from a previous read.
$ss = new SecretServerClient(getenv('SS_API_KEY'));
$record = $ss->getSecret('db-password');
$ss->updateSecret('db-password', 'new-value', [], $record[SecretServerClient::ETAG_KEY]);
```

A stale ETag throws `ConflictException`; its `getETag()` is the current one.

## Tests

- `composer test` runs the offline contract and security tests against a
  loopback fixture.
- `tests/live.php` runs only against a disposable loopback server started by
  `scripts/live-integration.sh`; it refuses to start unless `SS_LIVE_URL`
  points at localhost, 127.0.0.1 or ::1 and `SS_LIVE_KEY` is set.


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

## Install from git

No registry account needed; see the top-level README for `<ref>` values.

```bash
git clone -b <ref> https://github.com/afterdarksys/secretserver-clients.git
composer config repositories.secretserver path ./secretserver-clients/php   # a vcs repository does not work for a subdirectory
composer require afterdark/secretserver:@dev
```
