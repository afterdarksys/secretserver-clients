# SecretServer.io PHP client

```bash
composer require afterdark/secretserver
```

Requires PHP 8.0+ with the curl and json extensions.

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
