<?php

// Offline contract + security tests. Run via tests/run.sh (or composer test),
// which serves tests/router.php on a loopback port and sets TEST_SERVER_URL.

declare(strict_types=1);

require dirname(__DIR__) . '/src/SecretServerClient.php';

use SecretServer\AuthException;
use SecretServer\ConflictException;
use SecretServer\SecretServerClient;
use SecretServer\SecretServerException;

$baseURL = getenv('TEST_SERVER_URL');
if (!$baseURL) {
    throw new RuntimeException('TEST_SERVER_URL is required');
}

$passed = 0;
function check(bool $condition, string $what): void
{
    global $passed;
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $what);
    }
    $passed++;
}

/** Run $fn and return the SecretServerException it throws; fail if it does not throw. */
function expectFailure(callable $fn, string $what): SecretServerException
{
    try {
        $fn();
    } catch (SecretServerException $e) {
        check(true, $what);
        return $e;
    }
    throw new RuntimeException('FAIL: expected exception: ' . $what);
}

$client = new SecretServerClient('sk_test', $baseURL . '/api/v1');
$partial = new SecretServerClient('sk_test', $baseURL . '/api/v1', 10, true, null, true);

// ---------------------------------------------------------------------------
// Security policy: construction
// ---------------------------------------------------------------------------

$key = 'sk_SECRET_KEY_MARKER';
$e = expectFailure(fn () => new SecretServerClient($key, 'http://example.com'), 'plain http to non-loopback host rejected');
check(!str_contains($e->getMessage(), $key), 'base URL error does not leak API key');
expectFailure(fn () => new SecretServerClient($key, 'http://localhost.example.com'), 'http to loopback-lookalike host rejected');
expectFailure(fn () => new SecretServerClient($key, 'http://10.0.0.1:8080'), 'http to private non-loopback IP rejected');
expectFailure(fn () => new SecretServerClient($key, 'ftp://127.0.0.1'), 'non-http scheme rejected');
expectFailure(fn () => new SecretServerClient($key, 'not a url'), 'URL without host rejected');
$e = expectFailure(fn () => new SecretServerClient($key, 'https://user:hunter2pass@api.example.com'), 'userinfo in base URL rejected');
check(!str_contains($e->getMessage(), 'hunter2pass') && !str_contains($e->getMessage(), $key), 'userinfo error does not leak credentials');
expectFailure(fn () => new SecretServerClient($key, 'http://user@127.0.0.1'), 'userinfo rejected even for loopback');
$e = expectFailure(fn () => new SecretServerClient($key, 'https://api.example.com', 10, false), 'verifySsl=false rejected');
check(!str_contains($e->getMessage(), $key), 'verifySsl error does not leak API key');
expectFailure(fn () => new SecretServerClient($key, 'https://api.example.com', 10, true, '/nonexistent/ca.pem'), 'missing CA file rejected');
foreach (['https://api.example.com', 'http://localhost:1', 'http://127.0.0.1:1', 'http://[::1]:1'] as $okUrl) {
    new SecretServerClient($key, $okUrl);
    check(true, "accepted base URL $okUrl");
}

// ---------------------------------------------------------------------------
// Security policy: responses
// ---------------------------------------------------------------------------

$e = expectFailure(fn () => $client->request('GET', '/oversize'), 'response over 4 MiB rejected (Content-Length)');
check(str_contains($e->getMessage(), 'size limit'), 'oversize error names the size limit');
$e = expectFailure(fn () => $client->request('GET', '/oversize-chunked'), 'response over 4 MiB rejected (chunked)');
check(str_contains($e->getMessage(), 'size limit'), 'chunked oversize error names the size limit');
expectFailure(fn () => $client->request('GET', '/notjson'), 'non-JSON success response rejected');
expectFailure(fn () => $client->request('GET', '/scalar'), 'non-object JSON success response rejected');

$e = expectFailure(fn () => $client->request('GET', '/fail'), 'HTTP 500 raises');
check($e->getMessage() === 'SecretServer request failed (HTTP 500)' && $e->getCode() === 500, 'error message format');
check(!str_contains($e->getMessage(), 'BODY_LEAK_MARKER'), 'error does not include response body');

$e = expectFailure(fn () => $client->request('GET', '/redirect'), 'redirect is not followed');
check($e->getCode() === 302, 'redirect surfaces as HTTP 302');

$wrong = new SecretServerClient($key, $baseURL);
$e = expectFailure(fn () => $wrong->listSecrets(), 'wrong API key raises');
check($e instanceof AuthException, 'wrong API key raises AuthException');
check(!str_contains($e->getMessage(), $key) && !str_contains($e->getMessage(), 'BODY_LEAK_MARKER'), 'auth error free of key and body');

// ---------------------------------------------------------------------------
// Security policy: path segments are encoded, traversal refused
// ---------------------------------------------------------------------------

check($client->getJKSKeystore('../admin')['path'] === '/api/v1/jks-keystores/..%2Fadmin', 'id with slash encoded');
check($client->getGPGKey('a b?x=1#f')['path'] === '/api/v1/gpg-keys/a%20b%3Fx%3D1%23f', 'id with query chars encoded');
check($client->getSecret('c d/k%2F')['path'] === '/api/v1/s/c%20d/k%252F', 'secret path segments encoded');
check($client->getOpenSSLKey('x/y')['path'] === '/api/v1/openssl-keys/x%2Fy', 'openssl id encoded');
check($client->getTOTPToken('x/y')['path'] === '/api/v1/totp-tokens/x%2Fy', 'totp id encoded');
check($client->getYubikey('x/y')['path'] === '/api/v1/yubikeys/x%2Fy', 'yubikey id encoded');
check($client->getCertificate('x/y')['path'] === '/api/v1/certificates/x%2Fy', 'certificate id encoded');
check($client->credentials('wifi-credentials')->get('x/y')['path'] === '/api/v1/wifi-credentials/x%2Fy', 'credential resource id encoded');
check($client->getVersion('secret', 'x/y', 2)['path'] === '/api/v1/secret/x%2Fy/history/2', 'history type/id/version encoded');
check($client->getAuditLogs(['action' => 'a&b=c', 'limit' => 5, 'offset' => null])['path'] === '/api/v1/audit/logs?action=a%26b%3Dc&limit=5', 'audit query encoded, nulls dropped');
expectFailure(fn () => $client->getGPGKey('..'), 'dot-dot segment refused');
expectFailure(fn () => $client->getGPGKey(''), 'empty segment refused');
check($client->credentials('../admin')->list()['path'] === '/api/v1/..%2Fadmin', 'credential resource name encoded');
expectFailure(fn () => $client->credentials('..'), 'credential resource dot-dot refused');
expectFailure(fn () => $client->getHistory('secrets/../../admin', 'x'), 'unknown :type refused');

// ---------------------------------------------------------------------------
// Security policy: TLS verification is enforced; caFile trusts a private CA
// ---------------------------------------------------------------------------

$tmp = sys_get_temp_dir() . '/ss-php-tls-' . bin2hex(random_bytes(6));
mkdir($tmp, 0700);
$cert = "$tmp/cert.pem";
$certKey = "$tmp/key.pem";
exec(sprintf(
    'openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -addext %s -keyout %s -out %s 2>/dev/null',
    escapeshellarg('subjectAltName=DNS:localhost,IP:127.0.0.1'),
    escapeshellarg($certKey),
    escapeshellarg($cert)
), $out, $rc);
check($rc === 0 && is_file($cert), 'generated self-signed test certificate');
$proc = proc_open(
    [PHP_BINARY, '-d', 'display_errors=stderr', __DIR__ . '/tls_server.php', $cert, $certKey],
    [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']],
    $pipes
);
try {
    $tlsPort = (int) trim((string) fgets($pipes[1]));
    check($tlsPort > 0, 'TLS fixture started');
    $untrusted = new SecretServerClient('sk_test', "https://127.0.0.1:$tlsPort", 5);
    $e = expectFailure(fn () => $untrusted->listSecrets(), 'self-signed certificate rejected without caFile');
    check($e->getMessage() === 'SecretServer connection failed', 'TLS failure reported as connection failure');
    $trusted = new SecretServerClient('sk_test', "https://localhost:$tlsPort", 5, true, $cert);
    check(($trusted->listSecrets()[0]['name'] ?? null) === 'tls-ok', 'caFile trusts private CA (hostname verified)');
} finally {
    proc_terminate($proc);
    proc_close($proc);
    array_map('unlink', [$cert, $certKey]);
    rmdir($tmp);
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

// Partial updates need an explicit opt-in or a server ETag (A1): an old
// server treats PUT as a full replace and ignores If-Match.
putenv('SS_PARTIAL_UPDATES');
$partialError = 'partial updates require secretserver.io 3075630 or newer; pass an ETag from get() as if_match or enable partial_updates';
// Port 1 on loopback is closed: a request that was actually sent would fail
// with "SecretServer connection failed" instead of the partial-update error.
$offline = new SecretServerClient('sk_test', 'http://127.0.0.1:1');
$refusals = [
    'updateSecret without opt-in or ETag' => fn () => $offline->updateSecret('s', 'v'),
    'updateSecret with version-only If-Match' => fn () => $offline->updateSecret('s', 'v', [], 3),
    'updateSecret with numeric-string If-Match' => fn () => $offline->updateSecret('s', 'v', [], '3'),
    'updateSecret with * If-Match' => fn () => $offline->updateSecret('s', 'v', [], '*'),
    'updateSecret with unquoted If-Match' => fn () => $offline->updateSecret('s', 'v', [], '2026-01-01T00:00:00Z'),
    'updateSecret with half-quoted If-Match' => fn () => $offline->updateSecret('s', 'v', [], '"abc'),
    'updateSecret with lowercase w/ If-Match' => fn () => $offline->updateSecret('s', 'v', [], 'w/"abc"'),
    'updateSecret with expected_version only' => fn () => $offline->updateSecret('s', 'v', ['expected_version' => 3]),
    'updateJKSKeystore without opt-in or ETag' => fn () => $offline->updateJKSKeystore('j1', ['notes' => null]),
    'updateJKSKeystore with * If-Match' => fn () => $offline->updateJKSKeystore('j1', ['notes' => null], '*'),
    'updateYubikey without opt-in or ETag' => fn () => $offline->updateYubikey('y1', ['name' => 'n']),
    'updateYubikey with unquoted If-Match' => fn () => $offline->updateYubikey('y1', ['name' => 'n'], 'abc'),
];
foreach ($refusals as $what => $fn) {
    $e = expectFailure($fn, "$what refused");
    check($e->getMessage() === $partialError && $e->getCode() === 0, "$what refused client-side before any request");
}
// Against a reachable fixture the refusal still comes from the client.
$e = expectFailure(fn () => $client->updateSecret('prod/db', 'v'), 'refused against a live fixture too');
check($e->getMessage() === $partialError, 'refusal message names the minimum server and both remedies');

// Allowed: quoted and weak ETags without opt-in.
check($client->updateSecret('prod/db', 'v', [], '"2026-01-01T00:00:00Z"')['if_match'] === '"2026-01-01T00:00:00Z"', 'quoted ETag allows updateSecret without opt-in');
check($client->updateSecret('prod/db', 'v', [], 'W/"2026-01-01T00:00:00Z"')['if_match'] === 'W/"2026-01-01T00:00:00Z"', 'weak ETag allows updateSecret without opt-in');
check($client->updateJKSKeystore('j1', ['notes' => null], '"2026-01-01T00:00:00Z"')['raw'] === '{"notes":null}', 'quoted ETag allows updateJKSKeystore without opt-in');
check($client->updateYubikey('y1', ['name' => 'n'], 'W/"2026-01-01T00:00:00Z"')['raw'] === '{"name":"n"}', 'weak ETag allows updateYubikey without opt-in');

// Allowed: constructor opt-in, setter, and SS_PARTIAL_UPDATES=1.
check($partial->updateSecret('prod/db', 'v')['raw'] === '{"data":{"value":"v"}}', 'constructor opt-in allows updateSecret');
check($partial->updateSecret('prod/db', 'v', [], '*')['if_match'] === '*', 'opt-in allows * If-Match');
check($partial->updateJKSKeystore('j1', ['notes' => null])['raw'] === '{"notes":null}', 'constructor opt-in allows updateJKSKeystore');
check($partial->updateYubikey('y1', ['name' => 'n'])['raw'] === '{"name":"n"}', 'constructor opt-in allows updateYubikey');
$toggled = (new SecretServerClient('sk_test', $baseURL))->setPartialUpdates(true);
check($toggled->updateSecret('prod/db', 'v')['raw'] === '{"data":{"value":"v"}}', 'setPartialUpdates(true) allows updateSecret');
$toggled->setPartialUpdates(false);
check(expectFailure(fn () => $toggled->updateSecret('prod/db', 'v'), 'setPartialUpdates(false) refuses again')->getMessage() === $partialError, 'setPartialUpdates(false) restores refusal');
putenv('SS_PARTIAL_UPDATES=1');
$fromEnv = new SecretServerClient('sk_test', $baseURL);
putenv('SS_PARTIAL_UPDATES=true');
$notOne = new SecretServerClient('sk_test', 'http://127.0.0.1:1');
putenv('SS_PARTIAL_UPDATES');
check($fromEnv->updateYubikey('y1', ['name' => 'n'])['raw'] === '{"name":"n"}', 'SS_PARTIAL_UPDATES=1 enables partial updates');
check(expectFailure(fn () => $notOne->updateSecret('s', 'v'), 'SS_PARTIAL_UPDATES other than 1 does not opt in')->getMessage() === $partialError, 'only SS_PARTIAL_UPDATES=1 opts in');

$secrets = $client->listSecrets();
check(($secrets[0]['name'] ?? null) === 'db', 'secret list envelope unwrapped');

// Partial updates: omitted = keep, explicit null = clear; no pre-read GET.
$update = $partial->updateSecret('prod/db', 'new');
check(($update['method'] ?? null) === 'PUT' && ($update['path'] ?? null) === '/api/v1/secrets/prod%2Fdb', 'secret update path');
check($update['raw'] === '{"data":{"value":"new"}}', 'secret update sends only data (no read-merge-write)');
check($update['if_match'] === null, 'no If-Match unless requested');
check($update[SecretServerClient::ETAG_KEY] === '"2026-03-03T00:00:00Z"', 'update exposes response ETag');
$update = $partial->updateSecret('prod/db', null, ['description' => null]);
check($update['raw'] === '{"description":null}', 'null value omits data; explicit null description is sent as null');
$update = $partial->updateSecret('prod/db', 'v', ['tags' => [], 'container_id' => null, 'description' => '']);
check(json_decode($update['raw'], true) === ['tags' => [], 'container_id' => null, 'description' => '', 'data' => ['value' => 'v']], 'empty string and empty list are sent literally');
check($partial->updateSecret('prod/db')['raw'] === '{}', 'empty partial update is a JSON object');
check($partial->updateSecret('prod/db', null, ['expected_version' => 3])['raw'] === '{"expected_version":3}', 'expected_version sent in body');
expectFailure(fn () => $partial->updateSecret('prod/db', null, ['expected_version' => '3']), 'non-integer expected_version rejected');
expectFailure(fn () => $partial->updateSecret('prod/db', 'v', ['descrption' => 'x']), 'unknown secret update field rejected');
$record = $client->getSecret('db1');
check($record[SecretServerClient::ETAG_KEY] === '"2026-01-01T00:00:00Z"' && $record['name'] === 'db1', 'getSecret exposes ETag');
check($client->secret('db1') === 'v1', 'ETag key does not disturb scalar extraction');
check($partial->updateSecret('prod/db', 'v', [], $record[SecretServerClient::ETAG_KEY])['if_match'] === '"2026-01-01T00:00:00Z"', 'If-Match ETag sent');
check($partial->updateSecret('prod/db', 'v', [], 3)['if_match'] === '3', 'If-Match version number sent');
check($partial->updateSecret('prod/db', 'v', [], 'W/"2026-01-01T00:00:00Z"')['if_match'] === 'W/"2026-01-01T00:00:00Z"', 'weak If-Match sent verbatim');
$e = expectFailure(fn () => $partial->updateSecret('prod/db', 'v', [], '"stale"'), 'stale ETag raises');
check($e instanceof ConflictException, 'HTTP 409 raises ConflictException');
check($e->getCode() === 409 && $e->getMessage() === 'SecretServer request failed (HTTP 409)', 'conflict message format');
check($e->getETag() === '"2026-02-02T00:00:00Z"', 'ConflictException carries current ETag');
check(!str_contains($e->getMessage(), 'BODY_LEAK_MARKER') && !str_contains($e->getMessage(), 'sk_test'), 'conflict error free of key and body');
check($e instanceof SecretServerException, 'ConflictException is a SecretServerException');
$e = expectFailure(fn () => $partial->updateSecret('prod/db', 'v', [], 4), 'stale version raises');
check($e instanceof ConflictException, 'stale version raises ConflictException');
$e = expectFailure(fn () => $partial->updateSecret('prod/db', 'v', [], "\"x\"\r\nX-Injected: 1"), 'CRLF in If-Match rejected');
check(!($e instanceof ConflictException), 'CRLF If-Match rejected before any request');
expectFailure(fn () => $partial->updateSecret('prod/db', 'v', [], ''), 'empty If-Match rejected');

$jks = $client->getJKSKeystore('j1');
check($jks[SecretServerClient::ETAG_KEY] === '"2026-01-01T00:00:00Z"', 'getJKSKeystore exposes ETag');
$jks = $partial->updateJKSKeystore('j1', ['notes' => null], $jks[SecretServerClient::ETAG_KEY]);
check($jks['raw'] === '{"notes":null}' && $jks['if_match'] === '"2026-01-01T00:00:00Z"', 'JKS update sends only notes:null with If-Match');
check($jks[SecretServerClient::ETAG_KEY] === '"2026-03-03T00:00:00Z"', 'JKS update exposes new ETag');
check($partial->updateJKSKeystore('j1', ['password' => 'pw2'])['raw'] === '{"password":"pw2"}', 'JKS password rotation sends only password');
expectFailure(fn () => $partial->updateJKSKeystore('j1', ['jks' => 'AAAA']), 'JKS upload without password rejected');
expectFailure(fn () => $partial->updateJKSKeystore('j1', ['store_type' => 'raw']), 'unknown JKS update field rejected');
$e = expectFailure(fn () => $partial->updateJKSKeystore('j1', ['name' => 'n'], '"stale"'), 'stale JKS ETag raises');
check($e instanceof ConflictException && $e->getETag() === '"2026-02-02T00:00:00Z"', 'JKS conflict carries ETag');

$yk = $client->getYubikey('y1');
check($yk[SecretServerClient::ETAG_KEY] === '"2026-01-01T00:00:00Z"', 'getYubikey exposes ETag');
$yk = $partial->updateYubikey('y1', ['serial_number' => null, 'name' => 'yk2'], '*');
check(json_decode($yk['raw'], true) === ['serial_number' => null, 'name' => 'yk2'] && $yk['if_match'] === '*', 'YubiKey update sends only given fields');
expectFailure(fn () => $partial->updateYubikey('y1', ['public_id' => 'short']), 'YubiKey public_id length enforced');
expectFailure(fn () => $partial->updateYubikey('y1', ['id' => 'y2']), 'unknown YubiKey update field rejected');
$e = expectFailure(fn () => $partial->updateYubikey('y1', ['name' => 'n'], '"stale"'), 'stale YubiKey ETag raises');
check($e instanceof ConflictException && $e->getETag() === '"2026-02-02T00:00:00Z"', 'YubiKey conflict carries ETag');

$pw = $client->createPassword('pw', 'alice', 's3cret');
check(($pw['body']['value'] ?? null) === 's3cret' && !isset($pw['body']['password']), 'createPassword sends value');
$gen = $client->generatePassword('gp', 20, false);
check($gen['body'] === ['name' => 'gp', 'length' => 20, 'use_lowercase' => true, 'use_uppercase' => true, 'use_digits' => true, 'use_symbols' => false], 'generatePassword body');
expectFailure(fn () => $client->generatePassword('gp', 7), 'password length below 8 rejected');
expectFailure(fn () => $client->generatePassword('gp', 129), 'password length above 128 rejected');

$tok = $client->createAPIToken('t', 'github', 'ghp_x', 'staging');
check($tok['body'] === ['name' => 't', 'service' => 'github', 'value' => 'ghp_x', 'environment' => 'staging'], 'createAPIToken body');
expectFailure(fn () => $client->createAPIToken('t', 'github', 'ghp_x', 'prod'), 'invalid token environment rejected');
$rot = $client->rotateAPIToken('tk1', 'ghp_y');
check($rot['path'] === '/api/v1/api-tokens/tk1/rotate' && $rot['body'] === ['value' => 'ghp_y'], 'rotateAPIToken body');

$share = $client->share('password', 'p1', 'u-1', null, 'manage', null);
check($share['path'] === '/api/v1/password/p1/shares' && $share['body'] === ['permission' => 'manage', 'shared_with_user_id' => 'u-1'], 'share with user');
$share = $client->share('secret', 's1', null, 'g-1');
check(($share['body']['shared_with_group_id'] ?? null) === 'g-1' && isset($share['body']['expires_at']) && !isset($share['body']['shared_with_user_id']), 'share with group');
expectFailure(fn () => $client->share('secret', 's1', 'u-1', 'g-1'), 'share with both user and group rejected');
expectFailure(fn () => $client->share('secret', 's1'), 'share with neither user nor group rejected');
expectFailure(fn () => $client->share('secret', 's1', 'u-1', null, 'write'), 'invalid share permission rejected');
expectFailure(fn () => $client->share('secrets', 's1', 'u-1'), 'invalid share type rejected');

check($client->createTempAccess('secret', 's1', 60)['body'] === ['duration_seconds' => 60], 'temp access minimum accepted');
expectFailure(fn () => $client->createTempAccess('secret', 's1', 59), 'temp access below 60s rejected');
expectFailure(fn () => $client->createTempAccess('secret', 's1', 86401), 'temp access above 86400s rejected');

check($client->getHistory('secret', 's1') === [['version_num' => 1, 'secret_type' => 'secret']], 'history is a bare array');
expectFailure(fn () => $client->getHistory('secret', 'not-a-list'), 'non-list history rejected');

$gpg = $client->generateGPGKey('g', 'g@example.test', 'RSA4096', ['comment' => 'c']);
check($gpg['body'] === ['comment' => 'c', 'name' => 'g', 'email' => 'g@example.test', 'algorithm' => 'RSA4096'], 'generateGPGKey body');
expectFailure(fn () => $client->generateGPGKey('g', 'g@example.test', 'rsa'), 'invalid GPG algorithm rejected');
check($client->importGPGKey('-----BEGIN PGP-----', 'pp')['body'] === ['armored_key' => '-----BEGIN PGP-----', 'passphrase' => 'pp'], 'importGPGKey body');
check($client->exportGPGKey('g1', 'private')['path'] === '/api/v1/gpg-keys/g1/export?format=private', 'exportGPGKey format param');
expectFailure(fn () => $client->exportGPGKey('g1', 'secret'), 'invalid GPG export format rejected');

check($client->generateOpenSSLKey('o', 'ecdsa', 4096, 'P-384')['body'] === ['name' => 'o', 'algorithm' => 'ecdsa', 'curve' => 'P-384'], 'generateOpenSSLKey ecdsa body');
check($client->generateOpenSSLKey('o', 'rsa', 2048)['body'] === ['name' => 'o', 'algorithm' => 'rsa', 'key_size' => 2048], 'generateOpenSSLKey rsa body');
expectFailure(fn () => $client->generateOpenSSLKey('o', 'dsa'), 'invalid OpenSSL algorithm rejected');
check($client->importOpenSSLKey('o', 'rsa', 'PEM')['body'] === ['name' => 'o', 'algorithm' => 'rsa', 'private_key' => 'PEM'], 'importOpenSSLKey body');

check($client->downloadCertificate('c1') === 'RAW-PEM:format=pem', 'certificate download returns raw body');
check($client->downloadCertificate('c1', 'pfx', 'p w&x') === 'RAW-PEM:format=pfx&password=p%20w%26x', 'certificate pfx password encoded');
expectFailure(fn () => $client->downloadCertificate('c1', 'p12'), 'pfx/p12 without password rejected');
expectFailure(fn () => $client->downloadCertificate('c1', 'der'), 'invalid certificate format rejected');
check(strlen($client->downloadCertificate('mid')) === 5 * 1024 * 1024, 'raw download allows up to 16 MiB');
$e = expectFailure(fn () => $client->downloadCertificate('big'), 'raw download over 16 MiB rejected');
check(str_contains($e->getMessage(), 'size limit'), 'raw oversize error names the size limit');

check($client->exportAuditLogs(['action' => 'a b', 'user_id' => null])['path'] === '/api/v1/audit/logs/export?action=a%20b&format=json', 'exportAuditLogs requests JSON with encoded filters');
check($client->listTOTPTokens() === [['id' => 't1']], 'TOTP list envelope unwrapped');
check($client->exportToJSON(true, false, true, false, ['prod'])['body'] === ['include_passwords' => true, 'include_secrets' => false, 'include_ssh_keys' => true, 'include_certificates' => false, 'tags' => ['prod']], 'exportToJSON flags');
check($client->exportToKeychain()['path'] === '/api/v1/export/keychain' && !isset($client->exportToKeychain()['body']['items']), 'exportToKeychain has no items');
check($client->exportToCredentialManager(false)['body']['include_passwords'] === false, 'exportToCredentialManager flags');
$hook = $client->createWebhook('h', 'https://hooks.example.test', ['secret.create'], 'whsec');
check($hook['body'] === ['name' => 'h', 'url' => 'https://hooks.example.test', 'events' => ['secret.create'], 'secret' => 'whsec'], 'createWebhook sends secret, no auth_type');
check($client->decode('eyJ...', 'jwt') === ['sub' => 'x'], 'decode returns structured result for jwt');

check($client->getSecret('a/b/12')['path'] === '/api/v1/s/a/b/12', 'three-segment path with version accepted');
expectFailure(fn () => $client->secret('a/b/c/d'), 'four-segment secret path rejected');
expectFailure(fn () => $client->secret('a/b/13'), 'version above 12 rejected');
expectFailure(fn () => $client->secret('a/b/0'), 'version 0 rejected');
expectFailure(fn () => $client->secret('a/b/x'), 'non-numeric version rejected');

$enroll = $client->enrollCertificate('wildcard', 'example.test', ['www.example.test']);
check(($enroll['body']['dns_names'][0] ?? null) === 'www.example.test' && !isset($enroll['body']['sans']), 'certificate enrollment matches backend contract');

echo "PHP contract PASS ($passed checks)\n";
