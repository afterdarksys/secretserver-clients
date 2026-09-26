<?php

// Offline contract + security tests. Run via tests/run.sh (or composer test),
// which serves tests/router.php on a loopback port and sets TEST_SERVER_URL.

declare(strict_types=1);

require dirname(__DIR__) . '/src/SecretServerClient.php';

use SecretServer\AuthException;
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

$secrets = $client->listSecrets();
check(($secrets[0]['name'] ?? null) === 'db', 'secret list envelope unwrapped');

$update = $client->updateSecret('prod/db', 'new');
check(($update['body']['name'] ?? null) === 'prod/db' && ($update['path'] ?? null) === '/api/v1/secrets/prod%2Fdb', 'secret update matches backend contract');

$enroll = $client->enrollCertificate('wildcard', 'example.test', ['www.example.test']);
check(($enroll['body']['dns_names'][0] ?? null) === 'www.example.test' && !isset($enroll['body']['sans']), 'certificate enrollment matches backend contract');

echo "PHP contract PASS ($passed checks)\n";
