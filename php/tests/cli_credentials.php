<?php

// CliCredentialProvider against fake `ss` executables. Run via tests/run.sh
// (or composer test), which sets TEST_SERVER_URL to tests/router.php.

declare(strict_types=1);

require dirname(__DIR__) . '/src/CliCredentialProvider.php';

use SecretServer\AuthException;
use SecretServer\CliCredentialProvider;
use SecretServer\SecretServerClient;
use SecretServer\SecretServerException;

$baseURL = getenv('TEST_SERVER_URL');
if (!$baseURL) {
    throw new RuntimeException('TEST_SERVER_URL is required');
}
putenv('SS_API_URL');
putenv('SS_API_KEY');

const TOKEN = 'eyJ.cli-session-token-do-not-leak.sig';

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

/** A fake `ss` that counts its runs and refuses any argv but the documented one. Returns [path, runs()]. */
function fakeSS(string $body): array
{
    $dir = sys_get_temp_dir() . '/fake-ss-' . bin2hex(random_bytes(8));
    mkdir($dir, 0700);
    $path = "$dir/ss";
    $count = "$dir/count";
    file_put_contents($path, <<<SH
#!/bin/sh
echo run >> '$count'
if [ "\$#" -ne 4 ] || [ "\$1" != auth ] || [ "\$2" != print-access-token ] || [ "\$3" != --format ] || [ "\$4" != json ]; then
  echo "unexpected argv: \$*" >&2; exit 1
fi
$body

SH);
    chmod($path, 0700);
    return [$path, static fn (): int => is_file($count) ? substr_count((string) file_get_contents($count), "run\n") : 0];
}

function tokenJSON(int $expiresIn, string $apiUrl = '', string $token = TOKEN): string
{
    $json = json_encode(['access_token' => $token, 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + $expiresIn), 'api_url' => $apiUrl, 'tenant_id' => 't-1'], JSON_UNESCAPED_SLASHES);
    return "printf '%s' '$json'";
}

function noToken(Throwable $e): bool
{
    for ($x = $e; $x !== null; $x = $x->getPrevious()) {
        if (str_contains($x->getMessage(), TOKEN) || str_contains((string) $x, TOKEN)) {
            return false;
        }
    }
    return true;
}

// Success + cached reuse.
[$path, $runs] = fakeSS(tokenJSON(3600, 'https://api.example.test'));
$p = new CliCredentialProvider($path);
check($p() === TOKEN && $p() === TOKEN && $p() === TOKEN, 'token returned');
check($p->apiUrl() === 'https://api.example.test', 'api_url returned');
check($runs() === 1, 'token cached until 60 s before expiry');
check(!str_contains(print_r($p, true), TOKEN), 'print_r redacts the token');
try {
    serialize($p);
    check(false, 'serialize refused');
} catch (LogicException) {
    check(true, 'serialize refused');
}

// Refresh within 60 s of expiry.
[$path, $runs] = fakeSS(tokenJSON(30));
$p = new CliCredentialProvider($path);
$p();
$p();
check($runs() === 2, 'token within 60 s of expiry is refreshed');

// SS_CLI_PATH.
[$path, $runs] = fakeSS(tokenJSON(3600));
putenv("SS_CLI_PATH=$path");
check((new CliCredentialProvider())() === TOKEN && $runs() === 1, 'SS_CLI_PATH honoured');
putenv('SS_CLI_PATH');

// Exit 2 -> AuthException mentioning `ss login`.
[$path] = fakeSS('echo "not logged in" >&2; exit 2');
$e = expectFailure(fn () => (new CliCredentialProvider($path))(), 'exit 2 fails');
check($e instanceof AuthException && str_contains($e->getMessage(), 'ss login'), 'exit 2 is AuthException mentioning ss login');

// Failures fail closed without leaking the token.
$cases = [
    'exit 1' => ["echo 'network unreachable' >&2; printf '" . TOKEN . "'; exit 1", 'exit 1): network unreachable'],
    'malformed json' => ["printf '{\"access_token\":\"" . TOKEN . "\",'", 'invalid JSON'],
    'bad expires_at' => ["printf '{\"access_token\":\"" . TOKEN . "\",\"expires_at\":\"soon\"}'", 'expires_at'],
    'empty token' => ["printf '{\"access_token\":\"\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'", 'access_token'],
    'header injection' => ["printf '{\"access_token\":\"a\\\\r\\\\nX: y\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'", 'access_token'],
    'oversized stdout' => ["head -c 70000 /dev/zero | tr '\\0' a; " . tokenJSON(3600), 'exceeds 65536 bytes'],
];
foreach ($cases as $name => [$body, $want]) {
    [$path] = fakeSS($body);
    $e = expectFailure(fn () => (new CliCredentialProvider($path))(), $name);
    check(!($e instanceof AuthException) && str_contains($e->getMessage(), $want), "$name: message mentions '$want'");
    check(noToken($e), "$name: no token in exception");
}

// Timeout (configurable so the test is fast).
[$path] = fakeSS('exec sleep 10');
$start = microtime(true);
$e = expectFailure(fn () => (new CliCredentialProvider($path, 0.2))(), 'timeout');
check(str_contains($e->getMessage(), 'timed out') && microtime(true) - $start < 5, 'timeout is enforced promptly');

// Missing binary.
$e = expectFailure(fn () => (new CliCredentialProvider(sys_get_temp_dir() . '/no-such-ss-binary'))(), 'missing binary');
check(str_contains($e->getMessage(), 'not found'), 'missing binary message');
try {
    new CliCredentialProvider(null, 0);
    check(false, 'zero timeout refused');
} catch (InvalidArgumentException) {
    check(true, 'zero timeout refused');
}

// Client integration: token per request, api_url from the CLI.
[$path, $runs] = fakeSS(tokenJSON(3600, $baseURL, 'sk_test'));
$client = new SecretServerClient(credentialProvider: new CliCredentialProvider($path));
check(($client->listDocuments()['uri'] ?? null) === '/api/v1/documents', 'client uses CLI token and api_url');
$client->listDocuments();
check($runs() === 1, 'client reuses the cached token');

[$path] = fakeSS('exit 2');
$client = new SecretServerClient(apiUrl: $baseURL, credentialProvider: new CliCredentialProvider($path));
$e = expectFailure(fn () => $client->listDocuments(), 'logged-out client fails');
check($e instanceof AuthException && str_contains($e->getMessage(), 'ss login'), 'client surfaces run ss login');

// An explicit apiUrl that disagrees with the CLI's own session is refused on
// first use: the token must never be sent to a host the session was not
// issued for.
[$path, $runs] = fakeSS(tokenJSON(3600, 'https://cli.example.test'));
$client = new SecretServerClient(apiUrl: 'https://pinned.example.test', credentialProvider: new CliCredentialProvider($path));
check($runs() === 0, 'mismatch check is deferred to first request');
$e = expectFailure(fn () => $client->listDocuments(), 'mismatched api URL refused');
check(
    !($e instanceof AuthException)
    && str_contains($e->getMessage(), 'https://pinned.example.test')
    && str_contains($e->getMessage(), 'https://cli.example.test')
    && noToken($e),
    'mismatch error names both URLs and omits the token'
);

// An explicit apiUrl equal to the CLI's session modulo case and a trailing
// slash is not a mismatch.
$baseUrlParts = parse_url($baseURL);
$equivalentCliUrl = strtoupper((string) $baseUrlParts['scheme']) . '://' . strtoupper((string) $baseUrlParts['host'])
    . (isset($baseUrlParts['port']) ? ':' . $baseUrlParts['port'] : '') . '/';
[$path, $runs] = fakeSS(tokenJSON(3600, $equivalentCliUrl, 'sk_test'));
$client = new SecretServerClient(apiUrl: $baseURL, credentialProvider: new CliCredentialProvider($path));
check(($client->listDocuments()['uri'] ?? null) === '/api/v1/documents', 'equivalent (case/slash) api URL from the CLI is accepted');

$e = expectFailure(fn () => new SecretServerClient('sk_test', $baseURL, credentialProvider: fn () => 'x'), 'apiKey + provider refused');
$client = new SecretServerClient(apiUrl: $baseURL, credentialProvider: fn () => throw new RuntimeException(TOKEN));
$e = expectFailure(fn () => $client->listDocuments(), 'foreign provider exception');
check($e instanceof AuthException && $e->getMessage() === 'credential provider failed' && noToken($e), 'foreign provider exception masked');
$client = new SecretServerClient(apiUrl: $baseURL, credentialProvider: fn () => "a\r\nX-Injected: 1");
expectFailure(fn () => $client->listDocuments(), 'malformed provider token refused');

echo "PHP CLI credential provider PASS ($passed checks)\n";
