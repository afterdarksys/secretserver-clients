<?php
// Live contract test, run by scripts/live-integration.sh against a disposable
// loopback server (SS_LIVE_URL, SS_LIVE_KEY with admin:*, SS_LIVE_WRITE_KEY
// with only secrets:write, SS_LIVE_CONTAINER).
require dirname(__DIR__) . '/src/SecretServerClient.php';

use SecretServer\AuthException;
use SecretServer\ConflictException;
use SecretServer\SecretServerClient;

function ok(bool $condition, string $what): void
{
    if (!$condition) throw new RuntimeException('live check failed: ' . $what);
    echo "ok - $what\n";
}

/** Run $fn and return the ConflictException it throws; fail if it does not. */
function expectConflict(callable $fn, string $what): ConflictException
{
    try {
        $fn();
    } catch (ConflictException $e) {
        return $e;
    }
    throw new RuntimeException('live check failed: expected ConflictException: ' . $what);
}

/** Number of secret.read audit entries recorded for secret $name. */
function secretReadCount(SecretServerClient $c, string $name): int
{
    return count($c->getAuditLogs(['action' => 'secret.read', 'resource' => $name, 'limit' => 1000])['logs'] ?? []);
}

/** True when the JKS integrity digest (SHA-1 over UTF-16BE password, salt, body) matches $password. */
function jksPasswordMatches(string $jks, string $password): bool
{
    $utf16 = implode('', array_map(static fn (string $ch) => "\0" . $ch, str_split($password)));
    return strlen($jks) > 20 && hash_equals(substr($jks, -20), sha1($utf16 . 'Mighty Aphrodite' . substr($jks, 0, -20), true));
}

$key = getenv('SS_LIVE_KEY');
$c = new SecretServerClient($key, getenv('SS_LIVE_URL'));
$writer = new SecretServerClient(getenv('SS_LIVE_WRITE_KEY'), getenv('SS_LIVE_URL'));
$container = getenv('SS_LIVE_CONTAINER');
$E = SecretServerClient::ETAG_KEY;
$sfx = bin2hex(random_bytes(4));
$name = "php-live-$sfx";
$cleanup = [];

try {
    // Wrong key -> auth error that does not echo the key.
    $wrongKey = 'sk_wrong_' . bin2hex(random_bytes(12));
    try {
        (new SecretServerClient($wrongKey, getenv('SS_LIVE_URL')))->listSecrets();
        ok(false, 'wrong API key rejected');
    } catch (AuthException $e) {
        ok(!str_contains($e->getMessage(), $wrongKey) && !str_contains($e->getMessage(), $key), 'wrong API key -> AuthException without key in message');
    }

    // Secrets: create, list, path read, partial update, history.
    $c->createSecret($name, 'first', ['container_id' => $container, 'description' => 'php live', 'tags' => ['php-live']]);
    $cleanup[] = fn () => $c->deleteSecret($name);
    ok(in_array($name, array_column($c->listSecrets(), 'name'), true), 'listSecrets includes created secret');
    ok($c->secret("prod/$name") === 'first', 'path read /s/prod/<name>');

    // Value-only update with the secrets:write-only key: no 403, no pre-read.
    ok($c->secret($name) === 'first', 'read by name (logs secret.read)');
    $readsBefore = secretReadCount($c, $name);
    ok($readsBefore >= 1, "audit filter finds earlier secret.read entries ($readsBefore)");
    $updated = $writer->updateSecret($name, 'second');
    ok(is_string($updated[$E] ?? null) && $updated[$E] !== '', 'updateSecret with secrets:write-only key succeeds and returns an ETag');
    ok(secretReadCount($c, $name) === $readsBefore, 'update produced no secret.read audit entry');
    ok($c->secret($name) === 'second', 'updateSecret changes value');
    ok($c->secret("prod/$name") === 'second', 'path read after update (container preserved)');
    $record = $c->getSecret($name);
    ok(($record['description'] ?? null) === 'php live' && ($record['tags'] ?? null) === ['php-live'] && ($record['container_id'] ?? null) === $container, 'update preserved description, tags and container');

    // Explicit null clears; omitted fields are preserved.
    $c->updateSecret($name, null, ['description' => null]);
    $record = $c->getSecret($name);
    ok(($record['description'] ?? '') === '', 'description cleared via explicit null');
    ok($c->secret($name) === 'second' && ($record['tags'] ?? null) === ['php-live'] && ($record['container_id'] ?? null) === $container, 'omitted value, tags and container preserved');

    // Optimistic concurrency.
    $etag = $record[$E] ?? '';
    ok($etag !== '', 'getSecret returns ETag');
    $fresh = $c->updateSecret($name, null, ['description' => 'etag ok'], $etag);
    ok(($fresh[$E] ?? $etag) !== $etag, 'update with current ETag succeeds and returns a new ETag');
    $conflict = expectConflict(fn () => $c->updateSecret($name, null, ['description' => 'stale'], $etag), 'stale secret ETag');
    ok($conflict->getETag() === $fresh[$E] && $conflict->getCode() === 409 && !str_contains($conflict->getMessage(), $key), 'stale ETag -> ConflictException with current ETag');
    ok(($c->getSecret($name)['description'] ?? null) === 'etag ok', 'conflicting update was not applied');
    $history = $c->getHistory('secret', $record['id']);
    ok(is_array($history) && ($history === [] || array_keys($history) === range(0, count($history) - 1)), 'getHistory returns a list (' . count($history) . ' entries)');

    // Variables (admin:all).
    $c->assignVariable('PHP_LIVE', 'secret', $record['id'], 'value');
    $cleanup[] = fn () => $c->deleteVariable('PHP_LIVE');
    ok($c->render('x=%%PHP_LIVE%%') === 'x=second', 'render');
    $document = $c->resolveDocument(['password' => '%%PHP_LIVE%%', 'count' => 2]);
    ok($document->password === 'second' && $document->count === 2, 'resolveDocument');
    ok($c->getVariable('PHP_LIVE')['secret_id'] === $record['id'], 'getVariable binding');
    $c->listVariables();
    foreach (['{}', '{"0":"%%PHP_LIVE%%"}', '{"empty":{},"list":[],"nested":[{"0":"%%PHP_LIVE%%"}]}'] as $json) {
        $input = json_decode($json, false, 512, JSON_THROW_ON_ERROR);
        $resolved = $c->resolveDocument($input);
        $expected = str_replace('%%PHP_LIVE%%', 'second', $json);
        ok(json_encode($resolved) === json_encode(json_decode($expected)), "resolveDocument keeps shape $json");
    }

    // Passwords.
    $pw = $c->createPassword("php-pw-$sfx", 'alice', 'Correct-Horse-9');
    $cleanup[] = fn () => $c->delete('/passwords/' . $pw['id']);
    ok(isset($pw['id']), 'createPassword (value field)');
    $gen = $c->generatePassword("php-gen-$sfx", 24, false);
    $cleanup[] = fn () => $c->delete('/passwords/' . $gen['id']);
    ok(strlen($gen['value'] ?? '') === 24 && !preg_match('/[^A-Za-z0-9]/', $gen['value']), 'generatePassword persists record and returns value without symbols');

    // API tokens.
    $tok = $c->createAPIToken("php-tok-$sfx", 'github', 'ghp_' . bin2hex(random_bytes(8)), 'development');
    $cleanup[] = fn () => $c->delete('/api-tokens/' . $tok['id']);
    ok(($tok['environment'] ?? null) === 'development', 'createAPIToken with value + environment');
    $newValue = 'ghp_' . bin2hex(random_bytes(8));
    $rot = $c->rotateAPIToken($tok['id'], $newValue);
    ok(($rot['value'] ?? null) === $newValue, 'rotateAPIToken with new value');

    // GPG.
    $gpg = $c->generateGPGKey("php-gpg-$sfx", "php-$sfx@example.test", 'ED25519');
    $cleanup[] = fn () => $c->deleteGPGKey($gpg['id']);
    ok(($c->getGPGKey($gpg['id'])['id'] ?? null) === $gpg['id'], 'generateGPGKey + getGPGKey');
    ok(in_array($gpg['id'], array_column($c->listGPGKeys(), 'id'), true), 'listGPGKeys includes generated key');
    $export = $c->exportGPGKey($gpg['id'], 'public');
    ok(($export['format'] ?? null) === 'public' && str_contains($export['key'] ?? '', 'PGP PUBLIC KEY') && ($export['fingerprint'] ?? '') !== '', 'exportGPGKey(public)');

    // OpenSSL.
    $ossl = $c->generateOpenSSLKey("php-ossl-$sfx", 'ecdsa', 0, 'P-256');
    $cleanup[] = fn () => $c->deleteOpenSSLKey($ossl['id']);
    ok(($ossl['algorithm'] ?? null) === 'ecdsa' && str_contains($ossl['public_key'] ?? '', 'PUBLIC KEY'), 'generateOpenSSLKey ecdsa');

    // TOTP.
    $totp = $c->createTOTPToken("php-totp-$sfx", 'Example', "php-$sfx@example.test", 'JBSWY3DPEHPK3PXP');
    $cleanup[] = fn () => $c->deleteTOTPToken($totp['id']);
    ok(($c->getTOTPToken($totp['id'])['id'] ?? null) === $totp['id'], 'createTOTPToken + getTOTPToken');
    ok(in_array($totp['id'], array_column($c->listTOTPTokens(), 'id'), true), 'listTOTPTokens unwraps envelope');
    ok(str_starts_with($c->exportTOTPToURI($totp['id'])['uri'] ?? '', 'otpauth://'), 'exportTOTPToURI');
    ok(preg_match('/^\d{6}$/', (string) ($c->generateTOTPCode($totp['id'])['code'] ?? '')) === 1, 'generateTOTPCode');

    // JKS: managed keystore, partial update (notes clear, password rotation), ETag conflict.
    $jks = $c->createJKSKeystore("php-jks-$sfx", 'managed', ['password' => 'changeit-1', 'notes' => 'php notes', 'tags' => ['php-live']]);
    $cleanup[] = fn () => $c->deleteJKSKeystore($jks['id']);
    $jksRecord = $c->getJKSKeystore($jks['id']);
    ok(($jksRecord['notes'] ?? null) === 'php notes' && ($jksRecord[$E] ?? '') !== '', 'createJKSKeystore + getJKSKeystore with ETag');
    ok(jksPasswordMatches(base64_decode($c->exportJKSKeystore($jks['id'])['jks'] ?? ''), 'changeit-1'), 'exportJKSKeystore signed with initial password');
    $jksUpdated = $c->updateJKSKeystore($jks['id'], ['notes' => null, 'password' => 'changeit-2'], $jksRecord[$E]);
    $jksAfter = $c->getJKSKeystore($jks['id']);
    ok(($jksAfter['notes'] ?? '') === '' && ($jksAfter['tags'] ?? null) === ['php-live'] && ($jksAfter['name'] ?? null) === "php-jks-$sfx", 'updateJKSKeystore clears notes via null and preserves name/tags');
    $exported = base64_decode($c->exportJKSKeystore($jks['id'])['jks'] ?? '');
    ok(jksPasswordMatches($exported, 'changeit-2') && !jksPasswordMatches($exported, 'changeit-1'), 'updateJKSKeystore rotated the keystore password');
    $conflict = expectConflict(fn () => $c->updateJKSKeystore($jks['id'], ['notes' => 'stale'], $jksRecord[$E]), 'stale JKS ETag');
    ok($conflict->getETag() === ($jksUpdated[$E] ?? null) && $conflict->getETag() === $jksAfter[$E], 'stale JKS ETag -> ConflictException with current ETag');

    // YubiKey: create, partial update (serial_number clear), delete. OTP validation needs Yubico.
    $yk = $c->createYubikey("php-yk-$sfx", 'cccccc' . substr(strtr(bin2hex(random_bytes(3)), '0123456789abcdef', 'cbdefghijklnrtuv'), 0, 6),
        '12345', base64_encode(random_bytes(20)), ['serial_number' => '9876543', 'notes' => 'php yk', 'tags' => ['php-live']]);
    $cleanup[] = fn () => $c->deleteYubikey($yk['id']);
    $ykRecord = $c->getYubikey($yk['id']);
    ok(($ykRecord['serial_number'] ?? null) === '9876543' && ($ykRecord[$E] ?? '') !== '', 'createYubikey + getYubikey with ETag');
    $ykUpdated = $c->updateYubikey($yk['id'], ['serial_number' => null, 'name' => "php-yk2-$sfx"], $ykRecord[$E]);
    $ykAfter = $c->getYubikey($yk['id']);
    ok(($ykAfter['serial_number'] ?? '') === '' && ($ykAfter['name'] ?? null) === "php-yk2-$sfx" && ($ykAfter['notes'] ?? null) === 'php yk' && ($ykAfter['public_id'] ?? null) === $ykRecord['public_id'], 'updateYubikey clears serial_number and preserves omitted fields');
    $conflict = expectConflict(fn () => $c->updateYubikey($yk['id'], ['notes' => 'stale'], $ykRecord[$E]), 'stale YubiKey ETag');
    ok($conflict->getETag() === ($ykUpdated[$E] ?? null), 'stale YubiKey ETag -> ConflictException with current ETag');
    echo "SKIP: validateYubikeyOTP needs the external Yubico validation service\n";

    // Export with include flags; secret items carry their contents.
    $secretsOnly = $c->exportToJSON(false, true, false, false);
    ok(array_diff(array_column($secretsOnly['items'] ?? [], 'type'), ['secret']) === [], 'exportToJSON(secrets only) returns only secrets (' . count($secretsOnly['items'] ?? []) . ' items)');
    $exportedSecret = array_values(array_filter($secretsOnly['items'] ?? [], static fn ($i) => ($i['name'] ?? null) === $name))[0] ?? [];
    ok((json_decode((string) ($exportedSecret['value'] ?? ''), true)['value'] ?? null) === 'second', 'exportToJSON includes the created secret with its value');
    $passwordsOnly = $c->exportToJSON(true, false, false, false);
    $passwordItems = $passwordsOnly['items'] ?? [];
    ok(array_diff(array_column($passwordItems, 'type'), ['password']) === [] && in_array("php-pw-$sfx", array_column($passwordItems, 'name'), true), 'exportToJSON(passwords only) returns the created password and nothing else');

    // Certificates: local self-signed enroll, read/list, raw PEM download, revoke (no delete route).
    $cert = $c->enrollCertificate("php-cert-$sfx", "php-$sfx.example.test", ["www.php-$sfx.example.test"]);
    $cleanup[] = fn () => $c->revokeCertificate($cert['id']);
    ok(($c->getCertificate($cert['id'])['id'] ?? null) === $cert['id'], 'enrollCertificate + getCertificate');
    ok(in_array($cert['id'], array_column($c->listCertificates(), 'id'), true), 'listCertificates includes enrolled certificate');
    ok(str_starts_with($c->downloadCertificate($cert['id']), '-----BEGIN CERTIFICATE-----'), 'downloadCertificate returns raw PEM');

    // Audit export as JSON.
    $audit = $c->exportAuditLogs(['action' => 'secret.update']);
    ok(isset($audit['logs']) && is_array($audit['logs']), 'exportAuditLogs(format=json)');
} finally {
    $cleanupError = null;
    foreach (array_reverse($cleanup) as $undo) {
        try {
            $undo();
        } catch (Throwable $e) {
            $cleanupError ??= $e;
        }
    }
    if ($cleanupError !== null) throw $cleanupError;
}
echo "PHP live contract PASS\n";
