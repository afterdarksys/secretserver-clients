<?php

declare(strict_types=1);

namespace SecretServer;

/**
 * SecretServer.io PHP client library.
 *
 * Requires PHP 8.0+ and the curl extension.
 * Zero Composer dependencies.
 *
 * @example
 * ```php
 * use SecretServer\SecretServerClient;
 *
 * $ss = new SecretServerClient($_ENV['SS_API_KEY']);
 * $value = $ss->secret('production/db-password');
 * echo $value;
 * ```
 */
class SecretServerClient
{
    private const DEFAULT_URL = 'https://api.secretserver.io';
    private const USER_AGENT  = 'secretserver-php/1.3.0';

    /** Maximum body size for JSON responses. */
    private const MAX_JSON_BYTES = 4 * 1024 * 1024;
    /** Maximum body size for raw download responses. */
    private const MAX_RAW_BYTES = 16 * 1024 * 1024;
    /**
     * Key under which getSecret/getJKSKeystore/getYubikey and the update methods
     * return the response ETag (pass it back as $ifMatch).
     */
    public const ETAG_KEY = '_etag';
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '::1', '[::1]'];
    /** Values accepted by the server for the :type path parameter. */
    public const SECRET_TYPES = [
        'secret', 'password', 'ssh_key', 'gpg_key', 'api_token', 'openssl_key', 'ntlm_hash',
        'certificate', 'computer_credential', 'wifi_credential', 'windows_credential',
        'social_credential', 'disk_credential', 'service_config_credential', 'root_credential',
        'ldap_bind_credential', 'integration_credential', 'code_signing_key',
    ];

    private string  $apiKey;
    private string  $apiUrl;
    private int     $timeout;
    private bool    $allowHttp;
    private ?string $caFile;
    private bool    $partialUpdates;

    /**
     * Threats: rejects plaintext transport to non-loopback hosts, credentials
     * embedded in the base URL, disabled TLS verification, redirects and
     * oversized responses. It does NOT protect against a compromised CA the
     * caller chose to trust via $caFile.
     *
     * @param string|null $apiKey    API key (or set SS_API_KEY env var)
     * @param string|null $apiUrl    Base URL (or set SS_API_URL env var). Must be https;
     *                               plain http is accepted only for loopback hosts.
     * @param int         $timeout   Request timeout in seconds
     * @param bool        $verifySsl Kept for signature compatibility; TLS verification
     *                               cannot be disabled and false throws.
     * @param string|null $caFile    PEM bundle used to trust a private CA
     * @param bool        $partialUpdates Opt in to partial updates (updateSecret,
     *                               updateJKSKeystore, updateYubikey) without an ETag.
     *                               Only safe against secretserver.io 3075630 or newer;
     *                               also enabled by SS_PARTIAL_UPDATES=1.
     * @throws AuthException|SecretServerException
     */
    public function __construct(
        ?string $apiKey   = null,
        ?string $apiUrl   = null,
        int     $timeout  = 10,
        bool    $verifySsl = true,
        ?string $caFile   = null,
        bool    $partialUpdates = false
    ) {
        $this->apiKey    = $apiKey ?? (string) getenv('SS_API_KEY');
        $this->apiUrl    = rtrim($apiUrl ?? (string)(getenv('SS_API_URL') ?: self::DEFAULT_URL), '/');
        if (str_ends_with($this->apiUrl, '/api/v1')) {
            $this->apiUrl = substr($this->apiUrl, 0, -7);
        }
        $this->timeout   = $timeout;
        $this->partialUpdates = $partialUpdates || getenv('SS_PARTIAL_UPDATES') === '1';

        if ($this->apiKey === '') {
            throw new AuthException('No API key provided. Pass $apiKey or set SS_API_KEY env var.');
        }
        if (!$verifySsl) {
            throw new SecretServerException('TLS verification cannot be disabled; pass $caFile to trust a private CA');
        }
        if ($caFile !== null && !is_file($caFile)) {
            throw new SecretServerException('CA file does not exist');
        }
        $this->caFile = $caFile;

        $parts  = parse_url($this->apiUrl);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host   = strtolower((string) ($parts['host'] ?? ''));
        if ($parts === false || $host === '' || !in_array($scheme, ['https', 'http'], true)) {
            throw new SecretServerException('Invalid SecretServer base URL');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new SecretServerException('SecretServer base URL must not contain credentials');
        }
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw new SecretServerException('SecretServer base URL must not contain a query or fragment');
        }
        $this->allowHttp = in_array($host, self::LOOPBACK_HOSTS, true);
        if ($scheme === 'http' && !$this->allowHttp) {
            throw new SecretServerException('SecretServer base URL must use https (http is allowed only for loopback hosts)');
        }
    }

    /**
     * Enable or disable partial updates without an ETag. Servers older than
     * secretserver.io 3075630 treat these PUTs as a full replace and blank
     * omitted fields, so enable this only against 3075630 or newer.
     */
    public function setPartialUpdates(bool $enabled): static
    {
        $this->partialUpdates = $enabled;
        return $this;
    }

    /**
     * Refuse a partial update unless the caller opted in or passes an ETag
     * previously received from the server (strong "..." or weak W/"...").
     * An old server ignores If-Match, so a version number, "*" or an
     * unquoted value does not prove partial-update support.
     *
     * @throws SecretServerException
     */
    private function requirePartialUpdates(string|int|null $ifMatch): void
    {
        if ($this->partialUpdates || (is_string($ifMatch) && preg_match('#^(W/)?"[\x21\x23-\x7e]*"$#', $ifMatch) === 1)) {
            return;
        }
        throw new SecretServerException('partial updates require secretserver.io 3075630 or newer; pass an ETag from get() as if_match or enable partial_updates');
    }

    /**
     * Percent-encode one caller-supplied path segment.
     *
     * @internal Used by CredentialResource
     * @throws SecretServerException
     */
    public static function pathSegment(string|int $segment): string
    {
        $segment = (string) $segment;
        if ($segment === '' || $segment === '.' || $segment === '..') {
            throw new SecretServerException('Invalid path segment');
        }
        return rawurlencode($segment);
    }

    private static function secretType(string $type): string
    {
        if (!in_array($type, self::SECRET_TYPES, true)) {
            throw new SecretServerException('Unsupported secret type');
        }
        return $type;
    }

    /** @param array<string, mixed> $params */
    private static function query(array $params): string
    {
        $params = array_filter($params, static fn ($v) => $v !== null);
        $query  = http_build_query($params, '', '&', PHP_QUERY_RFC3986);
        return $query === '' ? '' : '?' . $query;
    }

    /** @return string[] */
    private static function secretPath(string $path): array
    {
        $parts = explode('/', trim($path, '/'));
        if (count($parts) > 3) {
            throw new SecretServerException('Secret path must be name, container/key or container/key/version');
        }
        if (count($parts) === 3 && (!ctype_digit($parts[2]) || (int) $parts[2] < 1 || (int) $parts[2] > 12)) {
            throw new SecretServerException('Secret path version must be between 1 and 12');
        }
        return $parts;
    }

    // -----------------------------------------------------------------------
    // Path-based secret access (primary interface)
    // -----------------------------------------------------------------------

    /**
     * Extract the scalar secret value from a secret payload.
     *
     * @throws SecretServerException
     */
    private function scalar(array $payload): string
    {
        $data = $payload['data'] ?? $payload;
        foreach (['value','password','token','key','passphrase','bind_password','certificate'] as $key) {
            if (isset($data[$key]) && is_string($data[$key])) return $data[$key];
        }
        throw new SecretServerException('Secret response has no supported scalar field');
    }

    /** Bind a named variable to a secret field. Requires the admin:all permission. */
    public function assignVariable(string $name, string $secretType, string $secretId, string $field): array
    { return $this->put('/variables/' . self::pathSegment($name), ['secret_type'=>$secretType, 'secret_id'=>$secretId, 'field'=>$field]); }
    /** Requires the admin:all permission. */
    public function getVariable(string $name): array { return $this->get('/variables/' . self::pathSegment($name)); }
    /** Requires the admin:all permission. */
    public function listVariables(): array { return $this->get('/variables')['variables']; }
    /** Requires the admin:all permission. */
    public function deleteVariable(string $name): void { $this->delete('/variables/' . self::pathSegment($name)); }
    public function render(string $template): string {
        $result = $this->post('/variables/resolve', ['template'=>$template]);
        if (!isset($result['rendered']) || !is_string($result['rendered'])) throw new SecretServerException('Invalid rendered response');
        return $result['rendered'];
    }
    public function resolveDocument(mixed $document): mixed {
        $result = $this->request('POST', '/variables/resolve', ['document'=>$document], true);
        if (!array_key_exists('document', $result)) throw new SecretServerException('Invalid document response');
        return $result['document'];
    }

    /**
     * Get a secret value by path: "name", "container/key" or "container/key/N" (N = 1..12).
     *
     * @throws SecretServerException
     */
    public function secret(string $path): string
    {
        return $this->scalar($this->getSecret($path));
    }

    /**
     * Get full secret metadata + value. A lookup by name also returns the
     * ETag under self::ETAG_KEY for use as updateSecret()'s $ifMatch.
     *
     * @return array<string, mixed>
     */
    public function getSecret(string $path): array
    {
        $parts = self::secretPath($path);
        if (count($parts) === 1) {
            return $this->requestWithETag('GET', '/secrets/' . self::pathSegment($parts[0]));
        }
        return $this->get('/s/' . implode('/', array_map([self::class, 'pathSegment'], $parts)));
    }

    // -----------------------------------------------------------------------
    // Secrets
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listSecrets(): array
    {
        return $this->getList('/secrets', 'secrets');
    }

    /**
     * @param array<string, string> $opts  'description', 'container_id'
     * @return array<string, mixed>
     */
    public function createSecret(string $name, string $value, array $opts = []): array
    {
        return $this->post('/secrets', array_merge([
            'name' => $name,
            'data' => ['value' => $value],
        ], $opts));
    }

    /**
     * Partially update a secret. Minimum server: secretserver.io 3075630
     * (partial, conditional updates). Refused client-side unless the client
     * opted in ($partialUpdates / setPartialUpdates() / SS_PARTIAL_UPDATES=1)
     * or $ifMatch is an ETag from getSecret(). Only what the caller supplies is sent:
     * a null $value keeps the stored value; a key absent from $opts keeps
     * that field; a key present with null clears it (description, tags,
     * container_id). Needs only secrets:write and does not read the value.
     *
     * $ifMatch is an ETag (from getSecret()/updateSecret() under
     * self::ETAG_KEY) or a version number; $opts['expected_version'] is also
     * accepted. On mismatch ConflictException carries the current ETag.
     * The result includes the new ETag under self::ETAG_KEY.
     *
     * @param array<string, mixed> $opts 'description', 'tags', 'container_id', 'expected_version'
     * @return array<string, mixed>
     * @throws ConflictException|SecretServerException
     */
    public function updateSecret(string $name, ?string $value = null, array $opts = [], string|int|null $ifMatch = null): array
    {
        $this->requirePartialUpdates($ifMatch);
        $body = self::patchFields($opts, ['description', 'tags', 'container_id', 'expected_version']);
        if (array_key_exists('expected_version', $body) && !is_int($body['expected_version'])) {
            throw new SecretServerException('expected_version must be an integer');
        }
        if ($value !== null) {
            $body['data'] = ['value' => $value];
        }
        return $this->requestWithETag('PUT', '/secrets/' . self::pathSegment($name), $body, $ifMatch);
    }

    public function deleteSecret(string $name): void { $this->delete('/secrets/' . self::pathSegment($name)); }

    // -----------------------------------------------------------------------
    // Containers
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listContainers(): array { return $this->get('/containers'); }

    /**
     * @return array<string, mixed>
     */
    public function createContainer(string $name, string $slug = '', string $description = ''): array
    {
        $body = ['name' => $name];
        if ($slug)        $body['slug']        = $slug;
        if ($description) $body['description'] = $description;
        return $this->post('/containers', $body);
    }

    // -----------------------------------------------------------------------
    // Certificates
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listCertificates(): array { return $this->getList('/certificates', 'certificates'); }

    /** @return array<string, mixed> */
    public function getCertificate(string $id): array { return $this->get('/certificates/' . self::pathSegment($id)); }

    /**
     * @param string[] $sans
     * @return array<string, mixed>
     */
    public function enrollCertificate(string $name, string $commonName, array $sans = [], bool $autoRenew = true): array
    {
        return $this->post('/certificates/enroll', [
            'name'        => $name,
            'common_name' => $commonName,
            'dns_names'   => $sans,
            'auto_renew'  => $autoRenew,
        ]);
    }

    /** @return array<string, mixed> */
    public function renewCertificate(string $id): array { return $this->post('/certificates/' . self::pathSegment($id) . '/renew'); }

    // -----------------------------------------------------------------------
    // Operation-only cryptographic backends
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listCryptoBackends(): array { return $this->get('/crypto/backends'); }

    /** @return array<int, array<string, mixed>> */
    public function listSigningKeys(string $backend = 'pkcs11'): array
    {
        return $this->get('/crypto/signing-keys?backend=' . self::pathSegment($backend));
    }

    /** @return array<string, mixed> */
    public function sign(string $backend, string $keyId, string $messageBase64, string $purpose): array
    {
        return $this->post('/crypto/sign', [
            'backend' => $backend,
            'key_id' => $keyId,
            'message' => $messageBase64,
            'purpose' => $purpose,
        ]);
    }

    // -----------------------------------------------------------------------
    // JKS keystores
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listJKSKeystores(): array { return $this->get('/jks-keystores'); }

    /** Includes the ETag under self::ETAG_KEY. @return array<string, mixed> */
    public function getJKSKeystore(string $id): array { return $this->requestWithETag('GET', '/jks-keystores/' . self::pathSegment($id)); }

    /** @param array<string, mixed> $options @return array<string, mixed> */
    public function createJKSKeystore(string $name, string $storeType = 'managed', array $options = []): array
    {
        return $this->post('/jks-keystores', array_merge($options, [
            'name' => $name,
            'store_type' => $storeType,
        ]));
    }

    /**
     * Partially update a keystore. Minimum server: secretserver.io 3075630
     * (partial, conditional updates). Refused client-side unless the client
     * opted in ($partialUpdates / setPartialUpdates() / SS_PARTIAL_UPDATES=1)
     * or $ifMatch is an ETag from getJKSKeystore(). A key absent from $data keeps that field; a
     * key present with null clears it (notes, tags, container_id). 'password'
     * alone rotates the stored password; 'jks' (raw keystores) requires 'password'.
     * $ifMatch is an ETag; on mismatch ConflictException carries the current one.
     * The result includes the new ETag under self::ETAG_KEY.
     *
     * @param array<string, mixed> $data 'name', 'notes', 'tags', 'container_id', 'password', 'jks'
     * @return array<string, mixed>
     * @throws ConflictException|SecretServerException
     */
    public function updateJKSKeystore(string $id, array $data, ?string $ifMatch = null): array
    {
        $this->requirePartialUpdates($ifMatch);
        $body = self::patchFields($data, ['name', 'notes', 'tags', 'container_id', 'password', 'jks']);
        if (array_key_exists('jks', $body) && !array_key_exists('password', $body)) {
            throw new SecretServerException('jks requires password');
        }
        return $this->requestWithETag('PUT', '/jks-keystores/' . self::pathSegment($id), $body, $ifMatch);
    }

    public function deleteJKSKeystore(string $id): void { $this->delete('/jks-keystores/' . self::pathSegment($id)); }

    /** @return array<string, mixed> */
    public function exportJKSKeystore(string $id): array
    {
        return $this->get('/jks-keystores/' . self::pathSegment($id) . '/export');
    }

    /** @return array<int, array<string, mixed>> */
    public function listJKSEntries(string $id): array
    {
        return $this->get('/jks-keystores/' . self::pathSegment($id) . '/entries');
    }

    /** @param array<string, mixed> $data @return array<string, mixed> */
    public function createJKSEntry(string $id, array $data): array
    {
        return $this->post('/jks-keystores/' . self::pathSegment($id) . '/entries', $data);
    }

    public function deleteJKSEntry(string $id, string $alias): void
    {
        $this->delete('/jks-keystores/' . self::pathSegment($id) . '/entries/' . self::pathSegment($alias));
    }

    // -----------------------------------------------------------------------
    // Provider credentials and key taxonomy
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listIntegrationProviders(): array { return $this->get('/integration-providers'); }

    /** @return array<int, array<string, mixed>> */
    public function listKeyCatalog(): array { return $this->get('/key-catalog'); }

    /**
     * @param array<string, string> $credentials
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function createIntegrationCredential(string $name, string $provider, array $credentials, array $options = []): array
    {
        return $this->post('/integrations', array_merge($options, [
            'name' => $name, 'provider' => $provider, 'credentials' => $credentials,
        ]));
    }

    /** Get redacted metadata; reveal requires export:read. @return array<string, mixed> */
    public function getIntegrationCredential(string $id, bool $reveal = false): array
    {
        return $this->get('/integrations/' . self::pathSegment($id) . ($reveal ? '?reveal=true' : ''));
    }

    // -----------------------------------------------------------------------
    // SSH Keys
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listSSHKeys(): array { return $this->getList('/ssh-keys', 'ssh_keys', 'keys'); }

    /** @return array<string, mixed> */
    public function generateSSHKey(string $name, string $keyType = 'ed25519', string $comment = ''): array
    {
        return $this->post('/ssh-keys/generate', ['name' => $name, 'key_type' => $keyType, 'comment' => $comment]);
    }

    /** @return array<string, mixed> */
    public function importSSHKey(string $name, string $privateKey): array
    {
        return $this->post('/ssh-keys/import', ['name' => $name, 'private_key' => $privateKey]);
    }

    /** @return array<string, mixed> */
    public function exportSSHKey(string $id): array { return $this->get('/ssh-keys/' . self::pathSegment($id) . '/export'); }

    // -----------------------------------------------------------------------
    // Passwords
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listPasswords(): array { return $this->getList('/passwords', 'passwords'); }

    /** @return array<string, mixed> */
    public function createPassword(string $name, string $username, string $value, string $url = ''): array
    {
        $body = ['name' => $name, 'username' => $username, 'value' => $value];
        if ($url) $body['url'] = $url;
        return $this->post('/passwords', $body);
    }

    /**
     * Generate and PERSIST a password record. The generated secret is in 'value'.
     *
     * @param array<string, mixed> $opts 'description', 'username', 'url', 'tags',
     *                                   'exclude_similar', 'min_uppercase', 'min_digits', 'min_symbols'
     * @return array<string, mixed> PasswordResponse
     */
    public function generatePassword(
        string $name,
        int    $length = 32,
        bool   $useSymbols = true,
        bool   $useLowercase = true,
        bool   $useUppercase = true,
        bool   $useDigits = true,
        array  $opts = []
    ): array {
        if ($length < 8 || $length > 128) {
            throw new SecretServerException('Password length must be between 8 and 128');
        }
        return $this->post('/passwords/generate', array_merge($opts, [
            'name'          => $name,
            'length'        => $length,
            'use_lowercase' => $useLowercase,
            'use_uppercase' => $useUppercase,
            'use_digits'    => $useDigits,
            'use_symbols'   => $useSymbols,
        ]));
    }

    // -----------------------------------------------------------------------
    // API Tokens
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listAPITokens(): array { return $this->getList('/api-tokens', 'tokens'); }

    /**
     * @param string $environment production, staging or development
     * @param array<string, mixed> $opts 'description', 'expires_at' (RFC 3339)
     * @return array<string, mixed>
     */
    public function createAPIToken(string $name, string $service, string $value, string $environment, array $opts = []): array
    {
        if (!in_array($environment, ['production', 'staging', 'development'], true)) {
            throw new SecretServerException('Environment must be production, staging or development');
        }
        return $this->post('/api-tokens', array_merge($opts, [
            'name' => $name, 'service' => $service, 'value' => $value, 'environment' => $environment,
        ]));
    }

    /** Replace a stored token with $newValue. @return array<string, mixed> */
    public function rotateAPIToken(string $id, string $newValue): array
    {
        return $this->post('/api-tokens/' . self::pathSegment($id) . '/rotate', ['value' => $newValue]);
    }

    // -----------------------------------------------------------------------
    // Extended credential type helper
    // -----------------------------------------------------------------------

    /**
     * Generic CRUD accessor for extended credential types.
     * Returns a CredentialResource scoped to the given API path.
     *
     * @example $ss->credentials('computer-credentials')->list()
     */
    public function credentials(string $resource): CredentialResource
    {
        return new CredentialResource($this, $resource);
    }

    // -----------------------------------------------------------------------
    // Version history
    // -----------------------------------------------------------------------

    /**
     * @param string $secretType one of self::SECRET_TYPES
     * @return array<int, array<string, mixed>>
     */
    public function getHistory(string $secretType, string $secretId): array
    {
        $data = $this->get('/' . self::secretType($secretType) . '/' . self::pathSegment($secretId) . '/history');
        if ($data !== [] && array_keys($data) !== range(0, count($data) - 1)) {
            throw new SecretServerException('Invalid server response');
        }
        return $data;
    }

    /** @return array<string, mixed> */
    public function getVersion(string $secretType, string $secretId, int $version): array
    {
        return $this->get('/' . self::secretType($secretType) . '/' . self::pathSegment($secretId) . '/history/' . self::pathSegment($version));
    }

    // -----------------------------------------------------------------------
    // Sharing & temp access
    // -----------------------------------------------------------------------

    /**
     * Share with exactly one user or group (UUIDs).
     *
     * @param string $permission read or manage
     * @return array<string, mixed>
     */
    public function share(
        string  $secretType,
        string  $secretId,
        ?string $userId = null,
        ?string $groupId = null,
        string  $permission = 'read',
        ?int    $expiresHours = 72
    ): array {
        if (($userId === null || $userId === '') === ($groupId === null || $groupId === '')) {
            throw new SecretServerException('Specify exactly one of userId or groupId');
        }
        if (!in_array($permission, ['read', 'manage'], true)) {
            throw new SecretServerException('Permission must be read or manage');
        }
        $body = ['permission' => $permission];
        if ($userId !== null && $userId !== '') {
            $body['shared_with_user_id'] = $userId;
        } else {
            $body['shared_with_group_id'] = $groupId;
        }
        if ($expiresHours !== null) {
            $body['expires_at'] = (new \DateTimeImmutable('+' . $expiresHours . ' hours'))->format(\DateTimeInterface::ATOM);
        }
        return $this->post('/' . self::secretType($secretType) . '/' . self::pathSegment($secretId) . '/shares', $body);
    }

    /**
     * @return array{token: string, expires_at: string}
     */
    public function createTempAccess(string $secretType, string $secretId, int $durationSeconds = 900): array
    {
        if ($durationSeconds < 60 || $durationSeconds > 86400) {
            throw new SecretServerException('Temp access duration must be between 60 and 86400 seconds');
        }
        return $this->post('/' . self::secretType($secretType) . '/' . self::pathSegment($secretId) . '/temp-access', [
            'duration_seconds' => $durationSeconds,
        ]);
    }

    // -----------------------------------------------------------------------
    // Intelligence & transform
    // -----------------------------------------------------------------------

    /** @return array<string, mixed> */
    public function checkBreach(string $value): array
    {
        return $this->post('/intelligence/check-breach', ['password' => $value]);
    }

    public function encode(string $data, string $format = 'base64'): string
    {
        $r = $this->post('/transform/encode', ['input' => $data, 'target_type' => $format]);
        return (string) ($r['result'] ?? '');
    }

    /**
     * Decode $data. Returns a string for base64; for jwt (claims) and json the
     * decoded structure is returned as-is.
     */
    public function decode(string $data, string $format = 'base64'): mixed
    {
        $r = $this->post('/transform/decode', ['input' => $data, 'source_type' => $format]);
        if (!array_key_exists('result', $r)) {
            throw new SecretServerException('Invalid server response');
        }
        return $r['result'];
    }

    // -----------------------------------------------------------------------
    // GPG Keys
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listGPGKeys(): array { return $this->getList('/gpg-keys', 'keys'); }

    /** @return array<string, mixed> */
    public function getGPGKey(string $id): array { return $this->get('/gpg-keys/' . self::pathSegment($id)); }

    /**
     * @param string $algorithm RSA2048, RSA4096 or ED25519
     * @param array<string, mixed> $opts 'comment', 'passphrase'
     * @return array<string, mixed>
     */
    public function generateGPGKey(string $name, string $email, string $algorithm = 'ED25519', array $opts = []): array
    {
        if (!in_array($algorithm, ['RSA2048', 'RSA4096', 'ED25519'], true)) {
            throw new SecretServerException('GPG algorithm must be RSA2048, RSA4096 or ED25519');
        }
        return $this->post('/gpg-keys/generate', array_merge($opts, [
            'name' => $name,
            'email' => $email,
            'algorithm' => $algorithm,
        ]));
    }

    /** @return array<string, mixed> */
    public function importGPGKey(string $armoredKey, ?string $passphrase = null, ?string $name = null): array
    {
        $body = ['armored_key' => $armoredKey];
        if ($passphrase !== null) $body['passphrase'] = $passphrase;
        if ($name !== null)       $body['name']       = $name;
        return $this->post('/gpg-keys/import', $body);
    }

    /**
     * @param string $format public or private
     * @return array{key: string, format: string, fingerprint: string, key_id: string}
     */
    public function exportGPGKey(string $id, string $format = 'public'): array
    {
        if (!in_array($format, ['public', 'private'], true)) {
            throw new SecretServerException('GPG export format must be public or private');
        }
        return $this->get('/gpg-keys/' . self::pathSegment($id) . '/export' . self::query(['format' => $format]));
    }

    public function deleteGPGKey(string $id): void { $this->delete('/gpg-keys/' . self::pathSegment($id)); }

    // -----------------------------------------------------------------------
    // OpenSSL Keys
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listOpenSSLKeys(): array { return $this->getList('/openssl-keys', 'openssl_keys', 'keys'); }

    /** @return array<string, mixed> */
    public function getOpenSSLKey(string $id): array { return $this->get('/openssl-keys/' . self::pathSegment($id)); }

    /**
     * @param string $algorithm rsa, ecdsa or ed25519
     * @param int    $keySize   RSA key size (2048..8192); ignored for ecdsa/ed25519
     * @param string|null $curve ECDSA curve (P-256, P-384, P-521)
     * @return array<string, mixed>
     */
    public function generateOpenSSLKey(string $name, string $algorithm = 'rsa', int $keySize = 4096, ?string $curve = null): array
    {
        if (!in_array($algorithm, ['rsa', 'ecdsa', 'ed25519'], true)) {
            throw new SecretServerException('OpenSSL algorithm must be rsa, ecdsa or ed25519');
        }
        $body = ['name' => $name, 'algorithm' => $algorithm];
        if ($algorithm === 'rsa') $body['key_size'] = $keySize;
        if ($curve !== null)      $body['curve']    = $curve;
        return $this->post('/openssl-keys/generate', $body);
    }

    /**
     * @param array<string, mixed> $opts 'description', 'key_size', 'curve', 'public_key', 'passphrase', 'format'
     * @return array<string, mixed>
     */
    public function importOpenSSLKey(string $name, string $algorithm, string $privateKey, array $opts = []): array
    {
        return $this->post('/openssl-keys/import', array_merge($opts, [
            'name' => $name,
            'algorithm' => $algorithm,
            'private_key' => $privateKey,
        ]));
    }

    /** @return array<string, mixed> */
    public function exportOpenSSLKey(string $id): array { return $this->get('/openssl-keys/' . self::pathSegment($id) . '/export'); }

    public function deleteOpenSSLKey(string $id): void { $this->delete('/openssl-keys/' . self::pathSegment($id)); }

    // -----------------------------------------------------------------------
    // NTLM Hashes
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listNTLMHashes(): array { return $this->getList('/ntlm', 'ntlm_hashes', 'hashes'); }

    /** @return array<string, mixed> */
    public function getNTLMHash(string $id): array { return $this->get('/ntlm/' . self::pathSegment($id)); }

    /** @return array<string, mixed> */
    public function createNTLMHash(string $name, string $username, string $hash): array
    {
        return $this->post('/ntlm', ['name' => $name, 'username' => $username, 'hash' => $hash]);
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    public function updateNTLMHash(string $id, array $data): array
    {
        return $this->put('/ntlm/' . self::pathSegment($id), $data);
    }

    public function deleteNTLMHash(string $id): void { $this->delete('/ntlm/' . self::pathSegment($id)); }

    // -----------------------------------------------------------------------
    // Certificates (extended operations)
    // -----------------------------------------------------------------------

    /** @return array<string, mixed> */
    public function revokeCertificate(string $id): array { return $this->post('/certificates/' . self::pathSegment($id) . '/revoke'); }

    /**
     * Download certificate material as raw bytes (not JSON).
     *
     * @param string      $format   pem, pem-bundle, key, pfx or p12
     * @param string|null $password required for pfx/p12
     */
    public function downloadCertificate(string $id, string $format = 'pem', ?string $password = null): string
    {
        if (!in_array($format, ['pem', 'pem-bundle', 'key', 'pfx', 'p12'], true)) {
            throw new SecretServerException('Certificate format must be pem, pem-bundle, key, pfx or p12');
        }
        $path = '/certificates/' . self::pathSegment($id) . '/download';
        if (in_array($format, ['pfx', 'p12'], true)) {
            if ($password === null || $password === '' || strlen($password) > 1024) {
                throw new SecretServerException('A 1-1024 byte password is required for pfx/p12 downloads');
            }
            // POST keeps the export password out of URLs and access logs.
            return $this->send('POST', $path, ['format' => $format, 'password' => $password], self::MAX_RAW_BYTES, '*/*');
        }
        if ($password !== null) {
            throw new SecretServerException('A password is only used with pfx/p12 downloads');
        }
        return $this->requestRaw('GET', $path . self::query(['format' => $format]));
    }

    // -----------------------------------------------------------------------
    // Webhooks
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listWebhooks(): array { return $this->getList('/webhooks', 'webhooks'); }

    /**
     * @param string[] $events
     * @return array<string, mixed>
     */
    public function createWebhook(string $name, string $url, array $events, string $secret = ''): array
    {
        $body = ['name' => $name, 'url' => $url, 'events' => $events];
        if ($secret !== '') $body['secret'] = $secret;
        return $this->post('/webhooks', $body);
    }

    /** @return array<int, array<string, mixed>> */
    public function getWebhookDeliveries(string $webhookId): array
    {
        return $this->getList('/webhooks/' . self::pathSegment($webhookId) . '/deliveries', 'deliveries');
    }

    /** @return array<string, mixed> */
    public function testWebhook(string $webhookId): array { return $this->post('/webhooks/' . self::pathSegment($webhookId) . '/test'); }

    // -----------------------------------------------------------------------
    // Export
    // -----------------------------------------------------------------------

    /**
     * Export tenant-wide credentials in macOS Keychain format.
     *
     * @param string[] $tags optional tag filter
     * @return array<string, mixed>
     */
    public function exportToKeychain(
        bool  $includePasswords = true,
        bool  $includeSecrets = true,
        bool  $includeSSHKeys = true,
        bool  $includeCertificates = true,
        array $tags = []
    ): array {
        return $this->post('/export/keychain', self::exportBody($includePasswords, $includeSecrets, $includeSSHKeys, $includeCertificates, $tags));
    }

    /**
     * Export tenant-wide credentials in Windows Credential Manager format.
     *
     * @param string[] $tags optional tag filter
     * @return array<string, mixed>
     */
    public function exportToCredentialManager(
        bool  $includePasswords = true,
        bool  $includeSecrets = true,
        bool  $includeSSHKeys = true,
        bool  $includeCertificates = true,
        array $tags = []
    ): array {
        return $this->post('/export/credential-manager', self::exportBody($includePasswords, $includeSecrets, $includeSSHKeys, $includeCertificates, $tags));
    }

    /**
     * Export tenant-wide credentials as JSON.
     *
     * @param string[] $tags optional tag filter
     * @return array<string, mixed>
     */
    public function exportToJSON(
        bool  $includePasswords = true,
        bool  $includeSecrets = true,
        bool  $includeSSHKeys = true,
        bool  $includeCertificates = true,
        array $tags = []
    ): array {
        return $this->post('/export/json', self::exportBody($includePasswords, $includeSecrets, $includeSSHKeys, $includeCertificates, $tags));
    }

    /**
     * @param string[] $tags
     * @return array<string, mixed>
     */
    private static function exportBody(bool $passwords, bool $secrets, bool $sshKeys, bool $certificates, array $tags): array
    {
        $body = [
            'include_passwords'    => $passwords,
            'include_secrets'      => $secrets,
            'include_ssh_keys'     => $sshKeys,
            'include_certificates' => $certificates,
        ];
        if ($tags !== []) $body['tags'] = array_values($tags);
        return $body;
    }

    // -----------------------------------------------------------------------
    // Audit logs
    // -----------------------------------------------------------------------

    /**
     * @param array<string, mixed> $opts 'limit', 'offset', 'action'
     * @return array<string, mixed>
     */
    public function getAuditLogs(array $opts = []): array
    {
        return $this->get('/audit/logs' . self::query($opts));
    }

    /**
     * Export audit logs as JSON ({logs, total, exported_at}).
     *
     * @param array<string, mixed> $filters 'action', 'resource', 'resource_id', 'user_id', 'start_date', 'end_date'
     * @return array<string, mixed>
     */
    public function exportAuditLogs(array $filters = []): array
    {
        return $this->get('/audit/logs/export' . self::query(array_merge($filters, ['format' => 'json'])));
    }

    // -----------------------------------------------------------------------
    // TOTP Authenticators
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // YubiKey OTP Credentials
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listYubikeys(): array { return $this->get('/yubikeys'); }

    /** Includes the ETag under self::ETAG_KEY. @return array<string, mixed> */
    public function getYubikey(string $id): array { return $this->requestWithETag('GET', '/yubikeys/' . self::pathSegment($id)); }

    /**
     * @param array<string, mixed> $opts 'serial_number', 'validation_server', 'notes', 'tags'
     * @return array<string, mixed>
     */
    public function createYubikey(string $name, string $publicId, string $clientId, string $apiKey, array $opts = []): array
    {
        return $this->post('/yubikeys', array_merge([
            'name'      => $name,
            'public_id' => $publicId,
            'client_id' => $clientId,
            'api_key'   => $apiKey,
        ], $opts));
    }

    /**
     * Partially update a YubiKey. Minimum server: secretserver.io 3075630
     * (partial, conditional updates). Refused client-side unless the client
     * opted in ($partialUpdates / setPartialUpdates() / SS_PARTIAL_UPDATES=1)
     * or $ifMatch is an ETag from getYubikey(). A key absent from $data keeps that field; a
     * key present with null clears it (notes, tags, container_id,
     * serial_number). 'api_key' replaces the stored key; 'public_id' must be
     * 12 characters. $ifMatch is an ETag; on mismatch ConflictException
     * carries the current one. The result includes the new ETag under self::ETAG_KEY.
     *
     * @param array<string, mixed> $data 'name', 'notes', 'tags', 'container_id', 'serial_number',
     *                                   'public_id', 'client_id', 'api_key', 'validation_server'
     * @return array<string, mixed>
     * @throws ConflictException|SecretServerException
     */
    public function updateYubikey(string $id, array $data, ?string $ifMatch = null): array
    {
        $this->requirePartialUpdates($ifMatch);
        $body = self::patchFields($data, [
            'name', 'notes', 'tags', 'container_id', 'serial_number', 'public_id', 'client_id', 'api_key', 'validation_server',
        ]);
        if (array_key_exists('public_id', $body) && (!is_string($body['public_id']) || strlen($body['public_id']) !== 12)) {
            throw new SecretServerException('public_id must be exactly 12 characters');
        }
        return $this->requestWithETag('PUT', '/yubikeys/' . self::pathSegment($id), $body, $ifMatch);
    }

    public function deleteYubikey(string $id): void { $this->delete('/yubikeys/' . self::pathSegment($id)); }

    /**
     * Validate a Yubico OTP against the stored YubiKey configuration.
     *
     * @return array{valid: bool, public_id: string, checked_at: string}
     */
    public function validateYubikeyOTP(string $id, string $otp): array
    {
        return $this->post('/yubikeys/' . self::pathSegment($id) . '/validate', ['otp' => $otp]);
    }

    /**
     * List all TOTP authenticator tokens.
     *
     * @return array<int, array<string, mixed>>
     */
    public function listTOTPTokens(): array { return $this->getList('/totp-tokens', 'tokens'); }

    /**
     * Get a specific TOTP token by ID.
     *
     * @return array<string, mixed>
     */
    public function getTOTPToken(string $id): array { return $this->get('/totp-tokens/' . self::pathSegment($id)); }

    /**
     * Create a new TOTP token.
     *
     * @param string $name         Display name for the token
     * @param string $issuer       Issuer name (e.g., "GitHub", "AWS")
     * @param string $accountName  Account identifier (e.g., email or username)
     * @param string $secretKey    Base32-encoded secret key
     * @param string $algorithm    Hash algorithm (SHA1, SHA256, SHA512)
     * @param int    $digits       Number of digits in the code (6 or 8)
     * @param int    $period       Time period in seconds (default 30)
     * @return array<string, mixed>
     */
    public function createTOTPToken(
        string $name,
        string $issuer,
        string $accountName,
        string $secretKey,
        string $algorithm = 'SHA1',
        int    $digits = 6,
        int    $period = 30
    ): array {
        return $this->post('/totp-tokens', [
            'name' => $name,
            'issuer' => $issuer,
            'account_name' => $accountName,
            'secret_key' => $secretKey,
            'algorithm' => $algorithm,
            'digits' => $digits,
            'period' => $period,
        ]);
    }

    /**
     * Update a TOTP token.
     *
     * @param string $id
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    public function updateTOTPToken(string $id, array $data): array
    {
        return $this->put('/totp-tokens/' . self::pathSegment($id), $data);
    }

    /**
     * Delete a TOTP token.
     */
    public function deleteTOTPToken(string $id): void { $this->delete('/totp-tokens/' . self::pathSegment($id)); }

    /**
     * Generate a TOTP code for the given token.
     *
     * Returns array with 'code' and 'expires_in' (seconds remaining).
     *
     * @return array{code: string, expires_in: int}
     */
    public function generateTOTPCode(string $id): array
    {
        return $this->post('/totp-tokens/' . self::pathSegment($id) . '/generate');
    }

    /**
     * Import a TOTP token from an otpauth:// URI.
     *
     * @param string $uri otpauth://totp/... URI string
     * @return array<string, mixed> The created TOTP token
     */
    public function importTOTPFromURI(string $uri): array
    {
        return $this->post('/totp-tokens/import', ['uri' => $uri]);
    }

    /**
     * Export a TOTP token to an otpauth:// URI.
     *
     * @return array{uri: string}
     */
    public function exportTOTPToURI(string $id): array
    {
        return $this->get('/totp-tokens/' . self::pathSegment($id) . '/export');
    }

    // -----------------------------------------------------------------------
    // HTTP core (internal)
    // -----------------------------------------------------------------------

    /**
     * @return array<string, mixed>
     * @internal Used by CredentialResource
     */
    public function get(string $path): array { return $this->request('GET', $path); }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     * @internal Used by CredentialResource
     */
    public function post(string $path, ?array $body = null): array { return $this->request('POST', $path, $body); }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     * @internal Used by CredentialResource
     */
    public function put(string $path, ?array $body = null): array { return $this->request('PUT', $path, $body); }

    /** @internal Used by CredentialResource */
    public function delete(string $path): void { $this->request('DELETE', $path); }

    /**
     * Build a partial-update body: keys absent from $fields are omitted, keys
     * present (including with null, which clears) are sent as given.
     *
     * @param array<string, mixed> $fields
     * @param string[] $allowed
     * @return array<string, mixed>
     * @throws SecretServerException on an unsupported field
     */
    private static function patchFields(array $fields, array $allowed): array
    {
        $unknown = array_diff(array_keys($fields), $allowed);
        if ($unknown !== []) {
            throw new SecretServerException('Unsupported update field: ' . implode(', ', $unknown));
        }
        return $fields;
    }

    /** @return array<int, mixed> */
    private function getList(string $path, string ...$envelopeKeys): array
    {
        $data = $this->get($path);
        if ($data === [] || array_keys($data) === range(0, count($data) - 1)) {
            return $data;
        }
        foreach ($envelopeKeys as $key) {
            if (isset($data[$key]) && is_array($data[$key])) {
                return $data[$key];
            }
        }
        return [];
    }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     * @throws SecretServerException
     */
    public function request(string $method, string $path, ?array $body = null, bool $preserveObjects = false): array
    {
        return $this->decodeJson($this->send($method, $path, $body, self::MAX_JSON_BYTES, 'application/json'), $preserveObjects);
    }

    /**
     * Perform a JSON request and add the response ETag under the ETAG_KEY key
     * (when the server sent one). $ifMatch is sent as the If-Match header.
     *
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     * @throws SecretServerException|ConflictException
     */
    private function requestWithETag(string $method, string $path, ?array $body = null, string|int|null $ifMatch = null): array
    {
        $headers = [];
        if ($ifMatch !== null) {
            $ifMatch = (string) $ifMatch;
            if ($ifMatch === '' || strlen($ifMatch) > 1024 || preg_match('/[^\x20-\x7e]/', $ifMatch)) {
                throw new SecretServerException('Invalid If-Match value');
            }
            $headers[] = 'If-Match: ' . $ifMatch;
        }
        $etag = null;
        $data = $this->decodeJson($this->send($method, $path, $body, self::MAX_JSON_BYTES, 'application/json', $headers, $etag), false);
        if ($etag !== null) {
            $data[self::ETAG_KEY] = $etag;
        }
        return $data;
    }

    /**
     * @return array<string, mixed>
     * @throws SecretServerException
     */
    private function decodeJson(string $raw, bool $preserveObjects): array
    {
        if ($raw === '') {
            return [];
        }
        try {
            $data = json_decode($raw, !$preserveObjects, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new SecretServerException('Invalid server response');
        }
        if ($preserveObjects && is_object($data)) $data = get_object_vars($data);
        if (!is_array($data)) {
            throw new SecretServerException('Invalid server response');
        }
        return $data;
    }

    /**
     * Perform a request and return the raw response body (up to 16 MiB).
     *
     * @throws SecretServerException
     */
    private function requestRaw(string $method, string $path): string
    {
        return $this->send($method, $path, null, self::MAX_RAW_BYTES, '*/*');
    }

    /**
     * @param array<string, mixed>|null $body
     * @throws SecretServerException
     */
    private function send(string $method, string $path, ?array $body, int $maxBytes, string $accept, array $extraHeaders = [], ?string &$etag = null): string
    {
        $path = '/' . ltrim($path, '/');
        if ($path === '/api/v1') {
            $path = '';
        } elseif (str_starts_with($path, '/api/v1/')) {
            $path = substr($path, 7);
        }
        $url = $this->apiUrl . '/api/v1' . $path;
        $ch  = curl_init($url);

        $headers = [
            'Authorization: Bearer ' . $this->apiKey,
            'Accept: ' . $accept,
            'Content-Type: application/json',
            'User-Agent: ' . self::USER_AGENT,
            ...$extraHeaders,
        ];

        $protocols = CURLPROTO_HTTPS | ($this->allowHttp ? CURLPROTO_HTTP : 0);
        $buffer    = '';
        $tooLarge  = false;
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER      => $headers,
            CURLOPT_TIMEOUT         => $this->timeout,
            CURLOPT_CONNECTTIMEOUT  => min($this->timeout, 10),
            CURLOPT_SSL_VERIFYPEER  => true,
            CURLOPT_SSL_VERIFYHOST  => 2,
            CURLOPT_SSLVERSION      => CURL_SSLVERSION_TLSv1_2,
            CURLOPT_PROTOCOLS       => $protocols,
            CURLOPT_REDIR_PROTOCOLS => $protocols,
            CURLOPT_FOLLOWLOCATION  => false,
            CURLOPT_CUSTOMREQUEST   => $method,
            CURLOPT_MAXFILESIZE     => $maxBytes,
            CURLOPT_WRITEFUNCTION   => static function ($handle, string $chunk) use (&$buffer, &$tooLarge, $maxBytes): int {
                if (strlen($buffer) + strlen($chunk) > $maxBytes) {
                    $tooLarge = true;
                    return 0;
                }
                $buffer .= $chunk;
                return strlen($chunk);
            },
            CURLOPT_HEADERFUNCTION  => static function ($handle, string $line) use (&$etag): int {
                if (str_starts_with($line, 'HTTP/')) {
                    $etag = null;
                } elseif (stripos($line, 'etag:') === 0) {
                    $etag = trim(substr($line, 5));
                }
                return strlen($line);
            },
        ]);
        if ($this->caFile !== null) {
            curl_setopt($ch, CURLOPT_CAINFO, $this->caFile);
        }

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body === [] ? '{}' : json_encode($body, JSON_THROW_ON_ERROR));
        }

        $ok      = curl_exec($ch);
        $status  = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errno   = curl_errno($ch);

        if ($tooLarge || $errno === CURLE_FILESIZE_EXCEEDED) {
            throw new SecretServerException('SecretServer response exceeded size limit', $status);
        }
        if ($ok === false || $errno !== 0) {
            throw new SecretServerException('SecretServer connection failed');
        }

        $message = "SecretServer request failed (HTTP $status)";
        if ($status === 401) throw new AuthException($message, $status);
        if ($status === 403) throw new PermissionException($message, $status);
        if ($status === 404) throw new NotFoundException($message, $status);
        if ($status === 409) throw new ConflictException($message, $status, $etag);
        if ($status < 200 || $status >= 300) throw new SecretServerException($message, $status);

        return $buffer;
    }
}

// -----------------------------------------------------------------------
// Credential resource helper
// -----------------------------------------------------------------------

class CredentialResource
{
    private string $resource;

    public function __construct(
        private SecretServerClient $client,
        string $resource
    ) {
        $this->resource = SecretServerClient::pathSegment($resource);
    }

    /** @return array<int, array<string, mixed>> */
    public function list(): array { return $this->client->get('/' . $this->resource); }

    /** @return array<string, mixed> */
    public function get(string $id): array { return $this->client->get('/' . $this->resource . '/' . SecretServerClient::pathSegment($id)); }

    /** @param array<string, mixed> $data
     *  @return array<string, mixed> */
    public function create(array $data): array { return $this->client->post('/' . $this->resource, $data); }

    /** @param array<string, mixed> $data
     *  @return array<string, mixed> */
    public function update(string $id, array $data): array { return $this->client->put('/' . $this->resource . '/' . SecretServerClient::pathSegment($id), $data); }

    public function delete(string $id): void { $this->client->delete('/' . $this->resource . '/' . SecretServerClient::pathSegment($id)); }
}

// -----------------------------------------------------------------------
// Exceptions
// -----------------------------------------------------------------------

class SecretServerException extends \RuntimeException
{
    public function __construct(string $message, int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}

class AuthException extends SecretServerException {}
class PermissionException extends SecretServerException {}
class NotFoundException extends SecretServerException {}

/**
 * HTTP 409: the resource changed since the caller read it (If-Match or
 * expected_version mismatch). getETag() is the current ETag from the
 * response header; re-read the resource and retry with it.
 */
class ConflictException extends SecretServerException
{
    private ?string $etag;

    public function __construct(string $message, int $code = 409, ?string $etag = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->etag = $etag;
    }

    public function getETag(): ?string { return $this->etag; }
}
