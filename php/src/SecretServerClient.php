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
    private const USER_AGENT  = 'secretserver-php/1.0.0';

    private string $apiKey;
    private string $apiUrl;
    private int    $timeout;
    private bool   $verifySsl;

    /**
     * @param string|null $apiKey    API key (or set SS_API_KEY env var)
     * @param string|null $apiUrl    Base URL (or set SS_API_URL env var)
     * @param int         $timeout   Request timeout in seconds
     * @param bool        $verifySsl Verify TLS certificates
     * @throws AuthException
     */
    public function __construct(
        ?string $apiKey   = null,
        ?string $apiUrl   = null,
        int     $timeout  = 10,
        bool    $verifySsl = true
    ) {
        $this->apiKey    = $apiKey ?? (string) getenv('SS_API_KEY');
        $this->apiUrl    = rtrim($apiUrl ?? (string)(getenv('SS_API_URL') ?: self::DEFAULT_URL), '/');
        $this->timeout   = $timeout;
        $this->verifySsl = $verifySsl;

        if ($this->apiKey === '') {
            throw new AuthException('No API key provided. Pass $apiKey or set SS_API_KEY env var.');
        }
    }

    // -----------------------------------------------------------------------
    // Path-based secret access (primary interface)
    // -----------------------------------------------------------------------

    /**
     * Get a secret value by path: "container/key" or "container/key/2"
     *
     * @throws SecretServerException
     */
    public function secret(string $path): string
    {
        $parts = explode('/', trim($path, '/'));
        if (count($parts) === 1) {
            $data = $this->get('/secrets/' . $parts[0]);
            return (string) ($data['value'] ?? $data['data']['value'] ?? '');
        }
        $data = $this->get('/s/' . implode('/', $parts));
        return (string) ($data['value'] ?? '');
    }

    /**
     * Get full secret metadata + value.
     *
     * @return array<string, mixed>
     */
    public function getSecret(string $path): array
    {
        $parts = explode('/', trim($path, '/'));
        if (count($parts) === 1) {
            return $this->get('/secrets/' . $parts[0]);
        }
        return $this->get('/s/' . implode('/', $parts));
    }

    // -----------------------------------------------------------------------
    // Secrets
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listSecrets(): array { return $this->get('/secrets'); }

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

    /** @return array<string, mixed> */
    public function updateSecret(string $name, string $value): array
    {
        return $this->put('/secrets/' . $name, ['data' => ['value' => $value]]);
    }

    public function deleteSecret(string $name): void { $this->delete('/secrets/' . $name); }

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
    public function listCertificates(): array { return $this->get('/certificates'); }

    /** @return array<string, mixed> */
    public function getCertificate(string $id): array { return $this->get('/certificates/' . $id); }

    /**
     * @param string[] $sans
     * @return array<string, mixed>
     */
    public function enrollCertificate(string $name, string $commonName, array $sans = [], bool $autoRenew = true): array
    {
        return $this->post('/certificates/enroll', [
            'name'        => $name,
            'common_name' => $commonName,
            'sans'        => $sans,
            'auto_renew'  => $autoRenew,
        ]);
    }

    /** @return array<string, mixed> */
    public function renewCertificate(string $id): array { return $this->post('/certificates/' . $id . '/renew'); }

    // -----------------------------------------------------------------------
    // SSH Keys
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listSSHKeys(): array { return $this->get('/ssh-keys'); }

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
    public function exportSSHKey(string $id): array { return $this->get('/ssh-keys/' . $id . '/export'); }

    // -----------------------------------------------------------------------
    // Passwords
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listPasswords(): array { return $this->get('/passwords'); }

    /** @return array<string, mixed> */
    public function createPassword(string $name, string $username, string $password, string $url = ''): array
    {
        $body = ['name' => $name, 'username' => $username, 'password' => $password];
        if ($url) $body['url'] = $url;
        return $this->post('/passwords', $body);
    }

    public function generatePassword(int $length = 32, bool $includeSymbols = true): string
    {
        $data = $this->post('/passwords/generate', ['length' => $length, 'include_symbols' => $includeSymbols]);
        return (string) ($data['password'] ?? '');
    }

    // -----------------------------------------------------------------------
    // API Tokens
    // -----------------------------------------------------------------------

    /** @return array<int, array<string, mixed>> */
    public function listAPITokens(): array { return $this->get('/api-tokens'); }

    /** @return array<string, mixed> */
    public function createAPIToken(string $name, string $service, string $token): array
    {
        return $this->post('/api-tokens', ['name' => $name, 'service' => $service, 'token' => $token]);
    }

    /** @return array<string, mixed> */
    public function rotateAPIToken(string $id): array { return $this->post('/api-tokens/' . $id . '/rotate'); }

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
     * @return array<int, array<string, mixed>>
     */
    public function getHistory(string $secretType, string $secretId): array
    {
        $data = $this->get('/' . $secretType . '/' . $secretId . '/history');
        return $data['versions'] ?? [];
    }

    /** @return array<string, mixed> */
    public function getVersion(string $secretType, string $secretId, int $version): array
    {
        return $this->get('/' . $secretType . '/' . $secretId . '/history/' . $version);
    }

    // -----------------------------------------------------------------------
    // Sharing & temp access
    // -----------------------------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    public function share(
        string  $secretType,
        string  $secretId,
        string  $email,
        string  $permission = 'read',
        ?int    $expiresHours = 72
    ): array {
        $body = ['shared_with_email' => $email, 'permission' => $permission];
        if ($expiresHours !== null) {
            $body['expires_at'] = (new \DateTimeImmutable('+' . $expiresHours . ' hours'))->format(\DateTimeInterface::ATOM);
        }
        return $this->post('/' . $secretType . '/' . $secretId . '/shares', $body);
    }

    /**
     * @return array{token: string, expires_at: string}
     */
    public function createTempAccess(string $secretType, string $secretId, int $durationSeconds = 900): array
    {
        return $this->post('/' . $secretType . '/' . $secretId . '/temp-access', [
            'duration_seconds' => $durationSeconds,
        ]);
    }

    // -----------------------------------------------------------------------
    // Intelligence & transform
    // -----------------------------------------------------------------------

    /** @return array<string, mixed> */
    public function checkBreach(string $value): array
    {
        return $this->post('/intelligence/check-breach', ['value' => $value]);
    }

    public function encode(string $data, string $format = 'base64'): string
    {
        $r = $this->post('/transform/encode', ['data' => $data, 'format' => $format]);
        return (string) ($r['result'] ?? '');
    }

    public function decode(string $data, string $format = 'base64'): string
    {
        $r = $this->post('/transform/decode', ['data' => $data, 'format' => $format]);
        return (string) ($r['result'] ?? '');
    }

    // -----------------------------------------------------------------------
    // HTTP core (internal)
    // -----------------------------------------------------------------------

    /**
     * @return array<string, mixed>
     * @internal
     */
    public function get(string $path): array { return $this->request('GET', $path); }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     * @internal
     */
    public function post(string $path, ?array $body = null): array { return $this->request('POST', $path, $body); }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     * @internal
     */
    public function put(string $path, ?array $body = null): array { return $this->request('PUT', $path, $body); }

    /** @internal */
    public function delete(string $path): void { $this->request('DELETE', $path); }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     * @throws SecretServerException
     */
    private function request(string $method, string $path, ?array $body = null): array
    {
        $url = $this->apiUrl . '/api/v1' . $path;
        $ch  = curl_init($url);

        $headers = [
            'Authorization: Bearer ' . $this->apiKey,
            'Accept: application/json',
            'Content-Type: application/json',
            'User-Agent: ' . self::USER_AGENT,
        ];

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_SSL_VERIFYPEER => $this->verifySsl,
            CURLOPT_SSL_VERIFYHOST => $this->verifySsl ? 2 : 0,
            CURLOPT_CUSTOMREQUEST  => $method,
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
        }

        $raw    = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = curl_error($ch);
        curl_close($ch);

        if ($curlErr !== '') {
            throw new SecretServerException('cURL error: ' . $curlErr);
        }

        $data = [];
        if (is_string($raw) && $raw !== '') {
            try {
                $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                $data = ['raw' => $raw];
            }
        }

        if ($status === 401) throw new AuthException($data['error'] ?? 'Unauthorized', $status);
        if ($status === 403) throw new PermissionException($data['error'] ?? 'Forbidden', $status);
        if ($status === 404) throw new NotFoundException($data['error'] ?? 'Not found', $status);
        if ($status >= 400)  throw new SecretServerException($data['error'] ?? "HTTP $status", $status);

        return $data ?? [];
    }
}

// -----------------------------------------------------------------------
// Credential resource helper
// -----------------------------------------------------------------------

class CredentialResource
{
    public function __construct(
        private SecretServerClient $client,
        private string $resource
    ) {}

    /** @return array<int, array<string, mixed>> */
    public function list(): array { return $this->client->get('/' . $this->resource); }

    /** @return array<string, mixed> */
    public function get(string $id): array { return $this->client->get('/' . $this->resource . '/' . $id); }

    /** @param array<string, mixed> $data
     *  @return array<string, mixed> */
    public function create(array $data): array { return $this->client->post('/' . $this->resource, $data); }

    /** @param array<string, mixed> $data
     *  @return array<string, mixed> */
    public function update(string $id, array $data): array { return $this->client->put('/' . $this->resource . '/' . $id, $data); }

    public function delete(string $id): void { $this->client->delete('/' . $this->resource . '/' . $id); }
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
