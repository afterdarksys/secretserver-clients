<?php

declare(strict_types=1);

namespace SecretServer;

// The exception classes live in SecretServerClient.php.
require_once __DIR__ . '/SecretServerClient.php';

/**
 * Credential provider that reuses the `ss login` SSO session.
 *
 * Runs `ss auth print-access-token --format json` ($cliPath, else env
 * SS_CLI_PATH, else `ss` on PATH) and caches the access token in memory until
 * 60 s before it expires. Exit status 2 from the CLI throws AuthException
 * asking the user to run `ss login`; every other failure throws
 * SecretServerException.
 *
 * ```php
 * $ss = new SecretServerClient(credentialProvider: new CliCredentialProvider());
 * ```
 *
 * Threats: the CLI is started from an argv array (proc_open, no shell) with a
 * 30 s timeout and a 64 KiB stdout cap; malformed answers fail closed; the
 * token and the CLI's stdout never appear in exceptions. It does NOT protect
 * against a malicious `ss` binary on PATH or in SS_CLI_PATH, or against other
 * code running as the same OS user.
 */
final class CliCredentialProvider
{
    private const MAX_OUTPUT = 65536;
    private const MAX_STDERR = 4096;
    private const REFRESH_SKEW = 60;
    private const RFC3339 = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i';

    private ?string $token = null;
    private int $expiresAt = 0;
    private ?string $apiUrl = null;

    /**
     * @param string|null $cliPath The `ss` executable (default: SS_CLI_PATH, else `ss` on PATH)
     * @param float       $timeout Limit for one CLI run in seconds
     */
    public function __construct(private ?string $cliPath = null, private float $timeout = 30.0)
    {
        if (!($timeout > 0)) {
            throw new \InvalidArgumentException('timeout must be positive');
        }
    }

    /** @throws SecretServerException */
    public function __invoke(): string
    {
        return $this->current()[0];
    }

    /**
     * The API URL the CLI is logged in to (runs the CLI if nothing is cached).
     *
     * @throws SecretServerException
     */
    public function apiUrl(): ?string
    {
        return $this->current()[1];
    }

    public function __debugInfo(): array
    {
        return ['credentials' => '[redacted]'];
    }

    public function __serialize(): array
    {
        throw new \LogicException('credential providers cannot be serialized');
    }

    /** @return array{0: string, 1: ?string} */
    private function current(): array
    {
        if ($this->token !== null && time() < $this->expiresAt - self::REFRESH_SKEW) {
            return [$this->token, $this->apiUrl];
        }
        $this->token = null;
        [$token, $expiresAt, $apiUrl] = $this->run();
        $this->token = $token;
        $this->expiresAt = $expiresAt;
        $this->apiUrl = $apiUrl;
        return [$token, $apiUrl];
    }

    /** @return array{0: string, 1: int, 2: ?string} */
    private function run(): array
    {
        $path = $this->cliPath ?? (getenv('SS_CLI_PATH') ?: 'ss');
        $exe = self::resolve($path);
        if ($exe === null) {
            throw new SecretServerException(sprintf('SecretServer CLI "%s" not found: install `ss` or set SS_CLI_PATH', $path));
        }
        $proc = proc_open([$exe, 'auth', 'print-access-token', '--format', 'json'], [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);
        if (!is_resource($proc)) {
            throw new SecretServerException(sprintf('SecretServer CLI "%s" could not be run', $path));
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $stdout = '';
        $stderr = '';
        $overflow = false;
        $timedOut = false;
        $deadline = microtime(true) + $this->timeout;
        $open = [1 => $pipes[1], 2 => $pipes[2]];
        while ($open !== []) {
            $left = $deadline - microtime(true);
            if ($left <= 0) {
                $timedOut = true;
                break;
            }
            $read = array_values($open);
            $write = $except = null;
            $ready = stream_select($read, $write, $except, (int) $left, (int) (($left - floor($left)) * 1e6));
            if ($ready === false) {
                break;
            }
            foreach ($open as $fd => $stream) {
                $chunk = fread($stream, 65536);
                if ($chunk === false || ($chunk === '' && feof($stream))) {
                    unset($open[$fd]);
                    continue;
                }
                if ($fd === 1) {
                    if (strlen($stdout) + strlen($chunk) > self::MAX_OUTPUT) {
                        $overflow = true;
                        break 2;
                    }
                    $stdout .= $chunk;
                } else {
                    $stderr .= substr($chunk, 0, max(0, self::MAX_STDERR - strlen($stderr)));
                }
            }
        }

        $exitCode = -1;
        if ($overflow || $timedOut || $open !== []) {
            proc_terminate($proc, 9);
        } else {
            while (($status = proc_get_status($proc))['running']) {
                if (microtime(true) >= $deadline) {
                    $timedOut = true;
                    proc_terminate($proc, 9);
                    break;
                }
                usleep(10000);
            }
            if (!$timedOut) {
                $exitCode = $status['signaled'] ? -1 : $status['exitcode'];
            }
        }
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);

        if ($overflow) {
            throw new SecretServerException('`ss auth print-access-token` output exceeds ' . self::MAX_OUTPUT . ' bytes');
        }
        if ($timedOut) {
            throw new SecretServerException(sprintf('`ss auth print-access-token` timed out after %s s', $this->timeout));
        }
        if ($exitCode === 2) {
            throw new AuthException('SecretServer CLI is not logged in: run `ss login`');
        }
        if ($exitCode !== 0) {
            throw new SecretServerException(sprintf('`ss auth print-access-token` failed (exit %d)%s', $exitCode, self::stderrExcerpt($stderr)));
        }

        try {
            $out = json_decode($stdout, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new SecretServerException('`ss auth print-access-token` returned invalid JSON');
        }
        if (!is_array($out)) {
            throw new SecretServerException('`ss auth print-access-token` returned invalid JSON');
        }
        $token = $out['access_token'] ?? null;
        if (!is_string($token) || preg_match('/^[\x21-\x7e]+$/', $token) !== 1) {
            throw new SecretServerException('`ss auth print-access-token` returned no usable access_token');
        }
        $expires = $out['expires_at'] ?? null;
        try {
            if (!is_string($expires) || preg_match(self::RFC3339, $expires) !== 1) {
                throw new \ValueError('expires_at');
            }
            $expiresAt = (new \DateTimeImmutable($expires))->getTimestamp();
        } catch (\Exception | \ValueError) {
            throw new SecretServerException('`ss auth print-access-token` returned an invalid expires_at');
        }
        $apiUrl = $out['api_url'] ?? null;
        return [$token, $expiresAt, is_string($apiUrl) && $apiUrl !== '' ? $apiUrl : null];
    }

    /** Resolve $path to an executable file: as given if it has a directory part, else via PATH. */
    private static function resolve(string $path): ?string
    {
        if ($path === '') {
            return null;
        }
        if (str_contains($path, '/') || str_contains($path, DIRECTORY_SEPARATOR)) {
            return is_file($path) && is_executable($path) ? $path : null;
        }
        $exts = PHP_OS_FAMILY === 'Windows' ? ['', '.exe', '.bat', '.cmd'] : [''];
        foreach (explode(PATH_SEPARATOR, (string) getenv('PATH')) as $dir) {
            // Relative PATH entries would resolve against the working directory.
            if ($dir === '' || !preg_match('#^([/\\\\]|[A-Za-z]:)#', $dir)) {
                continue;
            }
            foreach ($exts as $ext) {
                $candidate = rtrim($dir, '/\\') . DIRECTORY_SEPARATOR . $path . $ext;
                if (is_file($candidate) && is_executable($candidate)) {
                    return $candidate;
                }
            }
        }
        return null;
    }

    /** First stderr line, at most 200 printable characters. The CLI never writes tokens to stderr. */
    private static function stderrExcerpt(string $stderr): string
    {
        $line = strtok(trim($stderr), "\n");
        $line = substr((string) preg_replace('/[\x00-\x1f\x7f]/', '', $line === false ? '' : $line), 0, 200);
        return $line === '' ? '' : ': ' . $line;
    }
}
