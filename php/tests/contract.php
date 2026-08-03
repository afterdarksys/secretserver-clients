<?php

require dirname(__DIR__) . '/src/SecretServerClient.php';

use SecretServer\SecretServerClient;

$baseURL = getenv('TEST_SERVER_URL');
if (!$baseURL) {
    throw new RuntimeException('TEST_SERVER_URL is required');
}

$client = new SecretServerClient('sk_test', $baseURL . '/api/v1');
$secrets = $client->listSecrets();
if (($secrets[0]['name'] ?? null) !== 'db') {
    throw new RuntimeException('secret list envelope was not unwrapped');
}

$update = $client->updateSecret('prod/db', 'new');
if (($update['body']['name'] ?? null) !== 'prod/db' || ($update['path'] ?? null) !== '/api/v1/secrets/prod%2Fdb') {
    throw new RuntimeException('secret update does not match backend contract');
}

$enroll = $client->enrollCertificate('wildcard', 'example.test', ['www.example.test']);
if (($enroll['body']['dns_names'][0] ?? null) !== 'www.example.test' || isset($enroll['body']['sans'])) {
    throw new RuntimeException('certificate enrollment does not match backend contract');
}
