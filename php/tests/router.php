<?php

// Offline contract fixture for tests/contract.php (PHP built-in server router).

$uri    = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer sk_test') {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'invalid key BODY_LEAK_MARKER']);
    return;
}

switch ($uri) {
    case '/api/v1/oversize':
        header('Content-Type: application/json');
        echo '"' . str_repeat('a', 5 * 1024 * 1024) . '"';
        return;
    case '/api/v1/oversize-chunked':
        header('Content-Type: application/json');
        echo '"';
        for ($i = 0; $i < 80; $i++) {
            echo str_repeat('a', 64 * 1024);
            flush();
        }
        echo '"';
        return;
    case '/api/v1/notjson':
        header('Content-Type: text/plain');
        echo 'plain text, not json';
        return;
    case '/api/v1/scalar':
        header('Content-Type: application/json');
        echo '"just a string"';
        return;
    case '/api/v1/fail':
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'BODY_LEAK_MARKER']);
        return;
    case '/api/v1/redirect':
        http_response_code(302);
        header('Location: /api/v1/secrets');
        return;
}

$route = parse_url($uri, PHP_URL_PATH);
if ($method === 'GET' && preg_match('#^/api/v1/certificates/(\w+)/download$#', $route, $m)) {
    header('Content-Type: text/plain');
    $sizes = ['mid' => 5 * 1024 * 1024, 'big' => 17 * 1024 * 1024];
    echo isset($sizes[$m[1]]) ? str_repeat('b', $sizes[$m[1]]) : 'RAW-PEM:' . (string) parse_url($uri, PHP_URL_QUERY);
    return;
}

header('Content-Type: application/json');

$records = [
    '/api/v1/secrets/prod%2Fdb' => [
        'id' => 'id-db', 'name' => 'prod/db', 'description' => 'keep-desc', 'tags' => ['t1'],
        'container_id' => 'c-1', 'data' => ['value' => 'old'], 'version' => 3,
    ],
    '/api/v1/secrets/db1' => ['id' => 'id-db1', 'name' => 'db1', 'data' => ['value' => 'v1'], 'version' => 3],
    '/api/v1/jks-keystores/j1' => [
        'id' => 'j1', 'name' => 'jks-name', 'container_id' => 'c-1', 'notes' => 'n1', 'tags' => ['t1'],
        'store_type' => 'managed', 'created_at' => '2026-01-01T00:00:00Z',
    ],
    '/api/v1/yubikeys/y1' => [
        'id' => 'y1', 'name' => 'yk', 'container_id' => null, 'serial_number' => '123', 'public_id' => 'cccccccccccc',
        'client_id' => '42', 'validation_server' => 'api.yubico.com', 'notes' => '', 'tags' => ['t2'],
    ],
    '/api/v1/secret/s1/history' => [['version_num' => 1, 'secret_type' => 'secret']],
    '/api/v1/totp-tokens' => ['tokens' => [['id' => 't1']], 'total' => 1],
];
$versioned = ['/api/v1/secrets/prod%2Fdb', '/api/v1/secrets/db1', '/api/v1/jks-keystores/j1', '/api/v1/yubikeys/y1'];
if ($method === 'GET' && isset($records[$uri])) {
    if (in_array($uri, $versioned, true)) {
        header('ETag: "2026-01-01T00:00:00Z"');
    }
    echo json_encode($records[$uri]);
    return;
}
// Partial updates: If-Match must be the current ETag, W/ form, *, or (secrets) version 3.
if ($method === 'PUT' && in_array($uri, $versioned, true)) {
    $ifMatch = $_SERVER['HTTP_IF_MATCH'] ?? null;
    $accepted = ['"2026-01-01T00:00:00Z"', 'W/"2026-01-01T00:00:00Z"', '*', '3'];
    if ($ifMatch !== null && !in_array($ifMatch, $accepted, true)) {
        http_response_code(409);
        header('ETag: "2026-02-02T00:00:00Z"');
        echo json_encode(['error' => 'modified BODY_LEAK_MARKER']);
        return;
    }
    header('ETag: "2026-03-03T00:00:00Z"');
    $raw = file_get_contents('php://input');
    echo json_encode(['method' => $method, 'path' => $uri, 'raw' => $raw, 'if_match' => $ifMatch]);
    return;
}
if ($method === 'POST' && $uri === '/api/v1/transform/decode') {
    echo json_encode(['result' => ['sub' => 'x'], 'type' => 'jwt']);
    return;
}

if ($method === 'GET' && $uri === '/api/v1/secrets') {
    echo json_encode(['secrets' => [['id' => '1', 'name' => 'db']], 'total' => 1]);
    return;
}

$body = json_decode(file_get_contents('php://input'), true) ?? [];
echo json_encode([
    'method' => $method,
    'path' => $uri,
    'body' => $body,
]);
