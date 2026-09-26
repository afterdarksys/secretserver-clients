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

header('Content-Type: application/json');

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
