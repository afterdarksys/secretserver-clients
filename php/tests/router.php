<?php

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'GET' && $_SERVER['REQUEST_URI'] === '/api/v1/secrets') {
    echo json_encode(['secrets' => [['id' => '1', 'name' => 'db']], 'total' => 1]);
    return;
}

$body = json_decode(file_get_contents('php://input'), true) ?? [];
echo json_encode([
    'method' => $_SERVER['REQUEST_METHOD'],
    'path' => $_SERVER['REQUEST_URI'],
    'body' => $body,
]);
