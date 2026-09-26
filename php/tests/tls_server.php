<?php

// Minimal loopback HTTPS responder used by tests/contract.php to prove that
// TLS verification is enforced and that $caFile trusts a private CA.
// Usage: php tls_server.php <cert.pem> <key.pem>; prints the bound port.

[$_, $cert, $key] = $argv;
$context = stream_context_create(['ssl' => [
    'local_cert' => $cert,
    'local_pk' => $key,
    'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
]]);
$server = stream_socket_server('tls://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
if ($server === false) {
    fwrite(STDERR, "bind failed: $errstr\n");
    exit(1);
}
echo parse_url('tcp://' . stream_socket_get_name($server, false), PHP_URL_PORT), "\n";
fflush(STDOUT);

while (true) {
    // A failed handshake (client rejected the certificate) returns false; keep serving.
    // Warnings go to stderr, which the test harness discards.
    $conn = stream_socket_accept($server, 30);
    if ($conn === false) {
        continue;
    }
    while (($line = fgets($conn)) !== false && trim($line) !== '') {
    }
    $body = json_encode(['secrets' => [['name' => 'tls-ok']]]);
    fwrite($conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
    fclose($conn);
}
