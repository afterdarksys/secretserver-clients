#!/usr/bin/env bash
# Offline test runner: serves tests/router.php on a free loopback port with the
# PHP built-in server, runs tests/contract.php against it, then stops it.
set -euo pipefail

DIR=$(cd "$(dirname "$0")/.." && pwd)
PHP=${PHP:-php}
PORT=$("$PHP" -r '$s=stream_socket_server("tcp://127.0.0.1:0");echo parse_url("tcp://".stream_socket_get_name($s,false),PHP_URL_PORT);')
LOG=$(mktemp "${TMPDIR:-/tmp}/ss-php-router.XXXXXX")

"$PHP" -S "127.0.0.1:$PORT" "$DIR/tests/router.php" >"$LOG" 2>&1 &
SERVER=$!
cleanup() { kill "$SERVER" 2>/dev/null || true; wait "$SERVER" 2>/dev/null || true; rm -f "$LOG"; }
trap cleanup EXIT

for _ in $(seq 1 50); do
  (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
  sleep 0.1
done

TEST_SERVER_URL="http://127.0.0.1:$PORT" "$PHP" "$DIR/tests/contract.php"
TEST_SERVER_URL="http://127.0.0.1:$PORT" "$PHP" "$DIR/tests/cli_credentials.php"
