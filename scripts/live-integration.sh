#!/usr/bin/env bash
# Live client verification against a disposable, loopback-only SecretServer.
#
# Threats: exercises every client against the real API binary, PostgreSQL and
# Vault so contract drift fails loudly. All services listen on 127.0.0.1 only
# (except the API binary, which binds its configured port on all interfaces;
# run on a trusted host), credentials are generated from the OS CSPRNG per run,
# and the whole state directory is deleted on exit. It does NOT test TLS
# termination or production configuration, and must never point at a real
# deployment: it refuses any SECRETSERVER_SRC that is not a local checkout.
#
# Usage:
#   git -C ~/development/secretserver.io worktree add --detach /tmp/ss-main origin/main
#   SECRETSERVER_SRC=/tmp/ss-main scripts/live-integration.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=${SECRETSERVER_SRC:?set SECRETSERVER_SRC to a local secretserver.io checkout}
[[ -f "$SRC/cmd/api-server/main.go" ]] || { echo "SECRETSERVER_SRC is not a secretserver.io checkout" >&2; exit 2; }
for tool in initdb pg_ctl createdb psql vault go node npm python3 php ansible-playbook openssl curl shasum; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/ss-client-live.XXXXXX")
chmod 700 "$WORK"
# Unix socket paths are limited to ~104 bytes; keep the PostgreSQL socket in a
# short private directory so a long TMPDIR still works.
SOCK=$(mktemp -d /tmp/ssli.XXXXXX)
chmod 700 "$SOCK"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] && { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
  done
  pg_ctl -D "$WORK/pg" -m fast stop >/dev/null 2>&1 || true
  rm -rf "$WORK" "$SOCK"
}
trap cleanup EXIT

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
PG_PORT=$(free_port); VAULT_PORT=$(free_port); API_PORT=$(free_port)
# Vault dev also listens on VAULT_PORT+1 for cluster traffic; keep the API clear of it.
while [[ $API_PORT == $((VAULT_PORT + 1)) || $API_PORT == "$PG_PORT" || $PG_PORT == $((VAULT_PORT + 1)) ]]; do
  VAULT_PORT=$(free_port)
done
PG_PASSWORD=$(openssl rand -hex 24)
VAULT_TOKEN=$(openssl rand -hex 24)
JWT_SECRET=$(openssl rand -hex 32)
umask 077

echo "==> PostgreSQL on 127.0.0.1:$PG_PORT"
printf '%s\n' "$PG_PASSWORD" > "$WORK/pgpass"
initdb -D "$WORK/pg" -U ss_admin --auth-local=trust --auth-host=scram-sha-256 --pwfile="$WORK/pgpass" >"$WORK/initdb.log"
pg_ctl -D "$WORK/pg" -l "$WORK/pg.log" -o "-p $PG_PORT -h 127.0.0.1 -k $SOCK" -w start >/dev/null
createdb -h "$SOCK" -p "$PG_PORT" -U ss_admin ss_live
DSN="postgres://ss_admin:$PG_PASSWORD@127.0.0.1:$PG_PORT/ss_live?sslmode=disable"

echo "==> Vault dev on 127.0.0.1:$VAULT_PORT"
# The root token is passed through the environment, not argv, so it is not
# visible in the process list.
VAULT_DEV_ROOT_TOKEN_ID="$VAULT_TOKEN" vault server -dev -dev-no-store-token \
  -dev-listen-address="127.0.0.1:$VAULT_PORT" >"$WORK/vault.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do curl -fsS "http://127.0.0.1:$VAULT_PORT/v1/sys/health" >/dev/null 2>&1 && break; sleep 0.1; done

echo "==> Build server from $SRC ($(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown))"
(cd "$SRC" && go build -o "$WORK/api-server" ./cmd/api-server && go build -o "$WORK/ss-migrate" ./cmd/ss-migrate)
DATABASE_URL="$DSN" "$WORK/ss-migrate" >"$WORK/migrate.log" 2>&1
PORT="$API_PORT" DATABASE_URL="$DSN" VAULT_ADDR="http://127.0.0.1:$VAULT_PORT" VAULT_TOKEN="$VAULT_TOKEN" \
  JWT_SECRET="$JWT_SECRET" GIN_MODE=release "$WORK/api-server" >"$WORK/api.log" 2>&1 &
PIDS+=($!)
API="http://127.0.0.1:$API_PORT"
ready=0
for _ in $(seq 1 150); do
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/ready")" == 200 ]]; then ready=1; break; fi
  sleep 0.2
done
if [[ $ready != 1 ]]; then echo "API did not become ready" >&2; curl -sS "$API/ready" >&2 || true; tail -20 "$WORK/api.log" >&2; exit 1; fi

echo "==> Bootstrap tenant, API key and 'prod' container"
RAW_KEY="sk_$(openssl rand -hex 24)"
KEY_HASH=$(printf '%s' "$RAW_KEY" | shasum -a 256 | cut -d' ' -f1)
# A least-privilege key for update tests: it may write but never read secrets.
WRITE_KEY="sk_$(openssl rand -hex 24)"
WRITE_HASH=$(printf '%s' "$WRITE_KEY" | shasum -a 256 | cut -d' ' -f1)
psql -q -h "$SOCK" -p "$PG_PORT" -U ss_admin -d ss_live -v ON_ERROR_STOP=1 \
  -v key_hash="$KEY_HASH" -v key_prefix="${RAW_KEY:0:11}" \
  -v write_hash="$WRITE_HASH" -v write_prefix="${WRITE_KEY:0:11}" <<'SQL' >/dev/null
WITH t AS (
  INSERT INTO tenants (name, email, password_hash, vault_path, plan, max_secrets, max_certs, max_api_keys)
  VALUES ('Client Live', 'live@example.test', 'unused', 'client-live', 'enterprise', 10000, 1000, 50)
  RETURNING id)
INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, permissions)
SELECT id, 'client-live', :'key_hash', :'key_prefix', '["admin:*"]'::jsonb FROM t
UNION ALL
SELECT id, 'client-live-write', :'write_hash', :'write_prefix', '["secrets:write"]'::jsonb FROM t;
SQL
printf 'Authorization: Bearer %s\n' "$RAW_KEY" >"$WORK/auth.header"
printf '%s\n' "$RAW_KEY" >"$WORK/token"
CONTAINER=$(curl -fsS -H @"$WORK/auth.header" -H 'Content-Type: application/json' \
  -d '{"name":"Production","slug":"prod"}' "$API/api/v1/containers" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')

export SS_LIVE_WRITE_KEY="$WRITE_KEY"
export SS_LIVE_URL="$API" SS_LIVE_KEY="$RAW_KEY" SS_LIVE_CONTAINER="$CONTAINER" SS_LIVE_TOKEN_FILE="$WORK/token"

declare -a NAMES STATUS
run() {
  local name=$1 dir=$2; shift 2
  echo "==> $name"
  if (cd "$ROOT/$dir" && "$@") >"$WORK/$name.out" 2>&1; then
    # A client that exits 0 but reports skipped or server-blocked checks is
    # not a full pass.
    if grep -qE '^(NOT VERIFIED|SKIP)' "$WORK/$name.out"; then
      STATUS+=("NOT VERIFIED")
    else
      STATUS+=(PASS)
    fi
  else
    STATUS+=(FAIL); sed -e "s/$RAW_KEY/<redacted>/g" -e "s/$WRITE_KEY/<redacted>/g" "$WORK/$name.out" | tail -30 >&2
  fi
  NAMES+=("$name")
  sed "s/$RAW_KEY/<redacted>/g" "$WORK/$name.out" | grep -E '^(NOT VERIFIED|SKIP)' || true
  sed "s/$RAW_KEY/<redacted>/g" "$WORK/$name.out" | tail -3
}

run go go go run ./cmd/platform-smoke
run mcp mcp go test -count=1 -v -run '^TestLive$' .
run python python env PYTHONPATH="$ROOT/python" python3 tests/live.py
run node node sh -c 'npm run --silent build && node tests/live.mjs'
run php php php tests/live.php
run ansible ansible env ANSIBLE_LOOKUP_PLUGINS="$ROOT/ansible" ANSIBLE_NOCOLOR=1 \
  ansible-playbook -i localhost, tests/live.yml </dev/null

echo
printf '%-10s %s\n' CLIENT RESULT
failed=0
for i in "${!NAMES[@]}"; do
  printf '%-10s %s\n' "${NAMES[$i]}" "${STATUS[$i]}"
  if [[ "${STATUS[$i]}" == FAIL ]]; then failed=1; fi
done
if grep -qF -e "$RAW_KEY" -e "$WRITE_KEY" "$WORK/api.log"; then echo "FAIL: API key appeared in server log" >&2; failed=1; fi
if [[ $failed == 0 ]] && printf '%s\n' "${STATUS[@]}" | grep -q "NOT VERIFIED"; then
  echo "All clients passed their executed checks; NOT VERIFIED rows list checks that were skipped or blocked by server defects."
fi
exit $failed
