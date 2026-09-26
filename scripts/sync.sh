#!/usr/bin/env bash
# sync.sh — Report drift between these clients and the secretserver.io repo.
#
# Usage:
#   ./scripts/sync.sh                         # uses default SOURCE path
#   SOURCE=/path/to/secretserver.io ./scripts/sync.sh
#
# What it does:
#   1. Shows a diff of the server's pkg/sdk against go/secretserver/ (read-only)
#   2. Shows a diff of the server's Ansible lookup plugin against ansible/ (read-only)
#   3. Refreshes docs/permissions.txt from the server's permission constants
#
# It never copies code over the clients and never commits. The client copies
# carry hardening (HTTPS-only base URLs, no TLS-verification bypass, bounded
# responses) that a blind copy would silently revert. Port changes by hand,
# then run the tests and scripts/live-integration.sh.

set -euo pipefail

CLIENTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${SOURCE:-$HOME/development/secretserver.io}"

if [[ ! -d "$SOURCE" ]]; then
  echo "ERROR: Source repo not found at $SOURCE"
  echo "       Set SOURCE=/path/to/secretserver.io and re-run."
  exit 1
fi

echo "==> Comparing: $SOURCE"
echo "==>        to: $CLIENTS_DIR"

GO_SRC="$SOURCE/pkg/sdk"
if [[ -d "$GO_SRC" ]]; then
  echo "    [go] Drift between $GO_SRC and go/secretserver (review, do not copy):"
  for f in "$GO_SRC"/*.go; do
    [[ "$f" == *_test.go ]] && continue
    dst="$CLIENTS_DIR/go/secretserver/$(basename "$f")"
    if [[ -f "$dst" ]]; then
      diff -u <(sed 's/^package sdk$/package secretserver/' "$f") "$dst" || true
    else
      echo "    [go] only in server: $(basename "$f")"
    fi
  done
else
  echo "    [go] SKIP: $GO_SRC not found"
fi

ANSIBLE_SRC="$SOURCE/ansible/plugins/lookup/secretserver.py"
if [[ -f "$ANSIBLE_SRC" ]]; then
  echo "    [ansible] Drift in lookup plugin (review, do not copy):"
  diff -u "$ANSIBLE_SRC" "$CLIENTS_DIR/ansible/secretserver.py" || true
fi

PERM_SRC="$SOURCE/internal/api/middleware/auth.go"
if [[ -f "$PERM_SRC" ]]; then
  echo "    [docs] Extracting permission constants..."
  grep -E '^\s+Perm[A-Za-z]+\s+=' "$PERM_SRC" \
    | sed 's/^\s*//' \
    > "$CLIENTS_DIR/docs/permissions.txt"
  echo "    [docs] Written to docs/permissions.txt (review with git diff; not committed)"
fi

echo "==> Drift report complete. Nothing was copied or committed."
