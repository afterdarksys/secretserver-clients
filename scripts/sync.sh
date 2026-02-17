#!/usr/bin/env bash
# sync.sh — Sync client libraries from the main secretserver.io repo.
#
# Usage:
#   ./scripts/sync.sh                         # uses default SOURCE path
#   SOURCE=/path/to/secretserver.io ./scripts/sync.sh
#
# What it does:
#   1. Copies pkg/sdk/*.go  → go/secretserver/
#   2. Copies ansible/plugins/lookup/secretserver.py → (future: python extras)
#   3. Updates go/go.mod package path if needed
#   4. Commits the result with a timestamped message
#
# Run this any time you want to publish a new version of the Go SDK
# without re-writing it by hand.

set -euo pipefail

CLIENTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${SOURCE:-/Users/ryan/development/secretserver.io}"

if [[ ! -d "$SOURCE" ]]; then
  echo "ERROR: Source repo not found at $SOURCE"
  echo "       Set SOURCE=/path/to/secretserver.io and re-run."
  exit 1
fi

echo "==> Syncing from: $SOURCE"
echo "==>           to: $CLIENTS_DIR"

# -----------------------------------------------------------------------
# 1. Go SDK
# -----------------------------------------------------------------------
GO_DST="$CLIENTS_DIR/go/secretserver"
GO_SRC="$SOURCE/pkg/sdk"

if [[ -d "$GO_SRC" ]]; then
  echo "    [go] Syncing $GO_SRC → $GO_DST"
  mkdir -p "$GO_DST"
  # Copy only .go source files (not tests for the public SDK)
  find "$GO_SRC" -maxdepth 1 -name "*.go" ! -name "*_test.go" -exec cp {} "$GO_DST/" \;

  # Fix the package declaration: sdk → secretserver
  for f in "$GO_DST"/*.go; do
    sed -i.bak 's/^package sdk$/package secretserver/' "$f" && rm -f "${f}.bak"
  done

  echo "    [go] Synced $(ls "$GO_DST"/*.go | wc -l | tr -d ' ') files"
else
  echo "    [go] SKIP: $GO_SRC not found"
fi

# -----------------------------------------------------------------------
# 2. Permission constants reference (documentation only)
# -----------------------------------------------------------------------
PERM_SRC="$SOURCE/internal/api/middleware/auth.go"
if [[ -f "$PERM_SRC" ]]; then
  echo "    [docs] Extracting permission constants..."
  grep -E '^\s+Perm[A-Za-z]+\s+=' "$PERM_SRC" \
    | sed 's/^\s*//' \
    > "$CLIENTS_DIR/docs/permissions.txt"
  echo "    [docs] Written to docs/permissions.txt"
fi

# -----------------------------------------------------------------------
# 3. Ansible lookup plugin
# -----------------------------------------------------------------------
ANSIBLE_SRC="$SOURCE/ansible/plugins/lookup/secretserver.py"
if [[ -f "$ANSIBLE_SRC" ]]; then
  echo "    [ansible] Syncing lookup plugin..."
  mkdir -p "$CLIENTS_DIR/ansible"
  cp "$ANSIBLE_SRC" "$CLIENTS_DIR/ansible/secretserver.py"
  echo "    [ansible] Done"
fi

# -----------------------------------------------------------------------
# 4. Git commit
# -----------------------------------------------------------------------
cd "$CLIENTS_DIR"
if git diff --quiet && git diff --cached --quiet; then
  echo "==> No changes to commit."
else
  STAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  git add -A
  git commit -m "sync: Update from secretserver.io @ $STAMP"
  echo "==> Committed."
fi

echo "==> Sync complete."
