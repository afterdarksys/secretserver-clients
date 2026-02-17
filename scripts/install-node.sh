#!/usr/bin/env bash
# Install the SecretServer Node.js / TypeScript client library.
# Usage: bash scripts/install-node.sh [--dev]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$SCRIPT_DIR/../node"

cd "$NODE_DIR"

if [[ "${1:-}" == "--dev" ]]; then
  echo "==> Installing deps and linking for dev..."
  npm install
  npm link
  echo "==> Done. Use 'npm link secretserver' in your project."
else
  echo "==> Building dist..."
  npm install
  npm run build
  echo "==> Install from local path with:"
  echo "    npm install $NODE_DIR"
fi
