#!/usr/bin/env bash
# Install the SecretServer Python client library.
# Usage: bash scripts/install-python.sh [--dev]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_DIR="$SCRIPT_DIR/../python"

if [[ "${1:-}" == "--dev" ]]; then
  echo "==> Installing in editable (dev) mode..."
  pip install -e "$PYTHON_DIR"
else
  echo "==> Building and installing..."
  pip install "$PYTHON_DIR"
fi

echo "==> Done. Test with:"
echo "    python -c \"from secretserver import SecretServerClient; print('OK')\""
