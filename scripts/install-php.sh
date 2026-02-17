#!/usr/bin/env bash
# Install the SecretServer PHP client library via Composer.
# Usage: bash scripts/install-php.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHP_DIR="$SCRIPT_DIR/../php"

if ! command -v composer &>/dev/null; then
  echo "ERROR: composer not found. Install from https://getcomposer.org"
  exit 1
fi

echo "==> Installing PHP client library dependencies..."
cd "$PHP_DIR"
composer install --no-dev --optimize-autoloader

echo "==> Done. Add to your project:"
echo "    composer require afterdark/secretserver"
echo "    # or from local path:"
echo "    composer config repositories.secretserver path $PHP_DIR"
echo "    composer require afterdark/secretserver:@dev"
