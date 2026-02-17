#!/usr/bin/env bash
# Install the SecretServer Go client module.
# Usage: bash scripts/install-go.sh
set -euo pipefail

echo "==> SecretServer Go client"
echo ""
echo "Add to your go.mod:"
echo "    go get github.com/afterdarksys/secretserver-go"
echo ""
echo "Or install from local path (development):"
echo "    go mod edit -replace github.com/afterdarksys/secretserver-go=/path/to/secretserver-clients/go"
echo "    go mod tidy"
echo ""
echo "Usage:"
echo "    import ss \"github.com/afterdarksys/secretserver-go/secretserver\""
echo "    client, _ := ss.NewClient(&ss.Config{APIKey: os.Getenv(\"SS_API_KEY\")})"
echo "    secret, _ := client.Secrets.Get(ctx, \"mykey\", nil)"
