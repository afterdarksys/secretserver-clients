# Client compatibility verification

**Verified:** 2026-08-03

**Backend:** `secretserver.io` commit `e83233c`

**REST contract:** `/api/v1`

## Result

The maintained clients now match the overhauled REST backend in the areas where
they provide typed helpers, and the general SDKs provide a generic authenticated
request method for the rest of the live REST surface.

| Client | Result | Notes |
|---|---|---|
| Python 1.3.0 | Pass | Contract tests, generic request, JKS, secure signing |
| Node.js 1.3.0 | Pass | Strict TypeScript build, generic request, JKS, secure signing |
| PHP 1.3.0 | Pass | PHP lint, generic request, JKS, secure signing |
| Go | Pass | Contract tests, typed core/JKS/signing services, generic `Call` |
| Ansible lookup | Pass | Path access, version access, normalized API base URL |
| MCP bridge | Pass | Operation-only signing tests; no private-key export |
| Go GUI | Pass through Go SDK | Fetches secret data before edit; list data remains redacted |

## Contract corrections

- List endpoints with backend envelopes (`secrets`, `certificates`, `ssh_keys`,
  `passwords`, `tokens`, `keys`, `openssl_keys`, `ntlm_hashes`, `webhooks`, and
  `deliveries`) are unwrapped by convenience methods.
- Secret updates include the backend-required `name` and `data` fields.
- Certificate enrollment sends `dns_names`, matching the live handler.
- Base URLs work with or without a trailing `/api/v1`, including proxy prefixes.
- Newly added resource IDs and aliases, core secret names, and query values are
  URL-escaped.
- Empty successful responses such as HTTP 204 do not cause Go JSON decode errors.
- JKS raw/managed keystore and entry operations are exposed in all general SDKs.
- HSM/smart-card signing remains operation-only and requires `keys:sign`; private
  key material is never returned by the signing APIs or MCP bridge.

## Scope

GraphQL and gRPC schemas are not treated as operational client transports because
the backend documents them as design artifacts. The Ansible plugin intentionally
supports lookup only, and the MCP bridge intentionally exposes only bounded key
metadata and signing operations.

## Verification commands

```bash
PYTHONPATH=python python3 -m unittest discover -s python/tests -v
(cd node && npm test)
php -l php/src/SecretServerClient.php
(cd go && go test ./...)
(cd mcp && go test ./...)
```
