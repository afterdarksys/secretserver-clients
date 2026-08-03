# SecretServer Cache Service

`secretserver-cache-service` is a proposed small local daemon for encrypted, time-bounded offline access to dashboard-approved secrets. This directory is an implementation-ready security design; it is not yet an operational daemon.

The service is an **offline lease cache**, not a general-purpose cache:

- A tenant administrator enables the feature and creates a policy in the dashboard.
- The policy fixes the device, secret set, versions, consumers, delivery modes, capacity, assurance tier, and TTL.
- A device generates non-exportable enrollment and wrapping keys.
- SecretServer issues a signed policy and a device-wrapped, per-lease cache key.
- The daemon cannot add secrets, extend a lease, change its TTL, or widen local consumers.
- Cache entries are encrypted individually and bound to the signed lease and policy using AEAD associated data.
- Expiration fails closed. An offline device cannot receive immediate revocation, so maximum exposure equals the remaining lease lifetime.

## Documents

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Protocol](docs/PROTOCOL.md)
- [Client integration](docs/CLIENT_INTEGRATION.md)
- [Architecture decision](docs/ADR-001-OFFLINE-LEASE-CACHE.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Local API sketch](api/openapi.yaml)
- [Signed policy schema](schemas/cache-policy.schema.json)

## Non-negotiable properties

1. Disabled by default at tenant and policy levels.
2. No local TTL, secret-selection, policy-edit, lease-renew, or cache-populate interface.
3. No reusable plaintext cache key is pasted into configuration.
4. No TCP listener; use a root-owned Unix socket or Windows named pipe.
5. No plaintext at rest, in logs, command-line arguments, environment variables, crash dumps, or metrics.
6. Client cache mode may be `off`, `prefer`, or `required`; it cannot modify server policy.
7. Standard assurance leases become unusable after an offline daemon restart. Offline-across-reboot requires a supported TPM-backed anti-rollback mechanism.
8. Local administrators/root remain outside the standard threat boundary; hardware-backed mode reduces but cannot eliminate a hostile administrator's ability to patch clients or inspect consumers.
