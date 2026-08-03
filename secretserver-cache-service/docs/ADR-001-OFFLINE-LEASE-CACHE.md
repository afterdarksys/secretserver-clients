# ADR-001: Device-bound offline lease cache

## Status

Proposed.

## Context

Servers and workstations need low-latency access to frequently used secrets and limited continuity during SecretServer or network outages. A conventional local cache would allow local configuration to extend TTLs, widen scope, replay old data, or silently serve stale credentials.

The dashboard must remain the authority for whether caching is enabled, which exact resources are eligible, who may consume them, and how long an issued cache is valid.

## Decision

Build a separate Go daemon using a signed offline-lease model.

- Dashboard changes create immutable policy versions.
- Devices enroll with separate signing/attestation and key-wrapping public keys.
- SecretServer signs a canonical policy manifest and issues monotonically sequenced leases.
- Every lease receives a new random content-encryption key wrapped to the approved device. The operator never handles this key.
- The daemon stores encrypted values in a transactional embedded key-value store. Identifiers are keyed hashes; values use per-record AEAD.
- Clients communicate only over OS-local IPC and authenticate the daemon and lease provenance.
- The client may select `off`, `prefer`, or `required`. It cannot set TTL, scope, or refresh behavior.
- Lease renewal requires the server and always creates a new signed lease. It never mutates an existing lease.

## Assurance tiers

### Standard OS-bound

Protects against disk theft, backups, other unprivileged users, accidental disclosure, and cache-file copying. It does not claim resistance to root, kernel compromise, debugger access, or offline clock rollback across reboot. A standard lease is invalid after restart unless it can revalidate online.

### Hardware-bound

Requires TPM-backed non-exportable wrapping keys plus a supported persistent monotonic counter or trusted clock. It may remain usable across offline reboot while the signed lease remains valid. PCR policy is dashboard-controlled and changes require a newly approved device state.

## Consequences

- Offline revocation cannot be instantaneous. Short leases bound the risk.
- Cached secret reads deliberately deliver plaintext to an approved consumer; the daemon can keep its own plaintext in locked memory, but the consumer and kernel IPC buffers are separate trust boundaries.
- Workstations without suitable hardware cannot receive the strongest offline-across-reboot guarantee.
- This is more complex than SQLite plus a locally configurable TTL, but it preserves dashboard authority and provides meaningful rollback controls.

## Rejected alternatives

- **Plaintext key in a config file or environment variable:** recoverable from disk, process metadata, backups, or support bundles.
- **Locally configurable TTL:** allows indefinite extension after server authorization ends.
- **Redis or a TCP cache:** expands the attack surface and encourages network sharing.
- **One tenant-wide cache key:** one device compromise exposes every device and lease.
- **Relying only on wall-clock time:** vulnerable to clock rollback.
- **Immediate offline revocation claims:** impossible without a communication channel.
