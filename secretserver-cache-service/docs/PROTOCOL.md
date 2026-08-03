# Lease and cache protocol

## State machine

```text
UNENROLLED -> PENDING_APPROVAL -> ACTIVE -> EXPIRED
                                 |   |
                                 |   +-> QUARANTINED
                                 +------> REVOKED
```

Only a server-signed transition may enter `ACTIVE`. Local events may move to `EXPIRED` or `QUARANTINED`; no local event may restore validity.

## Signed policy

Canonical serialization must be deterministic and versioned. Use deterministic CBOR or another reviewed canonical encoding; do not sign ordinary map-based JSON serialization.

Required claims:

- Format and protocol version.
- Tenant, policy ID, and immutable policy version.
- Device ID and approved device public-key digests.
- Lease ID and monotonic sequence.
- `issued_at`, `not_before`, and `expires_at`.
- Exact resource type, ID, resolved version, and encrypted-record digest.
- Consumer identities and permitted delivery modes.
- Assurance tier, algorithms, maximum entries, and maximum bytes.
- Previous lease digest when replacing a lease.

The JSON schema in `schemas/cache-policy.schema.json` documents logical fields; the signed representation remains canonical binary.

## Cryptographic suites

Use versioned, allowlisted suites rather than caller-supplied primitive names.

- Default suite: HPKE X25519/HKDF-SHA-256/ChaCha20-Poly1305 for key wrapping; XChaCha20-Poly1305 for records.
- FIPS suite: HPKE P-256/HKDF-SHA-256/AES-256-GCM for key wrapping; AES-256-GCM records with transactionally unique nonces.
- Policy signatures: Ed25519 by default; ECDSA P-256 for FIPS deployments.

Use maintained implementations of the standards. Do not implement HPKE, canonical encoding, or AEAD primitives locally.

AEAD associated data includes protocol version, tenant, policy hash, lease ID, sequence, resource type, resource ID, secret version, expiry, and record index.

## Bundle operations

### Enroll

The daemon requests a one-time device code, generates keys, and uploads public enrollment material. The administrator approves it in the dashboard.

### Issue

The server resolves policy resources and produces a complete atomic bundle. Issuance fails if any resource cannot be resolved or if size limits are exceeded.

### Activate

The daemon validates signatures, device binding, sequence, time, algorithms, capacity, and all record digests before replacing the prior active lease in one transaction.

### Resolve

The daemon authenticates the local peer, checks policy and time, locates the HMAC-derived record key, verifies AEAD, delivers according to the approved mode, wipes plaintext, and emits metadata-only audit data.

### Renew

Renewal is online issuance of a new lease and key. The client cannot request a duration; the server uses the immutable policy version. A shorter or changed policy produces a new version and explicit replacement.

### Revoke

Online revocation returns a signed tombstone with a sequence greater than any issued lease. The daemon destroys keys and records. An offline daemon learns of revocation only when it reconnects or the current lease expires.

## Local API

Expose only:

- Status and non-secret provenance.
- Resolve/materialize for signed-policy resources.
- Optional child-process execution with pipe delivery.

Do not expose local policy edits, arbitrary cache put, TTL changes, lease extension, raw key access, bulk dump, TCP binding, debug secret output, or unsafe environment-variable injection.
