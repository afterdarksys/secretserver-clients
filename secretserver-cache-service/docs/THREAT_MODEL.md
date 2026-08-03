# Threat model

## Protected assets

- Cached secret plaintext.
- Lease content-encryption keys.
- Device enrollment and wrapping private keys.
- Tenant policy-signing keys.
- Policy scope, TTL, consumer identity, and lease sequence.
- Audit integrity and resource provenance.

## Defended threats

- Stolen disks, snapshots, backups, and copied cache databases.
- Unprivileged local users and processes.
- Cache-file modification, record swapping, and ciphertext replay.
- Old policy or lease replay.
- Local attempts to extend TTL or add resources.
- Rogue local TCP clients and remote network access.
- Cache poisoning by a substituted daemon or socket.
- Clock rollback during a running standard lease.
- Secret leakage through logs, metrics, command arguments, environment variables, or error messages.

## Conditional defenses

- Offline rollback across reboot requires the hardware-bound tier.
- Executable identity enforcement depends on OS support and stable signed binaries.
- Memory scraping resistance depends on hardware sealing, locked memory, dump policy, kernel health, and consumer behavior.

## Out of scope for standard assurance

- Root, kernel, hypervisor, firmware, or physical live-memory compromise.
- A malicious approved consumer after plaintext delivery.
- Immediate revocation while the device is offline.
- Availability attacks, deliberate clock jumps that cause early expiry, or deletion of the cache.
- A fully compromised SecretServer/Vault/HSM control plane.

## Required failure behavior

- Invalid signature, unknown policy version, rollback, expired lease, unsupported algorithm, corrupt record, wrong consumer, or unavailable key: deny and audit.
- Cache miss in `required` mode: deny without remote fallback.
- Cache miss in `prefer` mode: use normal authenticated SecretServer lookup; never populate the cache from the client.
- Device revocation seen online: wipe wrapped keys and encrypted records, persist a signed tombstone, then deny.
- Hardware attestation downgrade: deny; never silently switch to standard assurance.

## Security tests

- Modify every signed and AEAD-bound field independently.
- Replay older lease sequences and policy versions.
- Copy a cache database to another enrolled and unenrolled device.
- Roll clocks backward and forward, suspend/resume, and reboot offline.
- Replace the socket, race socket creation, and connect as unauthorized users.
- Crash during atomic bundle replacement and key rotation.
- Fuzz manifest decoding, local IPC, bundle parsing, and encrypted-record headers.
- Assert logs and metrics never contain secret values, ciphertext bodies, keys, tokens, or local plaintext.
