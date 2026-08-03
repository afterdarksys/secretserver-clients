# Implementation plan

## Phase 1: Server authority

- Replace the placeholder tenant settings handler with persisted, tenant-isolated settings.
- Add cache permissions: `cache:manage`, `cache:enroll`, and `cache:audit`.
- Add immutable policy, resource-binding, device, lease, and event tables.
- Add tenant HSM/KMS-backed cache-policy signing keys.
- Implement dashboard master switch, policy editor, device approval/revocation, and lease visibility.
- Add API tests proving cross-tenant denial and that clients cannot choose TTL or resources.

## Phase 2: Enrollment and issuance

- Implement device-code enrollment and attestation verification.
- Define canonical signed encodings and versioned cryptographic suites.
- Implement atomic bundle issuance with device-wrapped per-lease keys.
- Add monotonic lease sequence and signed revocation tombstones.
- Add conformance fixtures for every supported language.

## Phase 3: Daemon core

- Build the root-owned Go service with locked memory and dump suppression.
- Implement local encrypted transactional storage and atomic bundle activation.
- Implement standard time high-water behavior and restart invalidation.
- Implement Unix peer credential and Windows named-pipe authorization.
- Add status, resolve, and pipe-delivery APIs; no TCP or local mutation API.
- Add fuzzing, race tests, crash recovery, and secret-leak tests.

## Phase 4: Hardware assurance

- Implement TPM-backed enrollment/wrapping keys.
- Bind policy to approved PCR policy where requested.
- Implement persistent anti-rollback sequence/time state.
- Require online re-enrollment after hardware or PCR policy changes.

## Phase 5: Clients

- Add `--cache=off|prefer|required` and SDK equivalents to Go, Node, Python, and PHP.
- Use fixed local endpoint discovery and shared provenance fixtures.
- Default to `off`; never add TTL, populate, endpoint URL, or lease-extension options.
- Add integration tests for miss fallback, required-mode denial, expiry, invalid signatures, and revoked/tombstoned leases.

## Release gates

- Independent cryptographic and protocol review.
- Threat-model review covering root boundary and offline revocation limitations.
- Cross-platform IPC authorization tests.
- Reboot, suspend, clock-change, rollback, cache-copy, and crash testing.
- No secrets in logs, metrics, traces, crash dumps, command lines, environments, or support bundles.
- Dashboard disabling must stop new issuance immediately; documentation must state that existing offline leases remain valid only until signed expiry.
