# Runtime memory protection

Implemented 2026-09-28. This is targeted hardening, not complete process-memory
protection. A compromised process, privileged debugger, kernel, or host can still
read secrets. Encryption at rest and access-controlled document viewing address
different threats.

## Go: guarded, locked buffers

Secret Server, the device agent, and the MCP executable use the same small
`securemem` adapter with pinned `github.com/awnumar/memguard v0.23.0`. The adapter
owns off-heap plaintext in locked pages with guard pages and canaries. Buffers
are read-only except during controlled writes. Linux additionally requires
`MADV_DONTDUMP` to succeed. Destroy wipes and frees the allocation. Consume wipes
the input byte slice even on failure; it cannot erase prior copies or strings.
Maximum owned secret size is 1 MiB; whole documents are not locked.

**Encrypted MemGuard Enclaves are intentionally not used.** Review of the pinned
version found recursive purge deadlocks under intermediate allocation failure,
cleanup omissions after failed decryption, and a heap plaintext intermediate in
`core.Decrypt`. LockedBuffer avoids these enclave paths. Owned plaintext remains
in locked memory between calls; do not describe it as encrypted memory.

A process-wide mutex serializes borrowed views, allocation, and destruction so a
MemGuard failure cannot purge another callback's live view. Callbacks must be
short, must not retain or mutate views, and must not reenter securemem. Do not use
MemGuard directly alongside this adapter. Callback panics become a redacted
error. A dependency panic permanently marks the adapter unavailable until process
restart: no fallback, reallocation loop, or access through stale handles. This
also bounds a pinned-dependency partial-allocation leak on failure. Restart the
service after correcting its resource limit; do not repeatedly retry in-process.
The adapter is not intended for realtime throughput or arbitrary plugin callbacks.

Coverage:

| Component | Owned memory protected |
|---|---|
| API crypto providers | Existing PKCS#11 PIN and eHSM application credential users of securemem |
| API MCP bridge / MCP executable | Existing service-token buffers; concurrent Close no longer changes the token pointer |
| Document service | Random and Vault-decoded 32-byte document keys; storage/renderer client bearer-token buffers |
| Device agent | Decoded software Ed25519 identity key; public key cached independently, no private string retained in client state |

Document upload/download/render handlers explicitly clear owned PDF/PNG byte
slices after synchronous use, including error paths. These large buffers remain
ordinary memory. Poppler receives plaintext and uses temporary files on the
renderer tmpfs. Its internal allocations are not controlled by Go cleanup.

Boundaries still creating ordinary memory include environment variables, input
strings, file/JSON decoding, Vault base64 serialization, HTTP Authorization
strings, TLS buffers and cryptographic key schedules. Agent enrollment/state
persistence retains the existing base64 disk format. The Go 1.27 Ed25519
implementation cannot safely accept the mmap key directly because of its weak
pointer cache; signing makes an explicit temporary Go-heap key copy and clears
that owned slice immediately afterward. Internal library copies can outlive it.
This is not an HSM-backed agent identity or a guarantee of key erasure throughout
the runtime. Existing `WipeString` helpers do not erase immutable strings.

Libraries expose Close/Destroy but do not install signal handlers or terminate
the host. Executables purge on normal shutdown after work drains. Fatal exits,
SIGKILL, runtime crashes and abrupt host loss cannot guarantee application cleanup.
MemGuard attempts process-wide core-dump disabling on import; enforce it at the
OS level as well. Embedders must account for this process-wide side effect.

## Python and Node: ownership and remote operations

Python `SecretServerClient` holds its owned API-key copy in a bytearray. `close()`
wipes it and invalidates the client; context-manager exit does the same. Replacing
`api_key` wipes the old owned buffer. Node's client stores an owned Uint8Array in
private fields and `destroy()` wipes it. Representations are redacted and supported
serialization refuses secret-bearing clients. Neither runtime provides locked
memory through this API, and immutable strings, garbage-collected copies, HTTP
buffers, and caller-owned inputs cannot be reliably erased.

Both SDKs accept a request-time credential provider (`credential_provider` in
Python, `credentialProvider` in Node). Providers enable short-lived credentials
and rotation without retaining a permanent SDK key. They are mutually exclusive
with an explicit API key. Provider failures are redacted; empty or header-injection
values are refused. Calls begun after destroy/close are refused; in-progress calls may
still send or finish using an already-created header copy. Provider implementations and returned strings remain the caller's
responsibility. Do not log tokens or capture them in long-lived closures.

Both expose operation-only signing handles: Python `client.signing_key(key_id,
backend="pkcs11")`, Node `client.signingKey(keyId, "pkcs11")`; `ehsm` is also
supported. Call `.sign(payload, purpose)` with bytes/Uint8Array. These invoke
existing authenticated `/crypto/sign` operations without exporting the private
key. Actual non-exporting hardware protection depends on the selected deployed
backend and key configuration; these helpers do not turn software keys into HSM
keys. Parent-client cleanup invalidates future operations.

Node `--secure-heap` applies to selected OpenSSL allocations, not JavaScript
strings or Buffers, and is not a replacement for this lifecycle. Python bytearray
wiping likewise is not an mlock equivalent. For the strongest boundary, keep
private keys in a non-exporting HSM/service and perform operations remotely.

## Rust foundation

No Rust consumer existed in the scoped repositories. The new unpublished crate
`secretserver-clients/rust/secret-memory` supplies a foundation, not a complete SDK
or an integration claim for nonexistent Rust services.

`SecretBytes` uses pinned secrecy/zeroize for redacted, non-Clone ownership and
zero-on-drop heap memory; it does not lock pages. Its constructor copies into a
final-sized allocation while its input Vec is held in Zeroizing to avoid leaving
plaintext behind during Vec-to-box reallocation.

The default `guarded` feature adds `GuardedSecret` using libsodium guarded native
allocation, an explicit mandatory sodium_mlock check, and no-access pages between
callback borrows. Views are read-only and protection is restored during unwinding;
a restoration failure aborts. Close/drop wipes and frees memory. The handle is
neither Send nor Sync; it is not encrypted between uses. It has no serialization,
Clone, or key-export method; caller callbacks can still deliberately copy bytes.
Native library/toolchain requirements apply. Tests here used pkg-config with
libsodium 1.0.22; vendored native builds and Windows were not validated.

## Deployment and acceptance

- Apply `LimitCORE=0` and an initial `LimitMEMLOCK=8M` to API/MCP/agent services;
  `deploy/secure-memory.service.conf` is a systemd example, not automatically
  installed. The agent unit and document Compose overlay include these limits.
  Containers use `core=0:0` and `memlock=8388608:8388608`. Ordinary limits suffice;
  do not grant broad capabilities to bypass a failed lock.
- Locked allocations round up to OS pages and add guard-page virtual mappings.
  Measure peak concurrency and key/token count before increasing the budget.
  Explicitly close clients; idle locked allocations persist until destruction.
- Keep heap profiles, crash collection, ptrace permissions, swap/hibernation, and
  core policies restricted. Review Vault's deployed locking separately. This
  change neither configures every host nor disables swap for every process.
- Test with normal limits and intentionally insufficient limits. First-allocation
  failure and one-success-then-exhaustion subprocess tests must fail promptly,
  wipe input and reject stale handles. No test changes the parent shell's limits.
- Roll back all affected binaries together if required; wire protocols, document
  envelopes and agent identity files are unchanged. No memory-related migration.

## Verification and references

Meaningful tests include ownership wiping/redaction, callback errors/panics,
concurrent buffer copy, destroyed-handle rejection, actual zero/partial memlock
exhaustion with deadlines, provider rotation and close races, operation-only
signing contracts, Rust panic cleanup and native lock refusal. Linux container
checks and macOS checks are recorded in the integration handoff. No Windows
runtime validation or claim of complete memory-dump resistance.

Primary references: [MemGuard](https://github.com/awnumar/memguard),
[libsodium memory management](https://doc.libsodium.org/memory_management),
[secrecy](https://docs.rs/secrecy/0.10.3/secrecy/),
[zeroize](https://docs.rs/zeroize/1.9.0/zeroize/),
[Node secure heap](https://nodejs.org/api/cli.html#--secure-heapn).
