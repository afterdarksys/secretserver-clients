# Secret Server memory foundation

Unpublished Rust building block; no full Rust SDK or existing production consumer.
See [the cross-runtime contract](../../docs/MEMORY_PROTECTION.md).

```rust
use secretserver_memory::GuardedSecret;
let mut secret = GuardedSecret::consume(vec![1, 2, 3])?;
secret.with_bytes(|bytes| assert_eq!(bytes.len(), 3))?;
secret.close();
# Ok::<(), secretserver_memory::Error>(())
```

Default `guarded` feature uses libsodium. The explicitly checked lock must succeed;
there is no heap fallback. Pages are inaccessible between immutable callback
borrows and are wiped/freed on close/drop. This is not encrypted memory. The handle
is neither Send nor Sync. `SecretBytes` is the secrecy/zeroize heap-only alternative;
`--no-default-features` excludes the native dependency. Both consume input ownership,
reject empty/over-1-MiB inputs, redact Debug, and do not implement Clone/Serialize.
Do not retain/copy secret data or convert it to strings inside a callback.

Tested on macOS with installed libsodium 1.0.22:

```sh
SODIUM_USE_PKG_CONFIG=1 cargo test
SODIUM_USE_PKG_CONFIG=1 cargo test --no-default-features
```

Provide pkg-config and libsodium development files for that build mode. Review the
pinned libsodium-sys-stable build instructions for other toolchains. Vendored native
builds and Windows have not been validated. Enforce core=0 and an adequate memlock
limit. Allocation/protection failure is an error; failure to restore page protection
aborts rather than silently leaving a view accessible.
