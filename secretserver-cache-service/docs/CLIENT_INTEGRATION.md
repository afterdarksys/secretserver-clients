# Client integration contract

## Shared options

All SecretServer CLIs and SDKs use the same modes:

- `off`: bypass the cache and use SecretServer normally. This is the default until the dashboard feature is enabled and a device is enrolled.
- `prefer`: query the local cache for eligible resources; on miss, expiry, or unavailable daemon, use the normal authenticated remote request.
- `required`: query only the local cache and fail closed on any miss, expiry, provenance failure, or daemon error.

CLI flag:

```text
--cache=off|prefer|required
```

SDK fields:

- Go: `CacheMode CacheMode`.
- Node/TypeScript: `cacheMode: "off" | "prefer" | "required"`.
- Python: `cache_mode: Literal["off", "prefer", "required"]`.
- PHP: `cache_mode => 'off'|'prefer'|'required'`.

Environment fallback: `SS_CACHE_MODE`. Explicit constructor or CLI configuration wins.

There is deliberately no cache TTL, secret-set, renewal, encryption-key, or populate option.

## Endpoint discovery

Production clients use fixed OS locations installed by the signed package:

- Linux: `/run/secretserver-cache/daemon.sock`.
- macOS: `/var/run/secretserver-cache/daemon.sock`.
- Windows: `\\.\pipe\secretserver-cache`.

Do not support arbitrary remote URLs. A test-only endpoint override may exist behind an explicit build tag or test constructor and must never be read from ordinary production environment variables.

Clients verify:

- Local transport and expected daemon owner.
- Daemon identity or signed lease provenance.
- Tenant, resource ID, resource version, policy hash, and expiry in the response proof.
- Response size and content type.

## Lookup behavior

1. Determine whether the operation is cache-eligible. Writes, deletes, rotations, revocations, exports, and signing operations are never generic cache reads.
2. Send resource type, canonical resource ID/name, requested version, and acceptable delivery mode.
3. Verify returned provenance before exposing the value to the caller.
4. Never log or include the value in an error.
5. `prefer` may fall back remotely but never writes the remote result into the local cache.

Cache eligibility and TTL come only from the signed dashboard policy. A locally selected `prefer` or `required` mode cannot enable caching when the server policy is disabled.

## Rollout to existing clients

1. Add shared mode parsing and fixed endpoint discovery with cache defaulted to `off`.
2. Add a local transport abstraction and provenance model.
3. Implement metadata/status calls.
4. Implement cache reads only after daemon protocol conformance tests pass.
5. Add cross-language contract tests using the same signed fixtures.
6. Expose CLI flags last, after all SDKs fail identically on expiry, rollback, and invalid provenance.
