# Compatibility and supported contract

The development changes in these clients target the core platform contract in the sibling `secretserver.io` checkout. They are not yet published package releases.

Live validation covers Go, Python, TypeScript and PHP creating, reading by name and container path, updating and deleting generic secrets through the real API, Vault and PostgreSQL. Run the server repository's `scripts/test-platform-integration.sh` with these checkouts adjacent. This does not certify every convenience method, credential type or GUI workflow.

- Generic names are immutable. Bodies contain `data`, not a top-level `value`.
- Direct reads contain `data`; container path reads contain `{meta,data}`. Scalar helpers treat `data` as authoritative, preserve actual empty values and reject unsupported scalar shapes.
- Ordinary PUT helpers replace managed metadata. Supply the full desired record through the generic request/Call interface when retaining or changing tags/container/description.
- HTTP error messages omit server response bodies. Use typed status codes to distinguish denial/not-found. Mutations are not automatically retried; read current state after timeouts or audit failure before retrying.
- Default Go requests and Python/TypeScript requests refuse redirects. Caller-supplied Go HTTP clients are responsible for their own timeout/redirect policy. PHP uses cURL without follow-redirects.
- Go supports context cancellation. TypeScript has a configurable `timeoutMs`; Python/PHP accept timeout seconds. Transport and operating-system behavior still require deployment validation.
- API-key/JWT revocation and workload-binding disablement take effect on the next authenticated request. Offline cache design is not an implemented availability guarantee.
- New database credential and workload endpoints can be called through each client's generic REST interface; see the server operations contract for deployment bindings and scopes.

The Ansible lookup is mirrored from the server collection. Its consuming tasks must use `no_log: true`; a lookup does not automatically hide the returned value. Bare-name historical lookup is rejected; use a container/name/version path.
