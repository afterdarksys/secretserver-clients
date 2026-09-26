# SecretServer Python client

Python client for the SecretServer REST API. The client has no runtime dependencies outside the standard library.

```python
from secretserver import SecretServerClient

client = SecretServerClient(api_key="scoped-token", api_url="https://your-server.example")
client.create_secret("example", "value")
value = client.secret("example")
client.delete_secret("example")
```

Use protected configuration for credentials; avoid logging returned values. Path reads use `container/name`, and history uses `container/name/2`. Generic request helpers support newer REST endpoints. Requests have a configurable timeout and do not automatically retry mutations. HTTP failures expose a status code without echoing response bodies.

Transport policy: `api_url` must be `https://` (plain `http://` is accepted only for `localhost`, `127.0.0.1` or `::1`), URLs with embedded credentials are rejected, TLS 1.2 is the minimum and certificate verification cannot be disabled (`verify_ssl=False` raises `ValueError`). To trust a private CA pass `ca_file="/path/to/ca.pem"`; the bundle is added to the system trust store, so public CAs stay trusted. Redirects are never followed, JSON responses are capped at 4 MiB (raw downloads at 16 MiB), and every caller-supplied path segment is percent-encoded.

This source checkout includes fixes not yet published. See the repository compatibility matrix for validation scope.
