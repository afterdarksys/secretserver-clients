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

This source checkout includes fixes not yet published. See the repository compatibility matrix for validation scope.
