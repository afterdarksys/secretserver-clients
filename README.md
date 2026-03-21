# SecretServer.io Client Libraries

Official client libraries for [SecretServer.io](https://secretserver.io) — enterprise secret management.

## ⚠️ Current Implementation Status

**As of 2026-03-21**, the SecretServer.io API is in **partial implementation**:

### ✅ What Works
- **API Key Authentication** - Create and manage API keys
- **Core Secret Management** - Create, read, update, delete secrets
- **Path-based Access** - Access secrets by container/key path
- **Version History** - Access historical versions of secrets

### ❌ What Doesn't Work Yet
- Certificate management (enroll, renew, revoke)
- SSH key generation
- GPG key operations
- Password generation
- Extended credential types (WiFi, Computer, Windows, Social, Disk, etc.)
- Intelligence features (breach detection)
- Export operations (Keychain, Credential Manager)

**For full implementation status**, see [API_IMPLEMENTATION_STATUS.md](https://github.com/afterdarksys/secretserver.io/blob/main/API_IMPLEMENTATION_STATUS.md) in the server repository.

**The examples below show the intended API**. Only the secret management examples will work with the current implementation.

---

## Libraries

| Language | Directory | Install | Package |
|----------|-----------|---------|---------|
| **Python** | `python/` | `pip install secretserver` | [PyPI](https://pypi.org/project/secretserver) |
| **Node.js / TypeScript** | `node/` | `npm install secretserver` | [npm](https://npmjs.com/package/secretserver) |
| **PHP** | `php/` | `composer require afterdark/secretserver` | [Packagist](https://packagist.org/packages/afterdark/secretserver) |
| **Go** | `go/` | `go get github.com/afterdarksys/secretserver-go` | [pkg.go.dev](https://pkg.go.dev/github.com/afterdarksys/secretserver-go) |
| **Ansible** | `ansible/` | Drop `secretserver.py` in your lookup_plugins/ | — |

---

## Quick Start

### Python

```python
from secretserver import SecretServerClient

ss = SecretServerClient(api_key="sk_...")
# or set SS_API_KEY in your environment

# Get a secret value
db_password = ss.secret("production/db-password")

# Get a specific version (2 = previous)
old_password = ss.secret("production/db-password/2")

# Full secret metadata
secret = ss.get_secret("production/db-password")

# Share with a colleague
ss.share("passwords", secret["id"], "colleague@company.com", expires_hours=24)

# Generate a temp access token
grant = ss.create_temp_access("passwords", secret["id"], duration_seconds=900)
print(grant["token"])
```

### Node.js / TypeScript

```typescript
import { SecretServerClient } from "secretserver";

const ss = new SecretServerClient({ apiKey: process.env.SS_API_KEY });

// Path-based lookup
const dbPassword = await ss.secret("production/db-password");

// List all certificates
const certs = await ss.listCertificates();

// Generate SSH key
const key = await ss.generateSSHKey("deploy-key", "ed25519");

// Extended credential types
const computers = await ss.computerCredentials.list();
await ss.computerCredentials.create({
  name: "web-server-01",
  hostname: "web01.internal",
  ip_address: "10.0.0.10",
  os_type: "linux",
  admin_user: "admin",
  password: "secure-password",
});
```

### PHP

```php
use SecretServer\SecretServerClient;

$ss = new SecretServerClient(getenv('SS_API_KEY'));

// Get a secret
$dbPassword = $ss->secret('production/db-password');

// Enroll a certificate
$cert = $ss->enrollCertificate('wildcard-prod', '*.example.com', ['example.com'], true);

// Use extended credential types
$wifiCreds = $ss->credentials('wifi-credentials');
$networks = $wifiCreds->list();
$wifiCreds->create([
    'name' => 'Office WiFi',
    'ssid' => 'Corp-Network',
    'password' => 'wifi-password',
    'security_protocol' => 'WPA3',
]);
```

### Go

```go
import ss "github.com/afterdarksys/secretserver-go/secretserver"

client, err := ss.NewClient(&ss.Config{
    APIKey: os.Getenv("SS_API_KEY"),
})

// Get a secret
secret, err := client.Secrets.Get(ctx, "production/db-password", nil)
fmt.Println(secret.Data["value"])

// Generate an SSH key
key, err := client.SSHKeys.Generate(ctx, &ss.GenerateSSHKeyRequest{
    Name:    "deploy-key",
    KeyType: "ed25519",
})
```

### Ansible

```yaml
- name: Deploy application
  hosts: webservers
  vars:
    db_password: "{{ lookup('secretserver', 'production/db-password') }}"
    api_key: "{{ lookup('secretserver', 'production/stripe-key') }}"
  tasks:
    - name: Write config
      template:
        src: app.conf.j2
        dest: /etc/app/app.conf
      no_log: true
```

---

## Authentication

All libraries support two auth methods:

| Method | How |
|--------|-----|
| Environment variable | `export SS_API_KEY=sk_...` |
| Constructor argument | `SecretServerClient(api_key="sk_...")` |

API keys are created in the SecretServer dashboard under **Settings → API Keys**.

---

## Permissions

API keys carry scopes. Ensure your key has the right permissions:

| Scope | What it grants |
|-------|----------------|
| `secrets:read/write/delete` | Generic secrets |
| `credentials:read/write/delete` | All extended credential types |
| `containers:read/write` | Container namespaces |
| `certs:read/write/revoke` | TLS certificates |
| `ssh:read/write` | SSH keys |
| `gpg:read/write` | GPG keys |
| `passwords:read/write` | Passwords |
| `tokens:read/write` | API tokens |
| `history:read` | Version history |
| `sharing:manage` | Share management |
| `temp-access:create` | Temp access tokens |
| `export:read` | Key/cert export |
| `transform:use` | Encode/decode |
| `intelligence:read` | Breach detection |
| `saml:read/write` | SAML federation |
| `oidc:read/write` | OIDC clients/tokens |
| `audit:read` | Audit logs |
| `admin:*` | All permissions |

---

## Keeping Libraries Up to Date

This repo is kept in sync with the main [secretserver.io](https://github.com/afterdarksys/secretserver.io) server repo using:

```bash
# Pull latest Go SDK and Ansible plugin from the server repo
SOURCE=/path/to/secretserver.io ./scripts/sync.sh
```

The sync script:
- Copies `pkg/sdk/*.go` → `go/secretserver/` (fixes package declaration)
- Copies `ansible/plugins/lookup/secretserver.py` → `ansible/`
- Extracts permission constants to `docs/permissions.txt`
- Auto-commits any changes

---

## Install Scripts

```bash
# Python
bash scripts/install-python.sh

# Node.js (builds TypeScript → dist/)
bash scripts/install-node.sh

# PHP (runs composer install)
bash scripts/install-php.sh

# Go (prints instructions)
bash scripts/install-go.sh
```

---

## Links

- [SecretServer.io](https://secretserver.io)
- [API Documentation](https://secretserver.io/docs/api)
- [CLI Documentation](https://secretserver.io/docs/cli)
- [Daemon (ssd) Documentation](https://secretserver.io/docs/daemon)
- [GitHub — Server](https://github.com/afterdarksys/secretserver.io)
- [GitHub — Clients](https://github.com/afterdarksys/secretserver-clients)
