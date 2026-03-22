# SecretServer.io Client Libraries

Official client libraries for [SecretServer.io](https://secretserver.io) — enterprise secret management.

**📦 [Download from GitHub](https://github.com/afterdarksys/secretserver-clients/releases) | [View Source](https://github.com/afterdarksys/secretserver-clients)**

## ✅ Full API Implementation

**As of 2026-03-22**, the SecretServer.io API is **100% IMPLEMENTED** with **TOTP support**!

All 168 API endpoints are now fully functional in production:

- ✅ **Authentication** - API keys, OAuth2, OIDC, WebAuthn/Passkeys
- ✅ **Core Secret Management** - Full CRUD, versioning, path-based access
- ✅ **Certificate Management** - Enroll, renew, revoke, download (PEM, PFX, JKS)
- ✅ **SSH Keys** - Generate (RSA, Ed25519, ECDSA), import, export
- ✅ **GPG Keys** - Generate, import, export, encrypt, decrypt, sign
- ✅ **Passwords** - Generate strong passwords, store, retrieve
- ✅ **API Tokens** - Store third-party tokens (Stripe, AWS, GitHub, etc.)
- ✅ **TOTP Authenticators** - Backup Google/Microsoft/Oracle Authenticator tokens **NEW!**
- ✅ **Extended Credentials** - 12 types (Computer, WiFi, Windows, Social, Disk, etc.)
- ✅ **Containers** - Namespace management
- ✅ **Sharing** - Share secrets with users/groups
- ✅ **Temp Access** - Time-limited access tokens
- ✅ **Export** - macOS Keychain, Windows Credential Manager, JSON
- ✅ **Transform** - Encode/decode/detect formats
- ✅ **Intelligence** - Breach detection with Have I Been Pwned
- ✅ **Extraction** - Secret discovery in files/databases
- ✅ **LDAP** - Import/export users
- ✅ **Audit** - Complete audit logs with CSV/JSON export
- ✅ **SAML** - Metadata and assertion management
- ✅ **OIDC** - Client, token, and JWKS management

**All client library examples below are now fully functional!** 🎉

---

## Libraries

| Language | Directory | Install | Package | GitHub |
|----------|-----------|---------|---------|--------|
| **Python** | `python/` | `pip install secretserver` | [PyPI](https://pypi.org/project/secretserver) | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/python) |
| **Node.js / TypeScript** | `node/` | `npm install secretserver` | [npm](https://npmjs.com/package/secretserver) | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/node) |
| **PHP** | `php/` | `composer require afterdark/secretserver` | [Packagist](https://packagist.org/packages/afterdark/secretserver) | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/php) |
| **Go** | `go/` | `go get github.com/afterdarksys/secretserver-go` | [pkg.go.dev](https://pkg.go.dev/github.com/afterdarksys/secretserver-go) | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/go) |
| **Ansible** | `ansible/` | Drop `secretserver.py` in your lookup_plugins/ | — | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/ansible) |

**📥 [Download All Clients](https://github.com/afterdarksys/secretserver-clients/releases) | [Clone Repository](https://github.com/afterdarksys/secretserver-clients.git)**

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

# TOTP Authenticator (NEW!)
# Backup your Google Authenticator / Microsoft Authenticator tokens
totp = ss.create_totp_token(
    name="AWS Production",
    issuer="Amazon Web Services",
    account_name="admin@company.com",
    secret_key="JBSWY3DPEHPK3PXP"
)
code = ss.generate_totp_code(totp["id"])
print(f"Current code: {code['code']}")  # 6-digit code
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

// TOTP Authenticator (NEW!)
// Backup Google Authenticator / Microsoft Authenticator tokens
const totp = await ss.createTOTPToken(
  "AWS Production",
  "Amazon Web Services",
  "admin@company.com",
  "JBSWY3DPEHPK3PXP"
);
const code = await ss.generateTOTPCode(totp.id);
console.log(`Current code: ${code.code}`);  // 6-digit code
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

// TOTP Authenticator (NEW!)
// Backup Google Authenticator / Microsoft Authenticator tokens
$totp = $ss->createTOTPToken(
    'AWS Production',
    'Amazon Web Services',
    'admin@company.com',
    'JBSWY3DPEHPK3PXP'
);
$code = $ss->generateTOTPCode($totp['id']);
echo "Current code: {$code['code']}\n";  // 6-digit code
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
