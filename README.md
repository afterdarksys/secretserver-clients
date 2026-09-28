# SecretServer.io Client Libraries

Official client libraries for [SecretServer.io](https://secretserver.io) — enterprise secret management.

**📦 [Download from GitHub](https://github.com/afterdarksys/secretserver-clients/releases) | [View Source](https://github.com/afterdarksys/secretserver-clients)**

> **Minimum server for updates: secretserver.io `3075630`.** Secret, JKS keystore
> and YubiKey updates are partial and are refused unless you opt in
> (`partial_updates` / `partialUpdates` / `Config.PartialUpdates` /
> `SS_PARTIAL_UPDATES=1`) or pass an ETag returned by the server. See
> [CLIENT_COMPATIBILITY_VERIFIED.md](CLIENT_COMPATIBILITY_VERIFIED.md) for the
> breaking changes and migration notes.

## REST API compatibility

The clients target the authenticated REST API under `/api/v1`. Python, Node.js,
PHP, and Go also expose a generic authenticated request method so newly added
REST endpoints remain usable before a typed convenience method is released:

- Python: `client.request(method, path, body)`
- Node.js: `client.request<T>(method, path, body)`
- PHP: `$client->request($method, $path, $body)`
- Go: `client.Call(ctx, method, path, body, &result)`

Base URLs may be configured with or without the `/api/v1` suffix. GraphQL and
gRPC schemas in the backend are design artifacts and are not client transports.

The backend REST surface includes:

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

Typed helpers include secret CRUD and path access, certificates, credentials,
TOTP and YubiKey OTP, JKS keystores, and operation-only HSM signing.

---

## Libraries

| Language | Directory | Install | Package | GitHub |
|----------|-----------|---------|---------|--------|
| **Python** | `python/` | `pip install secretserver` | [PyPI](https://pypi.org/project/secretserver) | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/python) |
| **Node.js / TypeScript** | `node/` | `npm install secretserver` | [npm](https://npmjs.com/package/secretserver) | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/node) |
| **PHP** | `php/` | `composer require afterdark/secretserver` | [Packagist](https://packagist.org/packages/afterdark/secretserver) | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/php) |
| **Go** | `go/` | `go get github.com/afterdarksys/secretserver-clients/go` | [pkg.go.dev](https://pkg.go.dev/github.com/afterdarksys/secretserver-clients/go) | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/go) |
| **Ansible** | `ansible/` | Drop `secretserver.py` in your lookup_plugins/ | — | [Download](https://github.com/afterdarksys/secretserver-clients/tree/main/ansible) |
| **MCP** | `mcp/` | `go build -o secretserver-mcp .` | stdio MCP server | [Source](https://github.com/afterdarksys/secretserver-clients/tree/main/mcp) |
| **Agent Skills** | `skills/` | Copy the appropriate skill folder | Claude Code and Codex | [Source](https://github.com/afterdarksys/secretserver-clients/tree/main/skills) |
| **Offline Cache Service** | `secretserver-cache-service/` | Architecture/design package | Device-bound encrypted lease cache | [Source](https://github.com/afterdarksys/secretserver-clients/tree/main/secretserver-cache-service) |

**📥 [Download All Clients](https://github.com/afterdarksys/secretserver-clients/releases) | [Clone Repository](https://github.com/afterdarksys/secretserver-clients.git)**

### MCP and agent skills

The standalone MCP bridge provides operation-only access to non-exportable smart-card and HSM signing keys. It reads a short-lived `keys:sign` identity from an owner-only file and never returns private key material.

- Codex skill: `skills/codex/using-secretserver/`
- Claude Code skill: `skills/claude/using-secretserver/`
- MCP build and configuration: `mcp/README.md`

Install the skills for the current user:

```bash
cp -R skills/codex/using-secretserver ~/.codex/skills/
cp -R skills/claude/using-secretserver ~/.claude/skills/
```

The proposed `secretserver-cache-service/` defines a dashboard-authorized encrypted offline lease cache and the shared `--cache=off|prefer|required` client contract. It is currently a reviewed design package, not an operational daemon.

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

// Partial update: a key absent from $opts is kept, a key set to null is cleared.
// Pass the ETag from getSecret() as $ifMatch; a stale one throws ConflictException
// whose getETag() is the current ETag.
$record = $ss->getSecret('db-password');
$ss->updateSecret('db-password', 'new-value', ['description' => null], $record[SecretServerClient::ETAG_KEY]);

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
import ss "github.com/afterdarksys/secretserver-clients/go/secretserver"

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

<!-- go-partial-updates:begin -->
#### Go: partial updates

**Minimum server: secretserver.io 3075630 (partial, conditional updates).**
Older servers treat `PUT` on secrets and JKS keystores as a full replace and
ignore `If-Match`, so a partial body would blank every omitted field.
`Secrets.Update` and `JKS.Update` therefore return
`ss.ErrPartialUpdatesUnconfirmed`, without sending a request, unless either:

- the client opts in with `ss.Config{PartialUpdates: true}` (only for servers
  known to be 3075630 or newer), or
- the call passes an ETag from `Get` as `IfMatch` (a quoted `"..."` or
  `W/"..."` value; a version number, `*` or `ExpectedVersion` alone does not
  count).

```go
cur, err := client.Secrets.Get(ctx, "db", nil)
desc := "rotated"
_, err = client.Secrets.Update(ctx, "db", &ss.SecretUpdateRequest{Description: &desc, IfMatch: cur.ETag})
```

The Go SDK does not read `SS_PARTIAL_UPDATES`; set `Config.PartialUpdates`.
<!-- go-partial-updates:end -->

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

## Named secret variables

Assign a name such as `LOG_SERVER_TX1_S` to a credential field and resolve
`%%LOG_SERVER_TX1_S%%` through the shared server resolver. See the
[variable assignment guide](docs/VARIABLE_ASSIGNMENTS.md) for APIs, SDK methods, Ansible lookup,
Terraform ephemeral templates, CLI rendering, and agent grants.
