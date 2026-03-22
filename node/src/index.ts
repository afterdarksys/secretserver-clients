/**
 * SecretServer.io Node.js / TypeScript client library.
 *
 * Works in Node.js 18+ (native fetch) and in any fetch-compatible environment.
 * Zero external dependencies.
 *
 * @example
 * ```ts
 * import { SecretServerClient } from "secretserver";
 *
 * const ss = new SecretServerClient({ apiKey: process.env.SS_API_KEY });
 * const value = await ss.secret("production/db-password");
 * ```
 */

export class SecretServerError extends Error {
  constructor(message: string, public statusCode = 0) {
    super(message);
    this.name = "SecretServerError";
  }
}
export class AuthError extends SecretServerError { constructor(m: string) { super(m, 401); this.name = "AuthError"; } }
export class PermissionError extends SecretServerError { constructor(m: string) { super(m, 403); this.name = "PermissionError"; } }
export class NotFoundError extends SecretServerError { constructor(m: string) { super(m, 404); this.name = "NotFoundError"; } }

export interface ClientConfig {
  /** API key — also reads SS_API_KEY from process.env */
  apiKey?: string;
  /** Base URL — defaults to https://api.secretserver.io */
  apiUrl?: string;
  /** Custom fetch implementation (default: global fetch) */
  fetchFn?: typeof fetch;
}

export interface Secret {
  id: string;
  name: string;
  description?: string;
  data: Record<string, string>;
  tags?: string[];
  version: number;
  created_at: string;
  updated_at: string;
}

export interface Container {
  id: string;
  name: string;
  slug: string;
  description?: string;
  created_at: string;
}

export interface Certificate {
  id: string;
  name: string;
  common_name: string;
  issuer: string;
  not_before: string;
  not_after: string;
  auto_renew: boolean;
}

export interface SSHKey {
  id: string;
  name: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
}

export interface Password {
  id: string;
  name: string;
  username: string;
  url?: string;
  created_at: string;
}

export interface VersionEntry {
  version_num: number;
  created_by: string;
  created_at: string;
}

export interface ShareResult {
  id: string;
  shared_with_email: string;
  permission: "read" | "manage";
  expires_at?: string;
}

export interface TempAccessResult {
  token: string;
  expires_at: string;
}

export interface TOTPToken {
  id: string;
  name: string;
  issuer: string;
  account_name: string;
  algorithm: string;
  digits: number;
  period: number;
  created_at: string;
  updated_at: string;
}

export interface TOTPCode {
  code: string;
  expires_in: number;
}

export interface TOTPExport {
  uri: string;
  qr_code: string;
}

const DEFAULT_URL = "https://api.secretserver.io";
const USER_AGENT = "secretserver-node/1.2.0";

export class SecretServerClient {
  private readonly apiKey: string;
  private readonly apiUrl: string;
  private readonly fetchFn: typeof fetch;

  constructor(config: ClientConfig = {}) {
    this.apiKey = config.apiKey ?? process.env.SS_API_KEY ?? "";
    this.apiUrl = (config.apiUrl ?? process.env.SS_API_URL ?? DEFAULT_URL).replace(/\/$/, "");
    this.fetchFn = config.fetchFn ?? fetch;

    if (!this.apiKey) {
      throw new AuthError("No API key provided. Set apiKey or SS_API_KEY env var.");
    }
  }

  // -----------------------------------------------------------------------
  // HTTP core
  // -----------------------------------------------------------------------

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.apiKey}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
    };
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.apiUrl}/api/v1${path}`;
    const res = await this.fetchFn(url, {
      method,
      headers: this.headers(),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    const text = await res.text();
    let data: unknown;
    try { data = JSON.parse(text); } catch { data = text; }

    if (!res.ok) {
      const msg = (data as { error?: string })?.error ?? `HTTP ${res.status}`;
      if (res.status === 401) throw new AuthError(msg);
      if (res.status === 403) throw new PermissionError(msg);
      if (res.status === 404) throw new NotFoundError(msg);
      throw new SecretServerError(msg, res.status);
    }

    return data as T;
  }

  private get = <T>(path: string) => this.request<T>("GET", path);
  private post = <T>(path: string, body?: unknown) => this.request<T>("POST", path, body);
  private put = <T>(path: string, body?: unknown) => this.request<T>("PUT", path, body);
  private delete = <T>(path: string) => this.request<T>("DELETE", path);

  // -----------------------------------------------------------------------
  // Path-based secret access (primary interface)
  // -----------------------------------------------------------------------

  /** Get a secret value by path: "container/key" or "container/key/2" */
  async secret(path: string): Promise<string> {
    const parts = path.replace(/^\/|\/$/g, "").split("/");
    if (parts.length === 1) {
      const d = await this.get<{ value?: string; data?: { value?: string } }>(`/secrets/${parts[0]}`);
      return d.value ?? d.data?.value ?? "";
    }
    const d = await this.get<{ value?: string }>(`/s/${parts.join("/")}`);
    return d.value ?? "";
  }

  /** Get full secret object by path */
  getSecret(path: string): Promise<Secret> {
    const parts = path.replace(/^\/|\/$/g, "").split("/");
    if (parts.length === 1) return this.get(`/secrets/${parts[0]}`);
    return this.get(`/s/${parts.join("/")}`);
  }

  // -----------------------------------------------------------------------
  // Secrets
  // -----------------------------------------------------------------------

  listSecrets(): Promise<Secret[]> { return this.get("/secrets"); }

  createSecret(name: string, value: string, opts: { description?: string; containerID?: string } = {}): Promise<Secret> {
    return this.post("/secrets", {
      name,
      data: { value },
      description: opts.description,
      container_id: opts.containerID,
    });
  }

  updateSecret(name: string, value: string): Promise<Secret> {
    return this.put(`/secrets/${name}`, { data: { value } });
  }

  deleteSecret(name: string): Promise<void> { return this.delete(`/secrets/${name}`); }

  // -----------------------------------------------------------------------
  // Containers
  // -----------------------------------------------------------------------

  listContainers(): Promise<Container[]> { return this.get("/containers"); }

  createContainer(name: string, slug?: string, description?: string): Promise<Container> {
    return this.post("/containers", { name, slug, description });
  }

  // -----------------------------------------------------------------------
  // Certificates
  // -----------------------------------------------------------------------

  listCertificates(): Promise<Certificate[]> { return this.get("/certificates"); }
  getCertificate(id: string): Promise<Certificate> { return this.get(`/certificates/${id}`); }

  enrollCertificate(name: string, commonName: string, sans: string[] = [], autoRenew = true): Promise<Certificate> {
    return this.post("/certificates/enroll", { name, common_name: commonName, sans, auto_renew: autoRenew });
  }

  renewCertificate(id: string): Promise<Certificate> { return this.post(`/certificates/${id}/renew`); }
  downloadCertificate(id: string): Promise<{ pem: string }> { return this.get(`/certificates/${id}/download`); }

  // -----------------------------------------------------------------------
  // SSH Keys
  // -----------------------------------------------------------------------

  listSSHKeys(): Promise<SSHKey[]> { return this.get("/ssh-keys"); }

  generateSSHKey(name: string, keyType: "rsa" | "ed25519" | "ecdsa" = "ed25519", comment?: string): Promise<SSHKey> {
    return this.post("/ssh-keys/generate", { name, key_type: keyType, comment });
  }

  importSSHKey(name: string, privateKey: string): Promise<SSHKey> {
    return this.post("/ssh-keys/import", { name, private_key: privateKey });
  }

  exportSSHKey(id: string): Promise<{ public_key: string; private_key: string }> {
    return this.get(`/ssh-keys/${id}/export`);
  }

  // -----------------------------------------------------------------------
  // Passwords
  // -----------------------------------------------------------------------

  listPasswords(): Promise<Password[]> { return this.get("/passwords"); }

  createPassword(name: string, username: string, password: string, url?: string): Promise<Password> {
    return this.post("/passwords", { name, username, password, url });
  }

  generatePassword(length = 32, includeSymbols = true): Promise<{ password: string }> {
    return this.post("/passwords/generate", { length, include_symbols: includeSymbols });
  }

  // -----------------------------------------------------------------------
  // API Tokens
  // -----------------------------------------------------------------------

  listAPITokens(): Promise<unknown[]> { return this.get("/api-tokens"); }
  createAPIToken(name: string, service: string, token: string): Promise<unknown> {
    return this.post("/api-tokens", { name, service, token });
  }
  rotateAPIToken(id: string): Promise<unknown> { return this.post(`/api-tokens/${id}/rotate`); }

  // -----------------------------------------------------------------------
  // GPG Keys
  // -----------------------------------------------------------------------

  listGPGKeys(): Promise<unknown[]> { return this.get("/gpg-keys"); }
  generateGPGKey(name: string, email: string, opts: { keyType?: string; expiresInDays?: number } = {}): Promise<unknown> {
    return this.post("/gpg-keys/generate", { name, email, key_type: opts.keyType, expires_in_days: opts.expiresInDays });
  }
  exportGPGKey(id: string): Promise<{ public_key: string; private_key: string }> {
    return this.get(`/gpg-keys/${id}/export`);
  }

  deleteGPGKey(id: string): Promise<void> { return this.delete(`/gpg-keys/${id}`); }

  // -----------------------------------------------------------------------
  // Extended credential types (read + write)
  // -----------------------------------------------------------------------

  private credAPI(resource: string) {
    return {
      list: () => this.get<unknown[]>(`/${resource}`),
      get: (id: string) => this.get<unknown>(`/${resource}/${id}`),
      create: (data: unknown) => this.post<unknown>(`/${resource}`, data),
      update: (id: string, data: unknown) => this.put<unknown>(`/${resource}/${id}`, data),
      delete: (id: string) => this.delete<void>(`/${resource}/${id}`),
    };
  }

  get computerCredentials() { return this.credAPI("computer-credentials"); }
  get wifiCredentials() { return this.credAPI("wifi-credentials"); }
  get windowsCredentials() { return this.credAPI("windows-credentials"); }
  get socialCredentials() { return this.credAPI("social-credentials"); }
  get diskCredentials() { return this.credAPI("disk-credentials"); }
  get serviceConfig() { return this.credAPI("service-config"); }
  get rootCredentials() { return this.credAPI("root-credentials"); }
  get ldapBindCredentials() { return this.credAPI("ldap-bind-credentials"); }
  get integrations() { return this.credAPI("integrations"); }
  get codeSigningKeys() { return this.credAPI("code-signing-keys"); }

  // -----------------------------------------------------------------------
  // Version history
  // -----------------------------------------------------------------------

  async getHistory(secretType: string, secretId: string): Promise<VersionEntry[]> {
    const d = await this.get<{ versions?: VersionEntry[] }>(`/${secretType}/${secretId}/history`);
    return d.versions ?? [];
  }

  getVersion(secretType: string, secretId: string, version: number): Promise<unknown> {
    return this.get(`/${secretType}/${secretId}/history/${version}`);
  }

  getHistorySettings(secretType: string, secretId: string): Promise<{ history_enabled: boolean; max_versions: number }> {
    return this.get(`/${secretType}/${secretId}/history-settings`);
  }

  updateHistorySettings(secretType: string, secretId: string, enabled: boolean, maxVersions: number): Promise<unknown> {
    return this.put(`/${secretType}/${secretId}/history-settings`, { history_enabled: enabled, max_versions: maxVersions });
  }

  // -----------------------------------------------------------------------
  // Sharing & temp access
  // -----------------------------------------------------------------------

  share(
    secretType: string,
    secretId: string,
    email: string,
    permission: "read" | "manage" = "read",
    expiresAt?: Date,
  ): Promise<ShareResult> {
    return this.post(`/${secretType}/${secretId}/shares`, {
      shared_with_email: email,
      permission,
      expires_at: expiresAt?.toISOString(),
    });
  }

  createTempAccess(secretType: string, secretId: string, durationSeconds = 900): Promise<TempAccessResult> {
    return this.post(`/${secretType}/${secretId}/temp-access`, { duration_seconds: durationSeconds });
  }

  // -----------------------------------------------------------------------
  // Intelligence & transform
  // -----------------------------------------------------------------------

  checkBreach(value: string): Promise<{ breached: boolean; sources?: string[] }> {
    return this.post("/intelligence/check-breach", { value });
  }

  encode(data: string, format = "base64"): Promise<{ result: string }> {
    return this.post("/transform/encode", { data, format });
  }

  decode(data: string, format = "base64"): Promise<{ result: string }> {
    return this.post("/transform/decode", { data, format });
  }

  // -----------------------------------------------------------------------
  // Audit
  // -----------------------------------------------------------------------

  getAuditLogs(opts: { limit?: number; offset?: number; action?: string } = {}): Promise<{ logs: unknown[]; total: number }> {
    const q = new URLSearchParams(opts as Record<string, string>).toString();
    return this.get(`/audit/logs${q ? `?${q}` : ""}`);
  }

  exportAuditLogs(): Promise<unknown> { return this.get("/audit/logs/export"); }

  // -----------------------------------------------------------------------
  // OpenSSL Keys
  // -----------------------------------------------------------------------

  listOpenSSLKeys(): Promise<unknown[]> { return this.get("/openssl-keys"); }
  getOpenSSLKey(id: string): Promise<unknown> { return this.get(`/openssl-keys/${id}`); }

  generateOpenSSLKey(name: string, keyType = "rsa", bits = 4096): Promise<unknown> {
    return this.post("/openssl-keys/generate", { name, key_type: keyType, bits });
  }

  importOpenSSLKey(name: string, privateKey: string): Promise<unknown> {
    return this.post("/openssl-keys/import", { name, private_key: privateKey });
  }

  exportOpenSSLKey(id: string): Promise<{ public_key: string; private_key: string }> {
    return this.get(`/openssl-keys/${id}/export`);
  }

  deleteOpenSSLKey(id: string): Promise<void> { return this.delete(`/openssl-keys/${id}`); }

  // -----------------------------------------------------------------------
  // NTLM Hashes
  // -----------------------------------------------------------------------

  listNTLMHashes(): Promise<unknown[]> { return this.get("/ntlm"); }
  getNTLMHash(id: string): Promise<unknown> { return this.get(`/ntlm/${id}`); }

  createNTLMHash(name: string, username: string, hash: string): Promise<unknown> {
    return this.post("/ntlm", { name, username, hash });
  }

  updateNTLMHash(id: string, data: unknown): Promise<unknown> {
    return this.put(`/ntlm/${id}`, data);
  }

  deleteNTLMHash(id: string): Promise<void> { return this.delete(`/ntlm/${id}`); }

  // -----------------------------------------------------------------------
  // Certificates (extended operations)
  // -----------------------------------------------------------------------

  revokeCertificate(id: string): Promise<unknown> { return this.post(`/certificates/${id}/revoke`); }

  // -----------------------------------------------------------------------
  // Webhooks
  // -----------------------------------------------------------------------

  listWebhooks(): Promise<unknown[]> { return this.get("/webhooks"); }

  createWebhook(name: string, url: string, events: string[], authType = "none"): Promise<unknown> {
    return this.post("/webhooks", { name, url, events, auth_type: authType });
  }

  listWebhookDeliveries(webhookId: string): Promise<unknown[]> {
    return this.get(`/webhooks/${webhookId}/deliveries`);
  }

  testWebhook(webhookId: string): Promise<unknown> {
    return this.post(`/webhooks/${webhookId}/test`);
  }

  // -----------------------------------------------------------------------
  // Export
  // -----------------------------------------------------------------------

  exportToKeychain(items: unknown[]): Promise<unknown> {
    return this.post("/export/keychain", { items });
  }

  exportToCredentialManager(items: unknown[]): Promise<unknown> {
    return this.post("/export/credential-manager", { items });
  }

  exportToJSON(items: unknown[]): Promise<unknown> {
    return this.post("/export/json", { items });
  }

  // -----------------------------------------------------------------------
  // TOTP Authenticators
  // -----------------------------------------------------------------------

  /** List all TOTP authenticator tokens */
  listTOTPTokens(): Promise<TOTPToken[]> { return this.get("/totp-tokens"); }

  /** Get a specific TOTP token by ID */
  getTOTPToken(id: string): Promise<TOTPToken> { return this.get(`/totp-tokens/${id}`); }

  /**
   * Create a new TOTP token
   *
   * @param name Display name for the token
   * @param issuer Issuer name (e.g., "GitHub", "AWS")
   * @param accountName Account identifier (e.g., email or username)
   * @param secretKey Base32-encoded secret key
   * @param opts Optional parameters (algorithm, digits, period)
   */
  createTOTPToken(
    name: string,
    issuer: string,
    accountName: string,
    secretKey: string,
    opts: { algorithm?: string; digits?: number; period?: number } = {}
  ): Promise<TOTPToken> {
    return this.post("/totp-tokens", {
      name,
      issuer,
      account_name: accountName,
      secret_key: secretKey,
      algorithm: opts.algorithm ?? "SHA1",
      digits: opts.digits ?? 6,
      period: opts.period ?? 30,
    });
  }

  /** Update a TOTP token */
  updateTOTPToken(id: string, data: Partial<Omit<TOTPToken, "id" | "created_at" | "updated_at">>): Promise<TOTPToken> {
    return this.put(`/totp-tokens/${id}`, data);
  }

  /** Delete a TOTP token */
  deleteTOTPToken(id: string): Promise<void> { return this.delete(`/totp-tokens/${id}`); }

  /**
   * Generate a TOTP code for the given token
   *
   * Returns an object with 'code' and 'expires_in' (seconds remaining)
   */
  generateTOTPCode(id: string): Promise<TOTPCode> {
    return this.post(`/totp-tokens/${id}/generate`);
  }

  /**
   * Import a TOTP token from an otpauth:// URI
   *
   * @param uri otpauth://totp/... URI string
   * @returns The created TOTP token
   */
  importTOTPFromURI(uri: string): Promise<TOTPToken> {
    return this.post("/totp-tokens/import", { uri });
  }

  /**
   * Export a TOTP token to an otpauth:// URI
   *
   * Returns an object with 'uri' and 'qr_code' (base64-encoded PNG)
   */
  exportTOTPToURI(id: string): Promise<TOTPExport> {
    return this.get(`/totp-tokens/${id}/export`);
  }
}

export default SecretServerClient;
