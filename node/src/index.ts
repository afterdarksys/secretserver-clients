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
  /**
   * Base URL — defaults to https://api.secretserver.io. Must be https; plain
   * http is accepted only for loopback hosts (localhost, 127.0.0.1, ::1).
   * TLS verification is always on. To trust a private CA, start Node with
   * NODE_EXTRA_CA_CERTS=/path/to/ca.pem (Node's default TLS minimum is 1.2).
   */
  apiUrl?: string;
  /** Custom fetch implementation (default: global fetch) */
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}

export interface VariableAssignment { secret_type: string; secret_id: string; field: string; }
export interface Variable extends VariableAssignment { id: string; name: string; }

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
  qr_code?: string;
}

export interface YubikeyCredential {
  id: string;
  name: string;
  serial_number?: string;
  public_id: string;
  client_id: string;
  validation_server: string;
  notes?: string;
  tags?: string[];
  created_at: string;
  updated_at: string;
}

export interface YubikeyValidateResult {
  valid: boolean;
  public_id: string;
  checked_at: string;
}

export interface IntegrationProvider {
  id: string;
  display_name: string;
  category: string;
  required?: string[];
  optional?: string[];
  alternatives?: string[][];
}

export interface KeyCatalogItem {
  id: string;
  category: string;
  kind: string;
  maturity: string;
  formats?: string[];
  algorithms?: string[];
  non_exportable?: boolean;
  enabled_by_default: boolean;
}

export interface IntegrationCredential {
  id: string;
  name: string;
  provider: string;
  auth_type?: string;
  endpoint?: string;
  credentials?: Record<string, unknown>;
}

export interface CryptoBackend {
  backend: string;
  name: string;
  healthy: boolean;
  capabilities: Record<string, unknown>;
}

export interface SigningKey {
  id: string;
  label: string;
  algorithm: string;
  backend: string;
  metadata?: Record<string, string>;
}

export interface SignResult {
  signature: string;
  algorithm: string;
  key_id: string;
  audit_id: string;
}

export interface JKSKeystore {
  id: string;
  name: string;
  store_type: "raw" | "managed";
  entry_count?: number;
  notes?: string;
  tags?: string[];
  created_at?: string;
  updated_at?: string;
}

export interface JKSEntry {
  id: string;
  keystore_id?: string;
  alias: string;
  entry_type: "private_key" | "trusted_cert";
  subject?: string;
  not_before?: string;
  not_after?: string;
  fingerprint?: string;
  created_at?: string;
}

export interface CreateJKSKeystoreInput {
  name: string;
  store_type?: "raw" | "managed";
  jks?: string;
  password?: string;
  container_id?: string;
  notes?: string;
  tags?: string[];
}

export interface CreateJKSEntryInput {
  alias: string;
  entry_type: "private_key" | "trusted_cert";
  certificate: string;
  private_key?: string;
  cert_chain?: string;
  key_password?: string;
}

export interface JKSExport {
  jks: string;
  format?: "jks";
  filename?: string;
}

const DEFAULT_URL = "https://api.secretserver.io";
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_RAW_BYTES = 16 * 1024 * 1024;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function validateBaseUrl(raw: string): string {
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new SecretServerError("Invalid apiUrl"); }
  if (parsed.username || parsed.password) throw new SecretServerError("apiUrl must not contain credentials");
  if (parsed.protocol === "http:" && !LOOPBACK_HOSTS.has(parsed.hostname)) {
    throw new SecretServerError("apiUrl must use https (plain http is allowed only for loopback hosts)");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new SecretServerError("apiUrl must use https");
  if (parsed.search || parsed.hash) throw new SecretServerError("apiUrl must not contain a query or fragment");
  return raw;
}

/**
 * Percent-encode one caller-supplied path segment. Empty and dot segments are
 * rejected because URL normalisation would collapse them into a different route.
 */
function seg(value: string | number): string {
  const s = String(value);
  if (s === "" || s === "." || s === "..") throw new SecretServerError("Invalid path segment");
  return encodeURIComponent(s);
}

async function discardBody(res: Response): Promise<void> {
  // Best-effort release of the connection; the caller is already failing with a real error.
  if (res.body && typeof res.body.cancel === "function") await res.body.cancel().catch(() => undefined);
}

/** Read a response body, failing closed once more than `cap` bytes arrive. */
async function readCapped(res: Response, cap: number): Promise<Uint8Array> {
  const tooLarge = () => new SecretServerError("SecretServer response exceeds size limit", res.status);
  const declared = Number(res.headers?.get?.("content-length") ?? NaN);
  if (Number.isFinite(declared) && declared > cap) { await discardBody(res); throw tooLarge(); }
  const body = res.body;
  if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) { await reader.cancel().catch(() => undefined); throw tooLarge(); }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
    return out;
  }
  if (typeof res.arrayBuffer === "function") {
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.byteLength > cap) throw tooLarge();
    return buf;
  }
  const text = await res.text();
  if (text.length > cap) throw tooLarge();
  const bytes = new TextEncoder().encode(text);
  if (bytes.byteLength > cap) throw tooLarge();
  return bytes;
}
const USER_AGENT = "secretserver-node/1.3.0";

export class SecretServerClient {
  private readonly apiKey: string;
  private readonly apiUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;

  constructor(config: ClientConfig = {}) {
    this.apiKey = config.apiKey ?? process.env.SS_API_KEY ?? "";
    this.apiUrl = validateBaseUrl(config.apiUrl ?? process.env.SS_API_URL ?? DEFAULT_URL)
      .replace(/\/$/, "")
      .replace(/\/api\/v1$/, "");
    this.fetchFn = config.fetchFn ?? fetch;
    this.timeoutMs = config.timeoutMs ?? 10000;
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0) throw new SecretServerError("timeoutMs must be positive");

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

  /** Call any REST endpoint using a path relative to `/api/v1`. */
  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.send(method, path, body);
    const text = new TextDecoder().decode(await readCapped(res, MAX_JSON_BYTES));
    if (text.trim() === "") return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new SecretServerError("SecretServer returned an invalid JSON response", res.status);
    }
  }

  /** GET a raw (non-JSON) download, capped at 16 MiB. */
  private async download(path: string): Promise<Uint8Array> {
    return readCapped(await this.send("GET", path), MAX_RAW_BYTES);
  }

  private async send(method: string, path: string, body?: unknown): Promise<Response> {
    const normalizedPath = `/${path}`.replace(/^\/+(?:api\/v1\/?)?/, "/");
    const url = `${this.apiUrl}/api/v1${normalizedPath === "/" ? "" : normalizedPath}`;
    const res = await this.fetchFn(url, {
      method,
      redirect: "error",
      signal: AbortSignal.timeout(this.timeoutMs),
      headers: this.headers(),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (!res.ok) {
      await discardBody(res);
      const msg = `SecretServer request failed (HTTP ${res.status})`;
      if (res.status === 401) throw new AuthError(msg);
      if (res.status === 403) throw new PermissionError(msg);
      if (res.status === 404) throw new NotFoundError(msg);
      throw new SecretServerError(msg, res.status);
    }
    return res;
  }

  private get = <T>(path: string) => this.request<T>("GET", path);
  private post = <T>(path: string, body?: unknown) => this.request<T>("POST", path, body);
  private put = <T>(path: string, body?: unknown) => this.request<T>("PUT", path, body);
  private delete = <T>(path: string) => this.request<T>("DELETE", path);

  private async getList<T>(path: string, ...envelopeKeys: string[]): Promise<T[]> {
    const data = await this.get<T[] | Record<string, unknown> | null | undefined>(path);
    if (Array.isArray(data)) return data;
    if (data === null || typeof data !== "object") return [];
    for (const key of envelopeKeys) {
      const value = data[key];
      if (Array.isArray(value)) return value as T[];
    }
    return [];
  }

  // -----------------------------------------------------------------------
  // Path-based secret access (primary interface)
  // -----------------------------------------------------------------------

  /** Get a secret value by path: "container/key" or "container/key/2" */
  async assignVariable(name: string, assignment: VariableAssignment): Promise<Variable> {
    return this.put<Variable>(`/variables/${seg(name)}`, assignment);
  }
  async getVariable(name: string): Promise<Variable> { return this.get<Variable>(`/variables/${seg(name)}`); }
  async listVariables(): Promise<Variable[]> { return (await this.get<{variables: Variable[]}>("/variables")).variables; }
  async deleteVariable(name: string): Promise<void> { await this.delete(`/variables/${seg(name)}`); }
  async render(template: string): Promise<string> {
    const result = await this.post<{rendered: string}>("/variables/resolve", {template});
    if (typeof result?.rendered !== "string") throw new SecretServerError("Invalid rendered response");
    return result.rendered;
  }
  async resolveDocument<T>(document: T): Promise<T> {
    const result = await this.post<{document: T}>("/variables/resolve", {document});
    if (!result || !("document" in result)) throw new SecretServerError("Invalid document response");
    return result.document;
  }

  async secret(path: string): Promise<string> {
    const parts = path.replace(/^\/|\/$/g, "").split("/");
    if (parts.length === 1) {
      const d = await this.get<{ value?: string; data?: { value?: string } }>(`/secrets/${seg(parts[0])}`);
      return scalar(d);
    }
    const d = await this.get<{ value?: string; data?: Record<string, unknown> }>(`/s/${parts.map(seg).join("/")}`);
    return scalar(d);
  }

  /** Get full secret object by path */
  async getSecret(path: string): Promise<Secret> {
    const parts = path.replace(/^\/|\/$/g, "").split("/");
    if (parts.length === 1) return this.get(`/secrets/${seg(parts[0])}`);
    return this.get(`/s/${parts.map(seg).join("/")}`);
  }

  // -----------------------------------------------------------------------
  // Secrets
  // -----------------------------------------------------------------------

  async listSecrets(): Promise<Secret[]> {
    return this.getList<Secret>("/secrets", "secrets");
  }

  async createSecret(name: string, value: string, opts: { description?: string; containerID?: string } = {}): Promise<Secret> {
    return this.post("/secrets", {
      name,
      data: { value },
      description: opts.description,
      container_id: opts.containerID,
    });
  }

  async updateSecret(name: string, value: string): Promise<Secret> {
    return this.put(`/secrets/${seg(name)}`, { name, data: { value } });
  }

  async deleteSecret(name: string): Promise<void> { return this.delete(`/secrets/${seg(name)}`); }

  // -----------------------------------------------------------------------
  // Containers
  // -----------------------------------------------------------------------

  async listContainers(): Promise<Container[]> { return this.get("/containers"); }

  async createContainer(name: string, slug?: string, description?: string): Promise<Container> {
    return this.post("/containers", { name, slug, description });
  }

  // -----------------------------------------------------------------------
  // Certificates
  // -----------------------------------------------------------------------

  async listCertificates(): Promise<Certificate[]> { return this.getList("/certificates", "certificates"); }
  async getCertificate(id: string): Promise<Certificate> { return this.get(`/certificates/${seg(id)}`); }

  async enrollCertificate(name: string, commonName: string, sans: string[] = [], autoRenew = true): Promise<Certificate> {
    return this.post("/certificates/enroll", { name, common_name: commonName, dns_names: sans, auto_renew: autoRenew });
  }

  async renewCertificate(id: string): Promise<Certificate> { return this.post(`/certificates/${seg(id)}/renew`); }
  async downloadCertificate(id: string): Promise<{ pem: string }> { return this.get(`/certificates/${seg(id)}/download`); }

  // -----------------------------------------------------------------------
  // Operation-only cryptographic backends
  // -----------------------------------------------------------------------

  async listCryptoBackends(): Promise<CryptoBackend[]> { return this.get("/crypto/backends"); }

  async listSigningKeys(backend = "pkcs11"): Promise<SigningKey[]> {
    return this.get(`/crypto/signing-keys?backend=${encodeURIComponent(backend)}`);
  }

  async sign(backend: string, keyId: string, message: string, purpose: string): Promise<SignResult> {
    return this.post("/crypto/sign", { backend, key_id: keyId, message, purpose });
  }

  // -----------------------------------------------------------------------
  // JKS keystores
  // -----------------------------------------------------------------------

  async listJKSKeystores(): Promise<JKSKeystore[]> { return this.get("/jks-keystores"); }
  async getJKSKeystore(id: string): Promise<JKSKeystore> { return this.get(`/jks-keystores/${seg(id)}`); }
  async createJKSKeystore(input: CreateJKSKeystoreInput): Promise<JKSKeystore> {
    return this.post("/jks-keystores", input);
  }
  async updateJKSKeystore(id: string, input: Partial<CreateJKSKeystoreInput>): Promise<{ message: string }> {
    return this.put(`/jks-keystores/${seg(id)}`, input);
  }
  async deleteJKSKeystore(id: string): Promise<void> { return this.delete(`/jks-keystores/${seg(id)}`); }
  async exportJKSKeystore(id: string): Promise<JKSExport> { return this.get(`/jks-keystores/${seg(id)}/export`); }
  async listJKSEntries(id: string): Promise<JKSEntry[]> { return this.get(`/jks-keystores/${seg(id)}/entries`); }
  async createJKSEntry(id: string, input: CreateJKSEntryInput): Promise<JKSEntry> {
    return this.post(`/jks-keystores/${seg(id)}/entries`, input);
  }
  async deleteJKSEntry(id: string, alias: string): Promise<void> {
    return this.delete(`/jks-keystores/${seg(id)}/entries/${seg(alias)}`);
  }

  // Provider credentials are redacted unless reveal=true and the identity has export:read.
  async listIntegrationProviders(): Promise<IntegrationProvider[]> { return this.get("/integration-providers"); }
  async listKeyCatalog(): Promise<KeyCatalogItem[]> { return this.get("/key-catalog"); }
  createIntegrationCredential(input: {
    name: string; provider: string; credentials: Record<string, string>;
    auth_type?: string; endpoint?: string; tags?: string[];
  }): Promise<{ id: string; created_at: string }> { return this.post("/integrations", input); }
  async getIntegrationCredential(id: string, reveal = false): Promise<IntegrationCredential> {
    const query = reveal ? "?reveal=true" : "";
    return this.get(`/integrations/${seg(id)}${query}`);
  }

  // -----------------------------------------------------------------------
  // SSH Keys
  // -----------------------------------------------------------------------

  async listSSHKeys(): Promise<SSHKey[]> { return this.getList("/ssh-keys", "ssh_keys", "keys"); }

  async generateSSHKey(name: string, keyType: "rsa" | "ed25519" | "ecdsa" = "ed25519", comment?: string): Promise<SSHKey> {
    return this.post("/ssh-keys/generate", { name, key_type: keyType, comment });
  }

  async importSSHKey(name: string, privateKey: string): Promise<SSHKey> {
    return this.post("/ssh-keys/import", { name, private_key: privateKey });
  }

  async exportSSHKey(id: string): Promise<{ public_key: string; private_key: string }> {
    return this.get(`/ssh-keys/${seg(id)}/export`);
  }

  // -----------------------------------------------------------------------
  // Passwords
  // -----------------------------------------------------------------------

  async listPasswords(): Promise<Password[]> { return this.getList("/passwords", "passwords"); }

  async createPassword(name: string, username: string, password: string, url?: string): Promise<Password> {
    return this.post("/passwords", { name, username, password, url });
  }

  async generatePassword(length = 32, includeSymbols = true): Promise<{ password: string }> {
    return this.post("/passwords/generate", { length, include_symbols: includeSymbols });
  }

  // -----------------------------------------------------------------------
  // API Tokens
  // -----------------------------------------------------------------------

  async listAPITokens(): Promise<unknown[]> { return this.getList("/api-tokens", "tokens"); }
  async createAPIToken(name: string, service: string, token: string): Promise<unknown> {
    return this.post("/api-tokens", { name, service, token });
  }
  async rotateAPIToken(id: string): Promise<unknown> { return this.post(`/api-tokens/${seg(id)}/rotate`); }

  // -----------------------------------------------------------------------
  // GPG Keys
  // -----------------------------------------------------------------------

  async listGPGKeys(): Promise<unknown[]> { return this.getList("/gpg-keys", "keys"); }
  async generateGPGKey(name: string, email: string, opts: { keyType?: string; expiresInDays?: number } = {}): Promise<unknown> {
    return this.post("/gpg-keys/generate", { name, email, key_type: opts.keyType, expires_in_days: opts.expiresInDays });
  }
  async exportGPGKey(id: string): Promise<{ public_key: string; private_key: string }> {
    return this.get(`/gpg-keys/${seg(id)}/export`);
  }

  async deleteGPGKey(id: string): Promise<void> { return this.delete(`/gpg-keys/${seg(id)}`); }

  // -----------------------------------------------------------------------
  // Extended credential types (read + write)
  // -----------------------------------------------------------------------

  private credAPI(resource: string) {
    return {
      list: async () => this.get<unknown[]>(`/${resource}`),
      get: async (id: string) => this.get<unknown>(`/${resource}/${seg(id)}`),
      create: async (data: unknown) => this.post<unknown>(`/${resource}`, data),
      update: async (id: string, data: unknown) => this.put<unknown>(`/${resource}/${seg(id)}`, data),
      delete: async (id: string) => this.delete<void>(`/${resource}/${seg(id)}`),
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
    const d = await this.get<{ versions?: VersionEntry[] }>(`/${seg(secretType)}/${seg(secretId)}/history`);
    return d.versions ?? [];
  }

  async getVersion(secretType: string, secretId: string, version: number): Promise<unknown> {
    return this.get(`/${seg(secretType)}/${seg(secretId)}/history/${seg(version)}`);
  }

  async getHistorySettings(secretType: string, secretId: string): Promise<{ history_enabled: boolean; max_versions: number }> {
    return this.get(`/${seg(secretType)}/${seg(secretId)}/history-settings`);
  }

  async updateHistorySettings(secretType: string, secretId: string, enabled: boolean, maxVersions: number): Promise<unknown> {
    return this.put(`/${seg(secretType)}/${seg(secretId)}/history-settings`, { history_enabled: enabled, max_versions: maxVersions });
  }

  // -----------------------------------------------------------------------
  // Sharing & temp access
  // -----------------------------------------------------------------------

  async share(
    secretType: string,
    secretId: string,
    email: string,
    permission: "read" | "manage" = "read",
    expiresAt?: Date,
  ): Promise<ShareResult> {
    return this.post(`/${seg(secretType)}/${seg(secretId)}/shares`, {
      shared_with_email: email,
      permission,
      expires_at: expiresAt?.toISOString(),
    });
  }

  async createTempAccess(secretType: string, secretId: string, durationSeconds = 900): Promise<TempAccessResult> {
    return this.post(`/${seg(secretType)}/${seg(secretId)}/temp-access`, { duration_seconds: durationSeconds });
  }

  // -----------------------------------------------------------------------
  // Intelligence & transform
  // -----------------------------------------------------------------------

  async checkBreach(value: string): Promise<{ leaked: boolean; exposure_count: number; risk_level: string }> {
    return this.post("/intelligence/check-breach", { password: value });
  }

  async encode(data: string, format = "base64"): Promise<{ result: string }> {
    return this.post("/transform/encode", { input: data, target_type: format });
  }

  async decode(data: string, format = "base64"): Promise<{ result: string }> {
    return this.post("/transform/decode", { input: data, source_type: format });
  }

  // -----------------------------------------------------------------------
  // Audit
  // -----------------------------------------------------------------------

  async getAuditLogs(opts: { limit?: number; offset?: number; action?: string } = {}): Promise<{ logs: unknown[]; total: number }> {
    const q = new URLSearchParams(opts as Record<string, string>).toString();
    return this.get(`/audit/logs${q ? `?${q}` : ""}`);
  }

  async exportAuditLogs(): Promise<unknown> { return this.get("/audit/logs/export"); }

  // -----------------------------------------------------------------------
  // OpenSSL Keys
  // -----------------------------------------------------------------------

  async listOpenSSLKeys(): Promise<unknown[]> { return this.getList("/openssl-keys", "openssl_keys", "keys"); }
  async getOpenSSLKey(id: string): Promise<unknown> { return this.get(`/openssl-keys/${seg(id)}`); }

  async generateOpenSSLKey(name: string, keyType = "rsa", bits = 4096): Promise<unknown> {
    return this.post("/openssl-keys/generate", { name, key_type: keyType, bits });
  }

  async importOpenSSLKey(name: string, privateKey: string): Promise<unknown> {
    return this.post("/openssl-keys/import", { name, private_key: privateKey });
  }

  async exportOpenSSLKey(id: string): Promise<{ public_key: string; private_key: string }> {
    return this.get(`/openssl-keys/${seg(id)}/export`);
  }

  async deleteOpenSSLKey(id: string): Promise<void> { return this.delete(`/openssl-keys/${seg(id)}`); }

  // -----------------------------------------------------------------------
  // NTLM Hashes
  // -----------------------------------------------------------------------

  async listNTLMHashes(): Promise<unknown[]> { return this.getList("/ntlm", "ntlm_hashes", "hashes"); }
  async getNTLMHash(id: string): Promise<unknown> { return this.get(`/ntlm/${seg(id)}`); }

  async createNTLMHash(name: string, username: string, hash: string): Promise<unknown> {
    return this.post("/ntlm", { name, username, hash });
  }

  async updateNTLMHash(id: string, data: unknown): Promise<unknown> {
    return this.put(`/ntlm/${seg(id)}`, data);
  }

  async deleteNTLMHash(id: string): Promise<void> { return this.delete(`/ntlm/${seg(id)}`); }

  // -----------------------------------------------------------------------
  // Certificates (extended operations)
  // -----------------------------------------------------------------------

  async revokeCertificate(id: string): Promise<unknown> { return this.post(`/certificates/${seg(id)}/revoke`); }

  // -----------------------------------------------------------------------
  // Webhooks
  // -----------------------------------------------------------------------

  async listWebhooks(): Promise<unknown[]> { return this.getList("/webhooks", "webhooks"); }

  async createWebhook(name: string, url: string, events: string[], authType = "none"): Promise<unknown> {
    return this.post("/webhooks", { name, url, events, auth_type: authType });
  }

  async listWebhookDeliveries(webhookId: string): Promise<unknown[]> {
    return this.getList(`/webhooks/${seg(webhookId)}/deliveries`, "deliveries");
  }

  async testWebhook(webhookId: string): Promise<unknown> {
    return this.post(`/webhooks/${seg(webhookId)}/test`);
  }

  // -----------------------------------------------------------------------
  // Export
  // -----------------------------------------------------------------------

  async exportToKeychain(items: unknown[]): Promise<unknown> {
    return this.post("/export/keychain", { items });
  }

  async exportToCredentialManager(items: unknown[]): Promise<unknown> {
    return this.post("/export/credential-manager", { items });
  }

  async exportToJSON(items: unknown[]): Promise<unknown> {
    return this.post("/export/json", { items });
  }

  // -----------------------------------------------------------------------
  // TOTP Authenticators
  // -----------------------------------------------------------------------

  // -----------------------------------------------------------------------
  // YubiKey OTP Credentials
  // -----------------------------------------------------------------------

  async listYubikeys(): Promise<YubikeyCredential[]> { return this.get("/yubikeys"); }
  async getYubikey(id: string): Promise<YubikeyCredential> { return this.get(`/yubikeys/${seg(id)}`); }

  async createYubikey(
    name: string, publicId: string, clientId: string, apiKey: string,
    opts: { serialNumber?: string; validationServer?: string; notes?: string } = {}
  ): Promise<YubikeyCredential> {
    return this.post("/yubikeys", {
      name, public_id: publicId, client_id: clientId, api_key: apiKey,
      serial_number: opts.serialNumber, validation_server: opts.validationServer, notes: opts.notes,
    });
  }

  async updateYubikey(id: string, data: Partial<YubikeyCredential & { api_key: string }>): Promise<unknown> {
    return this.put(`/yubikeys/${seg(id)}`, data);
  }

  async deleteYubikey(id: string): Promise<void> { return this.delete(`/yubikeys/${seg(id)}`); }

  /** Validate a Yubico OTP against the stored YubiKey configuration */
  async validateYubikeyOTP(id: string, otp: string): Promise<YubikeyValidateResult> {
    return this.post(`/yubikeys/${seg(id)}/validate`, { otp });
  }

  /** List all TOTP authenticator tokens */
  async listTOTPTokens(): Promise<TOTPToken[]> { return this.get("/totp-tokens"); }

  /** Get a specific TOTP token by ID */
  async getTOTPToken(id: string): Promise<TOTPToken> { return this.get(`/totp-tokens/${seg(id)}`); }

  /**
   * Create a new TOTP token
   *
   * @param name Display name for the token
   * @param issuer Issuer name (e.g., "GitHub", "AWS")
   * @param accountName Account identifier (e.g., email or username)
   * @param secretKey Base32-encoded secret key
   * @param opts Optional parameters (algorithm, digits, period)
   */
  async createTOTPToken(
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
  async updateTOTPToken(id: string, data: Partial<Omit<TOTPToken, "id" | "created_at" | "updated_at">>): Promise<TOTPToken> {
    return this.put(`/totp-tokens/${seg(id)}`, data);
  }

  /** Delete a TOTP token */
  async deleteTOTPToken(id: string): Promise<void> { return this.delete(`/totp-tokens/${seg(id)}`); }

  /**
   * Generate a TOTP code for the given token
   *
   * Returns an object with 'code' and 'expires_in' (seconds remaining)
   */
  async generateTOTPCode(id: string): Promise<TOTPCode> {
    return this.post(`/totp-tokens/${seg(id)}/generate`);
  }

  /**
   * Import a TOTP token from an otpauth:// URI
   *
   * @param uri otpauth://totp/... URI string
   * @returns The created TOTP token
   */
  async importTOTPFromURI(uri: string): Promise<TOTPToken> {
    return this.post("/totp-tokens/import", { uri });
  }

  /**
   * Export a TOTP token to an otpauth:// URI
   *
   * Returns an object with 'uri' and 'qr_code' (base64-encoded PNG)
   */
  async exportTOTPToURI(id: string): Promise<TOTPExport> {
    return this.get(`/totp-tokens/${seg(id)}/export`);
  }
}

export default SecretServerClient;

function scalar(payload: {value?: string; data?: Record<string, unknown>}): string {
 const data=payload.data ?? payload;
 for (const key of ["value","password","token","key","passphrase","bind_password","certificate"]) {
 const value=(data as Record<string,unknown>)[key];if(typeof value==="string") return value;
 }
 throw new SecretServerError("Secret response has no supported scalar field");
}
