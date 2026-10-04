/**
 * SecretServer.io Node.js / TypeScript client library.
 *
 * Works in Node.js 18+ (native fetch) and in any fetch-compatible environment.
 * Zero external dependencies.
 *
 * @example
 * ```ts
 * import { SecretServerClient } from "@afterdarksys/secretserver";
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
/** HTTP 409 from a conditional update: `etag` is the resource's current ETag (re-read and retry). */
export class ConflictError extends SecretServerError {
  constructor(m: string, public readonly etag?: string) { super(m, 409); this.name = "ConflictError"; }
}

export interface ClientConfig {
  /** API key — also reads SS_API_KEY from process.env */
  apiKey?: string;
  /**
   * Obtain a short-lived credential per request; mutually exclusive with
   * apiKey. Use cliCredentialProvider() to reuse the `ss login` session.
   */
  credentialProvider?: () => string | Promise<string>;
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
  /**
   * Allow updateSecret/updateJKSKeystore/updateYubikey to send partial
   * bodies without an ETag. Minimum server: secretserver.io 3075630 (partial,
   * conditional updates); older servers treat these PUTs as a full replace
   * and silently blank omitted fields. Defaults to SS_PARTIAL_UPDATES=1 in
   * process.env; without it, those methods refuse to send unless `ifMatch`
   * is an ETag received from the server ("..." or W/"...").
   */
  partialUpdates?: boolean;
}

export interface VariableAssignment { secret_type: string; secret_id: string; field: string; }
export interface Variable extends VariableAssignment { id: string; name: string; }

export interface Secret {
  id: string;
  container_id?: string | null;
  name: string;
  description?: string;
  data: Record<string, string>;
  tags?: string[];
  version: number;
  created_at: string;
  updated_at: string;
  /** ETag response header of getSecret(name)/updateSecret; pass it back as `ifMatch`. Not a stored field. */
  etag?: string;
}

/**
 * Partial secret update. OMITTED (undefined) = keep the stored value;
 * null = clear it. "" is sent as a literal empty string, not a clear.
 */
export interface UpdateSecretOptions {
  description?: string | null;
  tags?: string[] | null;
  containerID?: string | null;
  /**
   * Conditional update: an ETag from getSecret/updateSecret, or the secret's
   * version number. Only an ETag ("..." or W/"...") also proves the server
   * supports partial updates; see ClientConfig.partialUpdates.
   */
  ifMatch?: string | number;
  /** Conditional update on the secret's version number (sent as body field expected_version). */
  expectedVersion?: number;
}

/** Response of a container path lookup (/s/container/key[/version]). */
export interface PathSecret {
  meta: {
    secret_id: string;
    secret_type: SecretType;
    name: string;
    value: string;
    version: number;
    is_history: boolean;
    created_at: string;
  };
  data: Record<string, unknown>;
}

export const SECRET_TYPES = [
  "secret", "password", "ssh_key", "gpg_key", "api_token", "openssl_key", "ntlm_hash", "certificate",
  "computer_credential", "wifi_credential", "windows_credential", "social_credential", "disk_credential",
  "service_config_credential", "root_credential", "ldap_bind_credential", "integration_credential", "code_signing_key",
] as const;
export type SecretType = typeof SECRET_TYPES[number];

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
  dns_names?: string[];
  issuer_type: string;
  issuer_name: string;
  serial_number?: string;
  status: string;
  not_before?: string;
  not_after?: string;
  days_until_expiry?: number;
  auto_renew: boolean;
  renew_before: number;
  fingerprint?: string;
  created_at: string;
  updated_at: string;
}

export type CertificateTextFormat = "pem" | "pem-bundle" | "key";
export type CertificateBinaryFormat = "pfx" | "p12";

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
  description?: string;
  username?: string;
  url?: string;
  /** Only present on create/generate responses and explicit reads. */
  value?: string;
  tags?: string[];
  strength?: Record<string, unknown>;
  created_at: string;
  updated_at?: string;
}

export interface GeneratePasswordOptions {
  /** 8..128, default 32 */
  length?: number;
  useLowercase?: boolean;
  useUppercase?: boolean;
  useDigits?: boolean;
  useSymbols?: boolean;
  description?: string;
  username?: string;
  url?: string;
  tags?: string[];
}

export type APITokenEnvironment = "production" | "staging" | "development";

export interface APIToken {
  id: string;
  name: string;
  description?: string;
  service: string;
  token_prefix: string;
  environment: APITokenEnvironment;
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
  /** Only present on create/rotate responses. */
  value?: string;
}

export type GPGAlgorithm = "RSA2048" | "RSA4096" | "ED25519";

export interface GPGKeyGenerated {
  id: string;
  fingerprint: string;
  key_id: string;
  public_key: string;
  algorithm: GPGAlgorithm;
  name: string;
  email: string;
  created_at: string;
}

export interface GPGExport {
  key: string;
  format: "public" | "private";
  fingerprint: string;
  key_id: string;
}

export type OpenSSLAlgorithm = "rsa" | "ecdsa" | "ed25519";

export interface OpenSSLKeyOptions {
  /** RSA only: 2048 or 4096 (server default 4096) */
  keySize?: number;
  /** ECDSA only: P-256, P-384 or P-521 */
  curve?: string;
  description?: string;
  passphrase?: string;
}

export interface ExportOptions {
  includePasswords?: boolean;
  includeSecrets?: boolean;
  includeSSHKeys?: boolean;
  includeCertificates?: boolean;
  /** Only export items carrying at least one of these tags. */
  tags?: string[];
}

export interface AuditLogQuery {
  limit?: number;
  offset?: number;
  action?: string;
  resource?: string;
  resource_id?: string;
  user_id?: string;
  start_date?: string | Date;
  end_date?: string | Date;
}

export interface VersionEntry {
  id: string;
  secret_id: string;
  secret_type: SecretType;
  version_num: number;
  created_by?: string;
  created_at: string;
}

/** Share target: exactly one of userId / groupId (UUIDs). */
export type ShareTarget = { userId: string; groupId?: undefined } | { groupId: string; userId?: undefined };

export interface ShareResult {
  id: string;
  secret_id: string;
  secret_type: SecretType;
  shared_with_user_id?: string;
  shared_with_group_id?: string;
  permission: "read" | "manage";
  expires_at?: string;
  created_at: string;
}

export interface TempAccessResult {
  id: string;
  token: string;
  duration_seconds: number;
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
  period: number;
}

export interface TOTPExport {
  uri: string;
}

export interface YubikeyCredential {
  id: string;
  container_id?: string | null;
  name: string;
  serial_number?: string;
  public_id: string;
  client_id: string;
  validation_server: string;
  notes?: string;
  tags?: string[];
  created_at: string;
  updated_at: string;
  /** ETag response header of getYubikey; pass it back as `ifMatch`. Not a stored field. */
  etag?: string;
}

/** Partial YubiKey update: undefined = keep, null = clear (nullable fields only). */
export interface UpdateYubikeyInput {
  name?: string;
  container_id?: string | null;
  serial_number?: string | null;
  /** Exactly 12 modhex characters. */
  public_id?: string;
  client_id?: string;
  validation_server?: string;
  notes?: string | null;
  tags?: string[] | null;
  /** Replaces the stored Yubico API key (base64). */
  api_key?: string;
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
  container_id?: string | null;
  name: string;
  store_type: "raw" | "managed";
  entry_count?: number;
  notes?: string;
  tags?: string[];
  created_at?: string;
  updated_at?: string;
  /** ETag response header of getJKSKeystore; pass it back as `ifMatch`. Not a stored field. */
  etag?: string;
}

/** Partial keystore update: undefined = keep, null = clear (container_id, notes, tags). */
export interface UpdateJKSKeystoreInput {
  name?: string;
  container_id?: string | null;
  notes?: string | null;
  tags?: string[] | null;
  /** Replacement keystore (base64, raw keystores only); requires `password`. */
  jks?: string;
  /** Alone, rotates the stored keystore password. */
  password?: string;
}

/** Result of a keystore/YubiKey update; `etag` is the new ETag response header. */
export interface UpdateResult {
  message: string;
  etag?: string;
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
function normalizeBaseUrl(raw: string): string {
  return validateBaseUrl(raw).replace(/\/$/, "").replace(/\/api\/v1$/, "");
}

/**
 * Loose equality for the CLI-login/explicit-apiUrl mismatch check only:
 * lowercases scheme and host, strips the scheme's default port (80 for
 * http, 443 for https) and a trailing slash. Not a general URL normalizer.
 */
function sameApiOrigin(a: string, b: string): boolean {
  const norm = (raw: string): string => {
    let u: URL;
    try { u = new URL(raw); } catch { return raw.toLowerCase().replace(/\/$/, ""); }
    const scheme = u.protocol.toLowerCase();
    const isDefaultPort = (scheme === "https:" && (u.port === "" || u.port === "443")) || (scheme === "http:" && (u.port === "" || u.port === "80"));
    const port = isDefaultPort ? "" : (u.port ? `:${u.port}` : "");
    return `${scheme}//${u.hostname.toLowerCase()}${port}${u.pathname.replace(/\/$/, "")}`;
  };
  return norm(a) === norm(b);
}

function seg(value: string | number): string {
  const s = String(value);
  if (s === "" || s === "." || s === "..") throw new SecretServerError("Invalid path segment");
  return encodeURIComponent(s);
}

function secretTypeSeg(type: SecretType): string {
  if (!(SECRET_TYPES as readonly string[]).includes(type)) throw new SecretServerError("Invalid secret type");
  return seg(type);
}

/** Split and validate "name", "container/key" or "container/key/version" (version 1..12). */
function secretPath(path: string): string[] {
  const parts = path.replace(/^\/|\/$/g, "").split("/");
  if (parts.length > 3 || parts.some(p => p === "")) throw new SecretServerError("Secret path must be name, container/key or container/key/version");
  if (parts.length === 3 && !/^(?:[1-9]|1[0-2])$/.test(parts[2])) throw new SecretServerError("Secret version must be between 1 and 12");
  return parts;
}

/** Build the If-Match header. Numbers (secret versions) must be non-negative integers. */
function ifMatchHeader(ifMatch: string | number | undefined): Record<string, string> | undefined {
  if (ifMatch === undefined) return undefined;
  if (typeof ifMatch === "number") {
    if (!Number.isInteger(ifMatch) || ifMatch < 0) throw new SecretServerError("ifMatch version must be a non-negative integer");
    return { "If-Match": String(ifMatch) };
  }
  if (typeof ifMatch !== "string" || ifMatch.trim() === "" || /[\r\n]/.test(ifMatch)) throw new SecretServerError("Invalid ifMatch value");
  return { "If-Match": ifMatch };
}

const PARTIAL_UPDATES_REQUIRED =
  "partial updates require secretserver.io 3075630 or newer; pass an ETag from get() as if_match or enable partial_updates";

/** A server entity tag: "..." or W/"..." (RFC 9110 etagc). Versions, "*" and bare values are not. */
function isEntityTag(ifMatch: unknown): boolean {
  return typeof ifMatch === "string" && /^(?:W\/)?"[\x21\x23-\x7e\x80-\xff]*"$/.test(ifMatch);
}

/** Keep only the keys the caller set: undefined = omit, null = sent as JSON null. */
function providedFields(input: object): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([, v]) => v !== undefined));
}

function withETag<T>(data: T, etag: string | undefined): T {
  if (etag !== undefined && data !== null && typeof data === "object") Object.assign(data, { etag });
  return data;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
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
const USER_AGENT = "secretserver-node/1.4.0";

// ---------------------------------------------------------------------------
// CLI credential provider (`ss login`)
//
// Threats: lets a program reuse the developer's `ss login` session without
// handling refresh tokens. The CLI is run from an argv array (execFile, no
// shell) with a 30 s timeout and a 64 KiB output cap; any malformed answer
// fails closed; the access token and the CLI's stdout never appear in errors.
// Does NOT protect against a malicious `ss` binary on PATH or in SS_CLI_PATH,
// or against other code running as the same OS user.
// ---------------------------------------------------------------------------

export interface CliCredentialProviderOptions {
  /** The `ss` executable. Default: SS_CLI_PATH from process.env, else `ss` on PATH. */
  cliPath?: string;
  /** Limit for one CLI run in milliseconds. Default 30000. */
  timeoutMs?: number;
}

/** A `credentialProvider` backed by `ss auth print-access-token`. */
export interface CliCredentialProvider {
  (): Promise<string>;
  /** The API URL the CLI is logged in to (runs the CLI if nothing is cached). */
  apiUrl(): Promise<string | undefined>;
}

interface CliToken { token: string; expiresAt: number; apiUrl?: string; }

const CLI_MAX_OUTPUT = 64 * 1024;
const CLI_REFRESH_SKEW_MS = 60_000;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i;
const cliProviders = new WeakSet<object>();

/**
 * Credential provider that reuses the `ss login` SSO session: it runs
 * `ss auth print-access-token --format json` and caches the token in memory
 * until 60 s before it expires. Exit status 2 from the CLI becomes an
 * AuthError telling the user to run `ss login`. When the client is given no
 * apiUrl (and SS_API_URL is unset) it uses the URL the CLI is logged in to.
 */
export function cliCredentialProvider(opts: CliCredentialProviderOptions = {}): CliCredentialProvider {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new SecretServerError("timeoutMs must be positive");
  let cached: CliToken | undefined;
  let inflight: Promise<CliToken> | undefined;
  const current = async (): Promise<CliToken> => {
    if (cached && Date.now() < cached.expiresAt - CLI_REFRESH_SKEW_MS) return cached;
    cached = undefined;
    inflight ??= runCli(opts.cliPath || process.env.SS_CLI_PATH || "ss", timeoutMs).finally(() => { inflight = undefined; });
    cached = await inflight;
    return cached;
  };
  const provider = (async () => (await current()).token) as CliCredentialProvider;
  provider.apiUrl = async () => (await current()).apiUrl;
  cliProviders.add(provider);
  return provider;
}

type CliExecError = Error & { code?: number | string; killed?: boolean };
type ExecFile = (
  file: string, args: string[], options: object,
  callback: (err: CliExecError | null, stdout: string, stderr: string) => void,
) => { stdin?: { end(): void } | null };
// Loaded lazily (and through a variable, so bundlers for non-Node targets
// leave it alone); only cliCredentialProvider needs it.
const CHILD_PROCESS_MODULE = "node:child_process";

async function runCli(path: string, timeoutMs: number): Promise<CliToken> {
  const { execFile } = (await import(CHILD_PROCESS_MODULE)) as { execFile: ExecFile };
  const stdout = await new Promise<string>((resolve, reject) => {
    const child = execFile(path, ["auth", "print-access-token", "--format", "json"], {
      encoding: "utf8", shell: false, timeout: timeoutMs, killSignal: "SIGKILL", maxBuffer: CLI_MAX_OUTPUT, windowsHide: true,
    }, (err, out, errOut) => {
      if (!err) return resolve(out);
      // Never attach err: it carries the CLI's stdout.
      const e = err;
      if (e.code === "ENOENT") return reject(new SecretServerError(`SecretServer CLI "${path}" not found: install \`ss\` or set SS_CLI_PATH`));
      if (e.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return reject(new SecretServerError(`\`ss auth print-access-token\` output exceeds ${CLI_MAX_OUTPUT} bytes`));
      if (e.killed) return reject(new SecretServerError(`\`ss auth print-access-token\` timed out after ${timeoutMs} ms`));
      if (e.code === 2) return reject(new AuthError("SecretServer CLI is not logged in: run `ss login`"));
      if (typeof e.code === "number") return reject(new SecretServerError(`\`ss auth print-access-token\` failed (exit ${e.code})${stderrExcerpt(errOut)}`));
      reject(new SecretServerError(`running SecretServer CLI "${path}" failed`));
    });
    child.stdin?.end();
  });
  let parsed: unknown;
  try { parsed = JSON.parse(stdout); } catch { throw new SecretServerError("`ss auth print-access-token` returned invalid JSON"); }
  const o = (parsed ?? {}) as Record<string, unknown>;
  if (typeof o.access_token !== "string" || !/^[\x21-\x7e]+$/.test(o.access_token))
    throw new SecretServerError("`ss auth print-access-token` returned no usable access_token");
  const expiresAt = typeof o.expires_at === "string" && RFC3339.test(o.expires_at) ? Date.parse(o.expires_at) : NaN;
  if (!Number.isFinite(expiresAt)) throw new SecretServerError("`ss auth print-access-token` returned an invalid expires_at");
  return { token: o.access_token, expiresAt, apiUrl: typeof o.api_url === "string" && o.api_url ? o.api_url : undefined };
}

/** First stderr line, at most 200 printable characters. The CLI never writes tokens to stderr. */
function stderrExcerpt(stderr: string): string {
  const line = (stderr.trim().split("\n")[0] ?? "").replace(/[\x00-\x1f\x7f]/g, "").slice(0, 200);
  return line ? `: ${line}` : "";
}

export class SecretServerClient {
  #apiKey: Uint8Array;
  #credentialProvider?: () => string | Promise<string>;
  #destroyed = false;
  private apiUrl: string;
  #apiUrlFromCli?: () => Promise<string | undefined>;
  #explicitApiUrl?: string;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;
  private readonly partialUpdates: boolean;

  constructor(config: ClientConfig = {}) {
    if (config.credentialProvider !== undefined && (typeof config.credentialProvider !== "function" || config.apiKey !== undefined))
      throw new SecretServerError("provide either apiKey or credentialProvider");
    this.#credentialProvider = config.credentialProvider;
    this.#apiKey = new TextEncoder().encode(config.credentialProvider ? "" : (config.apiKey ?? process.env.SS_API_KEY ?? ""));
    this.apiUrl = normalizeBaseUrl(config.apiUrl ?? process.env.SS_API_URL ?? DEFAULT_URL);
    const apiUrlWasExplicit = config.apiUrl !== undefined || process.env.SS_API_URL !== undefined;
    if (apiUrlWasExplicit) this.#explicitApiUrl = this.apiUrl;
    if (cliProviders.has(config.credentialProvider as object))
      this.#apiUrlFromCli = (config.credentialProvider as CliCredentialProvider).apiUrl;
    this.fetchFn = config.fetchFn ?? fetch;
    this.timeoutMs = config.timeoutMs ?? 10000;
    this.partialUpdates = config.partialUpdates ?? process.env.SS_PARTIAL_UPDATES === "1";
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0) throw new SecretServerError("timeoutMs must be positive");

    if (!this.#credentialProvider && this.#apiKey.length === 0) {
      throw new AuthError("No API key provided. Set apiKey or SS_API_KEY env var.");
    }
  }

  // -----------------------------------------------------------------------
  // HTTP core
  // -----------------------------------------------------------------------

  /** Refuse a partial PUT unless opted in or `ifMatch` is a server ETag (proof of a 3075630+ server). */
  private requirePartialUpdates(ifMatch: unknown): void {
    if (!this.partialUpdates && !isEntityTag(ifMatch)) throw new SecretServerError(PARTIAL_UPDATES_REQUIRED);
  }

  /** Wipe the owned credential copy. Caller strings, headers, and in-flight requests are outside this guarantee. */
  destroy(): void { this.#destroyed = true; this.#apiKey.fill(0); this.#apiKey = new Uint8Array(0); this.#credentialProvider = undefined; }
  toJSON(): never { throw new SecretServerError("authenticated clients cannot be serialized"); }
  [Symbol.for("nodejs.util.inspect.custom")](): string { return "SecretServerClient { credentials: [redacted] }"; }

  private async headers(extra?: Record<string, string>): Promise<Record<string, string>> {
    if (this.#destroyed) throw new SecretServerError("client is destroyed");
    let key: string;
    try { key = this.#credentialProvider ? await this.#credentialProvider() : new TextDecoder().decode(this.#apiKey); }
    catch (e) {
      // SDK errors (e.g. cliCredentialProvider's "run `ss login`") carry no secrets.
      if (e instanceof SecretServerError) throw e;
      throw new AuthError("credential provider failed");
    }
    if (this.#destroyed) throw new SecretServerError("client is destroyed");
    if (typeof key !== "string" || !key || /[\r\n\0]/.test(key)) throw new AuthError("invalid credential");
    return {
      Authorization: `Bearer ${key}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
      ...extra,
    };
  }

  /** Call any REST endpoint using a path relative to `/api/v1`. */
  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    return (await this.requestWithETag<T>(method, path, body)).data;
  }

  /** Like request(), also returning the response ETag header when present. */
  private async requestWithETag<T>(
    method: string, path: string, body?: unknown, headers?: Record<string, string>,
  ): Promise<{ data: T; etag?: string }> {
    const res = await this.send(method, path, body, headers);
    const etag = res.headers?.get?.("etag") ?? undefined;
    const text = new TextDecoder().decode(await readCapped(res, MAX_JSON_BYTES));
    if (text.trim() === "") return { data: undefined as T, etag };
    try {
      return { data: JSON.parse(text) as T, etag };
    } catch {
      throw new SecretServerError("SecretServer returned an invalid JSON response", res.status);
    }
  }

  /** GET a raw (non-JSON) download, capped at 16 MiB. */
  private async download(path: string): Promise<Uint8Array> {
    return readCapped(await this.send("GET", path), MAX_RAW_BYTES);
  }

  private async send(method: string, path: string, body?: unknown, headers?: Record<string, string>, pdf?: Uint8Array): Promise<Response> {
    if (this.#apiUrlFromCli) {
      const fromCli = await this.#apiUrlFromCli();
      if (fromCli) {
        const normalized = normalizeBaseUrl(fromCli);
        if (this.#explicitApiUrl !== undefined) {
          if (!sameApiOrigin(this.#explicitApiUrl, normalized))
            throw new SecretServerError(`API URL ${this.#explicitApiUrl} does not match the \`ss login\` session for ${normalized}`);
        } else {
          this.apiUrl = normalized;
        }
      }
      this.#apiUrlFromCli = undefined;
    }
    const normalizedPath = `/${path}`.replace(/^\/+(?:api\/v1\/?)?/, "/");
    const url = `${this.apiUrl}/api/v1${normalizedPath === "/" ? "" : normalizedPath}`;
    const authHeaders = await this.headers(headers);
    if (this.#destroyed) throw new SecretServerError("client is destroyed");
    const res = await this.fetchFn(url, {
      method,
      redirect: "error",
      signal: AbortSignal.timeout(this.timeoutMs),
      headers: authHeaders,
      body: pdf !== undefined ? new Blob([new Uint8Array(pdf)], { type: "application/pdf" }) : (body !== undefined ? JSON.stringify(body) : undefined),
    });

    if (!res.ok) {
      await discardBody(res);
      const msg = `SecretServer request failed (HTTP ${res.status})`;
      if (res.status === 401) throw new AuthError(msg);
      if (res.status === 403) throw new PermissionError(msg);
      if (res.status === 404) throw new NotFoundError(msg);
      if (res.status === 409) throw new ConflictError(msg, res.headers?.get?.("etag") ?? undefined);
      throw new SecretServerError(msg, res.status);
    }
    return res;
  }

  listDocuments(): Promise<DocumentList> { return this.get("/documents"); }
  getDocument(id: string): Promise<ProtectedDocument> { return this.get(`/documents/${seg(id)}`); }
  async uploadDocument(name: string, pdf: Uint8Array): Promise<DocumentUpload> {
    if (!(pdf instanceof Uint8Array) || pdf.byteLength === 0 || pdf.byteLength > 8 * 1024 * 1024)
      throw new SecretServerError("PDF must contain between 1 byte and 8 MiB");
    const res = await this.send("POST", `/documents?${new URLSearchParams({name})}`, undefined, {"Content-Type": "application/pdf"}, pdf);
    try { return JSON.parse(new TextDecoder().decode(await readCapped(res, MAX_JSON_BYTES))); }
    catch (e) { if (e instanceof SecretServerError) throw e; throw new SecretServerError("Invalid document upload response"); }
  }
  downloadDocument(id: string): Promise<Uint8Array> { return this.download(`/documents/${seg(id)}/download`); }
  previewDocument(id: string, page = 1, forPrint = false): Promise<Uint8Array> {
    if (!Number.isInteger(page) || page < 1 || page > 50) throw new SecretServerError("Page must be an integer from 1 to 50");
    return this.download(`/documents/${seg(id)}/pages/${page}${forPrint ? "?purpose=print" : ""}`);
  }
  grantDocument(id: string, grant: DocumentGrantRequest): Promise<{id: string}> {
    if (!!grant.user_id === !!grant.recipient_email) throw new SecretServerError("Specify exactly one user_id or recipient_email");
    return this.post(`/documents/${seg(id)}/grants`, {allow_download: false, allow_print: false, ...grant});
  }
  listDocumentGrants(id: string): Promise<{grants: DocumentGrant[]}> { return this.get(`/documents/${seg(id)}/grants`); }
  revokeDocumentGrant(id: string, grantID: string): Promise<void> { return this.delete(`/documents/${seg(id)}/grants/${seg(grantID)}`); }

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

  /** Assign a named variable. Requires an identity with admin:all. */
  async assignVariable(name: string, assignment: VariableAssignment): Promise<Variable> {
    return this.put<Variable>(`/variables/${seg(name)}`, assignment);
  }
  /** Requires admin:all. */
  async getVariable(name: string): Promise<Variable> { return this.get<Variable>(`/variables/${seg(name)}`); }
  /** Requires admin:all. */
  async listVariables(): Promise<Variable[]> { return (await this.get<{variables: Variable[]}>("/variables")).variables; }
  /** Requires admin:all. */
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

  /** Get a secret value by path: "name", "container/key" or "container/key/2" (version 1..12). */
  async secret(path: string): Promise<string> {
    const parts = secretPath(path);
    if (parts.length === 1) {
      const d = await this.get<{ value?: string; data?: { value?: string } }>(`/secrets/${seg(parts[0])}`);
      return scalar(d);
    }
    const d = await this.get<{ value?: string; data?: Record<string, unknown> }>(`/s/${parts.map(seg).join("/")}`);
    return scalar(d);
  }

  /**
   * Get the full secret: a Secret for a bare name (with its `etag`), or
   * {meta, data} (PathSecret) for "container/key[/version]".
   */
  async getSecret(path: string): Promise<Secret | PathSecret> {
    const parts = secretPath(path);
    if (parts.length === 1) {
      const { data, etag } = await this.requestWithETag<Secret>("GET", `/secrets/${seg(parts[0])}`);
      return withETag(data, etag);
    }
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

  /**
   * Partially update a secret; only the fields you pass are sent. `value`
   * undefined keeps the stored value (null is rejected). In `opts`, undefined
   * keeps a field, null clears it, and "" is a literal empty value. Needs only
   * secrets:write and never reads the secret. With `ifMatch`/`expectedVersion`
   * a stale precondition throws ConflictError carrying the current ETag. The
   * result carries the new `etag`.
   *
   * Minimum server: secretserver.io 3075630 (partial, conditional updates).
   * Throws without sending unless the client has `partialUpdates: true` (or
   * SS_PARTIAL_UPDATES=1) or `ifMatch` is an ETag from getSecret()/updateSecret();
   * a version number, "*" or `expectedVersion` alone does not qualify.
   */
  async updateSecret(name: string, value?: string, opts: UpdateSecretOptions = {}): Promise<Secret> {
    this.requirePartialUpdates(opts.ifMatch);
    if (value === null) throw new SecretServerError("value cannot be null; omit it to keep the current value");
    const body = providedFields({
      data: value === undefined ? undefined : { value },
      description: opts.description,
      tags: opts.tags,
      container_id: opts.containerID,
      expected_version: opts.expectedVersion,
    });
    const { data, etag } = await this.requestWithETag<Secret>("PUT", `/secrets/${seg(name)}`, body, ifMatchHeader(opts.ifMatch));
    return withETag(data, etag);
  }

  async deleteSecret(name: string): Promise<{ message: string }> { return this.delete(`/secrets/${seg(name)}`); }

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
  /**
   * Download certificate material. Text formats (pem, pem-bundle, key) use GET
   * and return a string; pfx/p12 require an export password (1-1024 chars),
   * are sent as POST with the password in the JSON body (never in the URL),
   * and return bytes.
   */
  async downloadCertificate(id: string, opts?: { format?: CertificateTextFormat }): Promise<string>;
  async downloadCertificate(id: string, opts: { format: CertificateBinaryFormat; password: string }): Promise<Uint8Array>;
  async downloadCertificate(
    id: string,
    opts: { format?: CertificateTextFormat | CertificateBinaryFormat; password?: string } = {},
  ): Promise<string | Uint8Array> {
    const format = opts.format ?? "pem";
    const binary = format === "pfx" || format === "p12";
    if (!["pem", "pem-bundle", "key", "pfx", "p12"].includes(format)) throw new SecretServerError("Invalid certificate format");
    if (binary && (!opts.password || opts.password.length > 1024)) throw new SecretServerError("A password of 1-1024 characters is required for pfx/p12 export");
    if (!binary && opts.password !== undefined) throw new SecretServerError("A password is only used with pfx/p12 export");
    const bytes = binary
      ? await readCapped(await this.send("POST", `/certificates/${seg(id)}/download`, { format, password: opts.password }), MAX_RAW_BYTES)
      : await this.download(`/certificates/${seg(id)}/download?${new URLSearchParams({ format })}`);
    return binary ? bytes : new TextDecoder().decode(bytes);
  }

  // -----------------------------------------------------------------------
  // Operation-only cryptographic backends
  // -----------------------------------------------------------------------

  signingKey(keyId: string, backend = "pkcs11"): RemoteSigningKey {
    if (!["pkcs11", "ehsm"].includes(backend) || !keyId) throw new SecretServerError("use an operation-only backend and key ID");
    return new RemoteSigningKey(this, backend, keyId);
  }

  async listCryptoBackends(): Promise<CryptoBackend[]> { return this.get("/crypto/backends"); }

  async listSigningKeys(backend = "pkcs11"): Promise<SigningKey[]> {
    return this.get(`/crypto/signing-keys?backend=${encodeURIComponent(backend)}`);
  }

  /**
   * Sign a message in place on the backend. `message` is the raw payload:
   * bytes, or a string that is UTF-8 encoded. The client base64-encodes it.
   */
  async sign(backend: string, keyId: string, message: Uint8Array | string, purpose: string): Promise<SignResult> {
    const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
    if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > 1024 * 1024) {
      throw new SecretServerError("message must be between 1 byte and 1 MiB");
    }
    return this.post("/crypto/sign", { backend, key_id: keyId, message: bytesToBase64(bytes), purpose });
  }

  // -----------------------------------------------------------------------
  // JKS keystores
  // -----------------------------------------------------------------------

  async listJKSKeystores(): Promise<JKSKeystore[]> { return this.get("/jks-keystores"); }
  /** The result carries the response `etag` for conditional updates. */
  async getJKSKeystore(id: string): Promise<JKSKeystore> {
    const { data, etag } = await this.requestWithETag<JKSKeystore>("GET", `/jks-keystores/${seg(id)}`);
    return withETag(data, etag);
  }
  async createJKSKeystore(input: CreateJKSKeystoreInput): Promise<{ id: string; name: string; store_type: "raw" | "managed"; created_at: string }> {
    return this.post("/jks-keystores", input);
  }
  /**
   * Partially update a keystore; only the fields you pass are sent (undefined
   * keeps, null clears container_id/notes/tags, "" is a literal value). `jks`
   * requires `password`; `password` alone rotates the stored password. A stale
   * `ifMatch` ETag throws ConflictError carrying the current ETag.
   *
   * Minimum server: secretserver.io 3075630 (partial, conditional updates).
   * Throws without sending unless the client has `partialUpdates: true` (or
   * SS_PARTIAL_UPDATES=1) or `ifMatch` is an ETag from getJKSKeystore().
   */
  async updateJKSKeystore(id: string, input: UpdateJKSKeystoreInput, opts: { ifMatch?: string } = {}): Promise<UpdateResult> {
    this.requirePartialUpdates(opts.ifMatch);
    if (input.jks !== undefined && input.password === undefined) throw new SecretServerError("password is required with jks");
    const { data, etag } = await this.requestWithETag<UpdateResult>(
      "PUT", `/jks-keystores/${seg(id)}`, providedFields(input), ifMatchHeader(opts.ifMatch));
    return withETag(data, etag);
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

  async createPassword(name: string, username: string, value: string, url?: string): Promise<Password> {
    return this.post("/passwords", { name, username, value, url });
  }

  /** Generate and STORE a new password record; the generated secret is in `value`. */
  async generatePassword(name: string, opts: GeneratePasswordOptions = {}): Promise<Password> {
    const length = opts.length ?? 32;
    if (!name) throw new SecretServerError("name is required");
    if (!Number.isInteger(length) || length < 8 || length > 128) throw new SecretServerError("length must be between 8 and 128");
    return this.post("/passwords/generate", {
      name,
      description: opts.description,
      username: opts.username,
      url: opts.url,
      tags: opts.tags,
      length,
      use_lowercase: opts.useLowercase ?? true,
      use_uppercase: opts.useUppercase ?? true,
      use_digits: opts.useDigits ?? true,
      use_symbols: opts.useSymbols ?? true,
    });
  }

  // -----------------------------------------------------------------------
  // API Tokens
  // -----------------------------------------------------------------------

  async listAPITokens(): Promise<APIToken[]> { return this.getList("/api-tokens", "tokens"); }
  async createAPIToken(
    name: string,
    service: string,
    value: string,
    environment: APITokenEnvironment,
    opts: { description?: string; expiresAt?: Date } = {},
  ): Promise<APIToken> {
    if (!["production", "staging", "development"].includes(environment)) {
      throw new SecretServerError("environment must be production, staging or development");
    }
    return this.post("/api-tokens", {
      name, service, value, environment,
      description: opts.description,
      expires_at: opts.expiresAt?.toISOString(),
    });
  }
  /** Replace a token's stored value with `value`. */
  async rotateAPIToken(id: string, value: string): Promise<APIToken> {
    return this.post(`/api-tokens/${seg(id)}/rotate`, { value });
  }

  // -----------------------------------------------------------------------
  // GPG Keys
  // -----------------------------------------------------------------------

  async listGPGKeys(): Promise<unknown[]> { return this.getList("/gpg-keys", "keys"); }
  async generateGPGKey(
    name: string,
    email: string,
    opts: { algorithm?: GPGAlgorithm; comment?: string; passphrase?: string } = {},
  ): Promise<GPGKeyGenerated> {
    const algorithm = opts.algorithm ?? "ED25519";
    if (!["RSA2048", "RSA4096", "ED25519"].includes(algorithm)) throw new SecretServerError("algorithm must be RSA2048, RSA4096 or ED25519");
    return this.post("/gpg-keys/generate", { name, email, algorithm, comment: opts.comment, passphrase: opts.passphrase });
  }
  async exportGPGKey(id: string, format: "public" | "private" = "public"): Promise<GPGExport> {
    if (format !== "public" && format !== "private") throw new SecretServerError("format must be public or private");
    return this.get(`/gpg-keys/${seg(id)}/export?${new URLSearchParams({ format })}`);
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
      delete: async (id: string) => this.delete<{ message: string }>(`/${resource}/${seg(id)}`),
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

  async getHistory(secretType: SecretType, secretId: string): Promise<VersionEntry[]> {
    const d = await this.get<VersionEntry[] | null>(`/${secretTypeSeg(secretType)}/${seg(secretId)}/history`);
    if (d === null || d === undefined) return [];
    if (!Array.isArray(d)) throw new SecretServerError("Invalid history response");
    return d;
  }

  async getVersion(secretType: SecretType, secretId: string, version: number): Promise<unknown> {
    return this.get(`/${secretTypeSeg(secretType)}/${seg(secretId)}/history/${seg(version)}`);
  }

  async getHistorySettings(secretType: SecretType, secretId: string): Promise<{ history_enabled: boolean; max_versions: number }> {
    return this.get(`/${secretTypeSeg(secretType)}/${seg(secretId)}/history-settings`);
  }

  async updateHistorySettings(secretType: SecretType, secretId: string, enabled: boolean, maxVersions: number): Promise<{ message: string }> {
    return this.put(`/${secretTypeSeg(secretType)}/${seg(secretId)}/history-settings`, { history_enabled: enabled, max_versions: maxVersions });
  }

  // -----------------------------------------------------------------------
  // Sharing & temp access
  // -----------------------------------------------------------------------

  /** Share with exactly one user or group (UUIDs). */
  async share(
    secretType: SecretType,
    secretId: string,
    target: ShareTarget,
    permission: "read" | "manage" = "read",
    expiresAt?: Date,
  ): Promise<ShareResult> {
    const userId = target?.userId;
    const groupId = target?.groupId;
    if (Boolean(userId) === Boolean(groupId)) throw new SecretServerError("share requires exactly one of userId or groupId");
    if (permission !== "read" && permission !== "manage") throw new SecretServerError("permission must be read or manage");
    return this.post(`/${secretTypeSeg(secretType)}/${seg(secretId)}/shares`, {
      shared_with_user_id: userId,
      shared_with_group_id: groupId,
      permission,
      expires_at: expiresAt?.toISOString(),
    });
  }

  /** Create a token-gated read grant lasting 60..86400 seconds. */
  async createTempAccess(secretType: SecretType, secretId: string, durationSeconds = 900): Promise<TempAccessResult> {
    if (!Number.isInteger(durationSeconds) || durationSeconds < 60 || durationSeconds > 86400) {
      throw new SecretServerError("durationSeconds must be between 60 and 86400");
    }
    return this.post(`/${secretTypeSeg(secretType)}/${seg(secretId)}/temp-access`, { duration_seconds: durationSeconds });
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

  async getAuditLogs(opts: AuditLogQuery = {}): Promise<{ logs: unknown[]; total: number }> {
    const q = new URLSearchParams();
    for (const [key, value] of Object.entries(opts)) {
      if (value === undefined || value === null) continue;
      q.set(key, value instanceof Date ? value.toISOString() : String(value));
    }
    const qs = q.toString();
    return this.get(`/audit/logs${qs ? `?${qs}` : ""}`);
  }

  async exportAuditLogs(): Promise<{ logs: unknown[]; total: number; exported_at: string }> {
    return this.get("/audit/logs/export?format=json");
  }

  // -----------------------------------------------------------------------
  // OpenSSL Keys
  // -----------------------------------------------------------------------

  async listOpenSSLKeys(): Promise<unknown[]> { return this.getList("/openssl-keys", "openssl_keys", "keys"); }
  async getOpenSSLKey(id: string): Promise<unknown> { return this.get(`/openssl-keys/${seg(id)}`); }

  async generateOpenSSLKey(
    name: string,
    algorithm: OpenSSLAlgorithm = "rsa",
    opts: OpenSSLKeyOptions = {},
  ): Promise<{ id: string; name: string; algorithm: OpenSSLAlgorithm; public_key: string; created_at: string }> {
    return this.post("/openssl-keys/generate", {
      name, algorithm, key_size: opts.keySize, curve: opts.curve,
      description: opts.description, passphrase: opts.passphrase,
    });
  }

  async importOpenSSLKey(
    name: string,
    privateKey: string,
    algorithm: OpenSSLAlgorithm,
    opts: OpenSSLKeyOptions & { publicKey?: string } = {},
  ): Promise<{ id: string; name: string; algorithm: OpenSSLAlgorithm; created_at: string }> {
    return this.post("/openssl-keys/import", {
      name, algorithm, private_key: privateKey, public_key: opts.publicKey,
      key_size: opts.keySize, curve: opts.curve, description: opts.description, passphrase: opts.passphrase,
    });
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

  /** `secret`, when given, is used by the server to sign deliveries. */
  async createWebhook(name: string, url: string, events: string[], secret?: string): Promise<unknown> {
    return this.post("/webhooks", { name, url, secret, events });
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

  // Exports are tenant-wide. With every include flag false (the default) the
  // server exports all categories; `tags` narrows the result.

  async exportToKeychain(opts: ExportOptions = {}): Promise<unknown> {
    return this.post("/export/keychain", exportBody(opts));
  }

  async exportToCredentialManager(opts: ExportOptions = {}): Promise<unknown> {
    return this.post("/export/credential-manager", exportBody(opts));
  }

  async exportToJSON(opts: ExportOptions = {}): Promise<{ format: "json"; items: unknown[] | null; count: number; exported_at: string; version: string }> {
    return this.post("/export/json", exportBody(opts));
  }

  // -----------------------------------------------------------------------
  // YubiKey OTP Credentials
  // -----------------------------------------------------------------------

  async listYubikeys(): Promise<YubikeyCredential[]> { return this.get("/yubikeys"); }
  /** The result carries the response `etag` for conditional updates. */
  async getYubikey(id: string): Promise<YubikeyCredential> {
    const { data, etag } = await this.requestWithETag<YubikeyCredential>("GET", `/yubikeys/${seg(id)}`);
    return withETag(data, etag);
  }

  async createYubikey(
    name: string, publicId: string, clientId: string, apiKey: string,
    opts: { serialNumber?: string; validationServer?: string; notes?: string } = {}
  ): Promise<{ id: string; name: string; public_id: string; created_at: string }> {
    return this.post("/yubikeys", {
      name, public_id: publicId, client_id: clientId, api_key: apiKey,
      serial_number: opts.serialNumber, validation_server: opts.validationServer, notes: opts.notes,
    });
  }

  /**
   * Partially update a YubiKey credential; only the fields you pass are sent
   * (undefined keeps, null clears container_id/serial_number/notes/tags, "" is
   * a literal value). A stale `ifMatch` ETag throws ConflictError carrying the
   * current ETag.
   *
   * Minimum server: secretserver.io 3075630 (partial, conditional updates).
   * Throws without sending unless the client has `partialUpdates: true` (or
   * SS_PARTIAL_UPDATES=1) or `ifMatch` is an ETag from getYubikey().
   */
  async updateYubikey(id: string, data: UpdateYubikeyInput, opts: { ifMatch?: string } = {}): Promise<UpdateResult> {
    this.requirePartialUpdates(opts.ifMatch);
    if (data.public_id !== undefined && (typeof data.public_id !== "string" || data.public_id.length !== 12)) {
      throw new SecretServerError("public_id must be exactly 12 modhex characters");
    }
    const { data: result, etag } = await this.requestWithETag<UpdateResult>(
      "PUT", `/yubikeys/${seg(id)}`, providedFields(data), ifMatchHeader(opts.ifMatch));
    return withETag(result, etag);
  }

  async deleteYubikey(id: string): Promise<void> { return this.delete(`/yubikeys/${seg(id)}`); }

  /** Validate a Yubico OTP against the stored YubiKey configuration */
  async validateYubikeyOTP(id: string, otp: string): Promise<YubikeyValidateResult> {
    return this.post(`/yubikeys/${seg(id)}/validate`, { otp });
  }

  // -----------------------------------------------------------------------
  // TOTP Authenticators
  // -----------------------------------------------------------------------

  /** List all TOTP authenticator tokens */
  async listTOTPTokens(): Promise<TOTPToken[]> { return this.getList("/totp-tokens", "tokens"); }

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
   * Returns 'code', 'expires_in' (seconds remaining) and 'period'.
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
   * Returns an object with the otpauth:// 'uri'.
   */
  async exportTOTPToURI(id: string): Promise<TOTPExport> {
    return this.get(`/totp-tokens/${seg(id)}/export`);
  }
}

export default SecretServerClient;

function exportBody(opts: ExportOptions) {
  return {
    include_passwords: opts.includePasswords ?? false,
    include_secrets: opts.includeSecrets ?? false,
    include_ssh_keys: opts.includeSSHKeys ?? false,
    include_certificates: opts.includeCertificates ?? false,
    tags: opts.tags,
  };
}

function scalar(payload: {value?: string; data?: Record<string, unknown>}): string {
 const data=payload.data ?? payload;
 for (const key of ["value","password","token","key","passphrase","bind_password","certificate"]) {
 const value=(data as Record<string,unknown>)[key];if(typeof value==="string") return value;
 }
 throw new SecretServerError("Secret response has no supported scalar field");
}

export interface DocumentUpload { id: string; name: string; pages: number; size_bytes: number; }
export interface ProtectedDocument extends DocumentUpload { created_at: string; can_manage: boolean; can_download: boolean; can_print: boolean; }
export interface DocumentList { documents: ProtectedDocument[]; can_manage: boolean; limit: number; }
export interface DocumentGrantRequest { user_id?: string; recipient_email?: string; expires_at: string; allow_download?: boolean; allow_print?: boolean; }
export interface DocumentGrant extends DocumentGrantRequest { id: string; user_id: string; revoked_at: string | null; }

/** A server-side signing reference. It never imports or exports private key bytes. */
export class RemoteSigningKey {
  #client: SecretServerClient;
  #backend: string;
  #keyId: string;
  constructor(client: SecretServerClient, backend: string, keyId: string) { this.#client = client; this.#backend = backend; this.#keyId = keyId; }
  sign(message: Uint8Array, purpose: string): Promise<SignResult> { return this.#client.sign(this.#backend, this.#keyId, message, purpose); }
  toJSON(): never { throw new SecretServerError("authenticated signing handles cannot be serialized"); }
  [Symbol.for("nodejs.util.inspect.custom")](): string { return "RemoteSigningKey { operation-only }"; }
}
