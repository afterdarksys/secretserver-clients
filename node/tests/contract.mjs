import assert from "node:assert/strict";
import { SecretServerClient, SecretServerError, ConflictError } from "../dist/index.js";

const calls = [];
const fetchFn = async (url, init) => {
  calls.push({ url, init });
  const body = url.endsWith("/secrets")
    ? { secrets: [{ id: "1", name: "db" }], total: 1 }
    : {};
  return { ok: true, status: 200, text: async () => JSON.stringify(body) };
};

const client = new SecretServerClient({
  apiKey: "sk_test",
  apiUrl: "https://example.test/api/v1",
  fetchFn,
});

const secrets = await client.listSecrets();
await client.updateSecret("prod/db", "new");
await client.enrollCertificate("wildcard", "example.test", ["www.example.test"]);

assert.equal(secrets[0].name, "db");
assert.equal(calls[0].url, "https://example.test/api/v1/secrets");
assert.equal(calls[1].init.method, "PUT");
assert.equal(calls[1].url, "https://example.test/api/v1/secrets/prod%2Fdb");
assert.deepEqual(JSON.parse(calls[1].init.body), { data: { value: "new" } });
const enrollment = JSON.parse(calls[2].init.body);
assert.deepEqual(enrollment.dns_names, ["www.example.test"]);
assert.equal("sans" in enrollment, false);

for (const value of ['', 'actual-value']) {
  const scalarClient = new SecretServerClient({apiKey:'test', fetchFn:async()=>({ok:true,status:200,text:async()=>JSON.stringify({meta:{value:''},data:{value}})})});
  assert.equal(await scalarClient.secret('prod/db'),value);
}
const unsupported = new SecretServerClient({apiKey:'test',fetchFn:async()=>({ok:true,status:200,text:async()=>JSON.stringify({meta:{value:''},data:{unsupported:'do-not-log'}})})});
await assert.rejects(unsupported.secret('prod/db'), /no supported scalar/);
const denied = new SecretServerClient({apiKey:'test',fetchFn:async()=>({ok:false,status:403,text:async()=>JSON.stringify({error:'do-not-log'})})});
await assert.rejects(denied.secret('prod/db'), e=>e.statusCode===403&&!e.message.includes('do-not-log'));
assert.equal(calls[0].init.redirect,'error');
assert.ok(calls[0].init.signal);

// --- Security policy (negative tests) ---
const KEY = 'sk_live_must_never_leak';
const ok = (body, init = {}) => async (url, req) => new Response(body, { status: 200, ...init });

// 1. Base URL: https only, plain http only for loopback, never userinfo; errors never echo the key.
for (const bad of ['http://api.example.test', 'http://10.0.0.5:8080', 'ftp://api.example.test', 'https://user:pass@api.example.test', 'https://tok@api.example.test', 'not a url', 'https://api.example.test/?x=1']) {
  assert.throws(() => new SecretServerClient({ apiKey: KEY, apiUrl: bad, fetchFn }), e => e instanceof SecretServerError && !e.message.includes(KEY), bad);
}
for (const good of ['https://api.example.test', 'http://localhost:8080', 'http://127.0.0.1:1234/api/v1', 'http://[::1]:9000']) {
  new SecretServerClient({ apiKey: KEY, apiUrl: good, fetchFn });
}

// 4. Response size cap: streamed body, declared content-length and text-only fallback all fail closed.
const big = 4 * 1024 * 1024 + 1;
const streamed = new SecretServerClient({ apiKey: KEY, fetchFn: async () => new Response(new ReadableStream({
  pull(c) { c.enqueue(new Uint8Array(1024 * 1024).fill(0x20)); },
}), { status: 200 }) });
await assert.rejects(streamed.listSecrets(), /exceeds size limit/);
const declared = new SecretServerClient({ apiKey: KEY, fetchFn: ok('[]', { headers: { 'content-length': String(big) } }) });
await assert.rejects(declared.listSecrets(), /exceeds size limit/);
const textOnly = new SecretServerClient({ apiKey: KEY, fetchFn: async () => ({ ok: true, status: 200, text: async () => ' '.repeat(big) }) });
await assert.rejects(textOnly.listSecrets(), /exceeds size limit/);
const atCap = new SecretServerClient({ apiKey: KEY, fetchFn: ok('[' + ' '.repeat(4 * 1024 * 1024 - 2) + ']') });
assert.deepEqual(await atCap.listSecrets(), []);

// 6. Success responses that are not JSON raise; the error does not echo the body. Empty body -> undefined.
const notJson = new SecretServerClient({ apiKey: KEY, fetchFn: ok('<html>secret-body-marker</html>') });
await assert.rejects(notJson.request('GET', '/secrets'), e => /invalid JSON/.test(e.message) && !e.message.includes('secret-body-marker'));
const empty = new SecretServerClient({ apiKey: KEY, fetchFn: ok('') });
assert.equal(await empty.request('DELETE', '/x'), undefined);
const nullList = new SecretServerClient({ apiKey: KEY, fetchFn: ok('null') });
assert.deepEqual(await nullList.listSecrets(), []);

// 5. Errors never include the API key or the server body.
for (const status of [400, 401, 403, 404, 500]) {
  const failing = new SecretServerClient({ apiKey: KEY, fetchFn: ok(JSON.stringify({ error: `echo ${KEY} server-body-marker` }), { status }) });
  await assert.rejects(failing.listSecrets(), e => e.statusCode === status && e.message === `SecretServer request failed (HTTP ${status})`);
}

// 7. Path segments are percent-encoded; empty and dot segments are refused before any request.
const seen = [];
const recorder = new SecretServerClient({ apiKey: KEY, apiUrl: 'https://example.test', fetchFn: async (url, init) => { seen.push({ url, init }); return new Response('{}', { status: 200 }); } });
await recorder.getCertificate('a/b?c=d#e');
assert.equal(seen.at(-1).url, 'https://example.test/api/v1/certificates/a%2Fb%3Fc%3Dd%23e');
await recorder.deleteGPGKey('../../admin');
assert.equal(seen.at(-1).url, 'https://example.test/api/v1/gpg-keys/..%2F..%2Fadmin');
await recorder.computerCredentials.get('x/../y');
assert.equal(seen.at(-1).url, 'https://example.test/api/v1/computer-credentials/x%2F..%2Fy');
const before = seen.length;
for (const bad of ['..', '.', '']) {
  await assert.rejects(recorder.getYubikey(bad), /Invalid path segment/);
  await assert.rejects(recorder.getTOTPToken(bad), /Invalid path segment/);
}
assert.equal(seen.length, before);

// 3. Redirects are never followed.
assert.equal(seen.at(-1).init.redirect, 'error');


// --- Contract fixes against the server handlers ---
function stub(routes) {
  const log = [];
  const client = new SecretServerClient({ apiKey: KEY, apiUrl: 'https://example.test', fetchFn: async (url, init) => {
    const path = url.replace('https://example.test/api/v1', '');
    // headers is non-enumerable so deepEqual on log entries compares path/method/body only.
    log.push(Object.defineProperty({ path, method: init.method, body: init.body ? JSON.parse(init.body) : undefined }, 'headers', { value: init.headers }));
    const route = routes[`${init.method} ${path.split('?')[0]}`];
    const hit = typeof route === 'function' ? route() : route;
    if (hit instanceof Response) return hit;
    if (hit instanceof Uint8Array || typeof hit === 'string') return new Response(hit, { status: 200 });
    return new Response(JSON.stringify(hit ?? {}), { status: 200 });
  } });
  return { client, log, last: () => log.at(-1) };
}

// updateSecret is a partial PUT with no pre-read: omitted = keep, null = clear, "" = literal.
{
  const cid = '11111111-1111-1111-1111-111111111111';
  const etagged = () => new Response(JSON.stringify({ id: 'x', name: 'db', version: 3 }), { status: 200, headers: { etag: '"2026-01-02T03:04:05.123456Z"' } });
  const { client, log, last } = stub({ 'PUT /secrets/db': etagged, 'GET /secrets/db': etagged });
  const updated = await client.updateSecret('db', 'v2');
  assert.equal(log.length, 1);
  assert.deepEqual(last(), { path: '/secrets/db', method: 'PUT', body: { data: { value: 'v2' } } });
  assert.equal('If-Match' in last().headers, false);
  assert.equal(updated.etag, '"2026-01-02T03:04:05.123456Z"');
  await client.updateSecret('db', undefined, { description: null, tags: null, containerID: null });
  assert.deepEqual(last().body, { description: null, tags: null, container_id: null });
  await client.updateSecret('db', undefined, { description: '', tags: [], containerID: cid });
  assert.deepEqual(last().body, { description: '', tags: [], container_id: cid });
  await client.updateSecret('db', '');
  assert.deepEqual(last().body, { data: { value: '' } });
  await client.updateSecret('db', undefined, { description: 'd', tags: undefined });
  assert.deepEqual(last().body, { description: 'd' });
  assert.equal(log.every(e => e.method === 'PUT'), true);
  // If-Match: ETag string or version number; expected_version travels in the body.
  await client.updateSecret('db', 'v4', { ifMatch: '"2026-01-02T03:04:05.123456Z"' });
  assert.equal(last().headers['If-Match'], '"2026-01-02T03:04:05.123456Z"');
  await client.updateSecret('db', 'v5', { ifMatch: 3, expectedVersion: 3 });
  assert.equal(last().headers['If-Match'], '3');
  assert.deepEqual(last().body, { data: { value: 'v5' }, expected_version: 3 });
  const n = log.length;
  await assert.rejects(client.updateSecret('db', null), /cannot be null/);
  for (const bad of [-1, 1.5, '', ' ', 'a\r\nX-Injected: 1']) {
    await assert.rejects(client.updateSecret('db', 'v', { ifMatch: bad }), SecretServerError, String(bad));
  }
  assert.equal(log.length, n);
  // GET by bare name exposes the ETag.
  assert.equal((await client.getSecret('db')).etag, '"2026-01-02T03:04:05.123456Z"');
}

// HTTP 409 -> ConflictError carrying the current ETag; message free of key and body.
{
  const conflict = () => new Response(JSON.stringify({ error: `stale ${KEY} conflict-body-marker` }), { status: 409, headers: { etag: '"2026-02-02T00:00:00.5Z"' } });
  const { client } = stub({ 'PUT /secrets/db': conflict, 'PUT /jks-keystores/j1': conflict, 'PUT /yubikeys/y1': conflict });
  for (const call of [
    () => client.updateSecret('db', 'v', { ifMatch: '"old"' }),
    () => client.updateJKSKeystore('j1', { notes: null }, { ifMatch: '"old"' }),
    () => client.updateYubikey('y1', { notes: null }, { ifMatch: 'W/"old"' }),
  ]) {
    await assert.rejects(call(), e => e instanceof ConflictError && e instanceof SecretServerError && e.statusCode === 409
      && e.etag === '"2026-02-02T00:00:00.5Z"' && e.message === 'SecretServer request failed (HTTP 409)'
      && !e.message.includes(KEY) && !e.message.includes('conflict-body-marker'));
  }
  const bare = new SecretServerClient({ apiKey: KEY, fetchFn: async () => ({ ok: false, status: 409, text: async () => '' }) });
  await assert.rejects(bare.updateSecret('db', 'v'), e => e instanceof ConflictError && e.etag === undefined);
}

// secret()/getSecret(): 1..3 segments, version 1..12, container path returns {meta,data}.
{
  const { client, log } = stub({ 'GET /s/prod/db': { meta: { value: 'v' }, data: { value: 'v' } } });
  assert.deepEqual(await client.getSecret('prod/db'), { meta: { value: 'v' }, data: { value: 'v' } });
  for (const bad of ['a/b/c/d', 'a//b', 'a/b/0', 'a/b/13', 'a/b/x']) {
    await assert.rejects(client.secret(bad), SecretServerError, bad);
    await assert.rejects(client.getSecret(bad), SecretServerError, bad);
  }
  assert.equal(log.length, 1);
  await assert.rejects(client.secret('prod/db/12'), /no supported scalar/);
  assert.equal(log.at(-1).path, '/s/prod/db/12');
}

// :type validation, bare-array history, share by user/group id, temp access range.
{
  const { client, log, last } = stub({ 'GET /secret/abc/history': [{ id: 'h', version_num: 1 }] });
  assert.deepEqual(await client.getHistory('secret', 'abc'), [{ id: 'h', version_num: 1 }]);
  await assert.rejects(client.getHistory('secrets', 'abc'), /Invalid secret type/);
  await assert.rejects(client.getHistory('../admin', 'abc'), /Invalid secret type/);
  await client.share('password', 'abc', { userId: 'u-1' }, 'manage');
  assert.deepEqual(last().body, { shared_with_user_id: 'u-1', permission: 'manage' });
  await client.share('password', 'abc', { groupId: 'g-1' });
  assert.deepEqual(last().body, { shared_with_group_id: 'g-1', permission: 'read' });
  const n = log.length;
  await assert.rejects(client.share('password', 'abc', { userId: 'u', groupId: 'g' }), /exactly one/);
  await assert.rejects(client.share('password', 'abc', {}), /exactly one/);
  await assert.rejects(client.share('password', 'abc', 'someone@example.test'), /exactly one/);
  await assert.rejects(client.createTempAccess('secret', 'abc', 59), /between 60 and 86400/);
  await assert.rejects(client.createTempAccess('secret', 'abc', 86401), /between 60 and 86400/);
  assert.equal(log.length, n);
  await client.createTempAccess('secret', 'abc', 60);
  assert.deepEqual(last(), { path: '/secret/abc/temp-access', method: 'POST', body: { duration_seconds: 60 } });
}

// Passwords, API tokens, GPG, OpenSSL request shapes.
{
  const { client, last } = stub({});
  await client.createPassword('p', 'u', 's3cret');
  assert.deepEqual(last().body, { name: 'p', username: 'u', value: 's3cret' });
  await client.generatePassword('gen', { length: 20, useSymbols: false });
  assert.deepEqual(last().body, { name: 'gen', length: 20, use_lowercase: true, use_uppercase: true, use_digits: true, use_symbols: false });
  await assert.rejects(client.generatePassword('gen', { length: 7 }), /between 8 and 128/);
  await assert.rejects(client.generatePassword('gen', { length: 129 }), /between 8 and 128/);
  await assert.rejects(client.generatePassword(''), /name is required/);
  await client.createAPIToken('t', 'svc', 'tok-value', 'staging');
  assert.deepEqual(last().body, { name: 't', service: 'svc', value: 'tok-value', environment: 'staging' });
  await assert.rejects(client.createAPIToken('t', 'svc', 'v', 'prod'), /environment/);
  await client.rotateAPIToken('id/1', 'new-value');
  assert.deepEqual(last(), { path: '/api-tokens/id%2F1/rotate', method: 'POST', body: { value: 'new-value' } });
  await client.generateGPGKey('n', 'n@example.test', { algorithm: 'RSA4096' });
  assert.deepEqual(last().body, { name: 'n', email: 'n@example.test', algorithm: 'RSA4096' });
  await assert.rejects(client.generateGPGKey('n', 'e@example.test', { algorithm: 'DSA' }), /algorithm/);
  await client.exportGPGKey('k', 'private');
  assert.equal(last().path, '/gpg-keys/k/export?format=private');
  await assert.rejects(client.exportGPGKey('k', 'secret'), /format/);
  await client.generateOpenSSLKey('o', 'ecdsa', { curve: 'P-256' });
  assert.deepEqual(last().body, { name: 'o', algorithm: 'ecdsa', curve: 'P-256' });
  await client.importOpenSSLKey('o', 'PEM', 'rsa', { keySize: 2048 });
  assert.deepEqual(last().body, { name: 'o', algorithm: 'rsa', private_key: 'PEM', key_size: 2048 });
}

// TOTP envelope, certificates as raw text/bytes, sign base64, exports, webhook, audit.
{
  const pfx = new Uint8Array([0x30, 0x82, 0x00, 0xff]);
  const { client, last } = stub({
    'GET /totp-tokens': { tokens: [{ id: 't1' }], total: 1 },
    'GET /certificates/c1/download': '-----BEGIN CERTIFICATE-----\n',
  });
  assert.deepEqual(await client.listTOTPTokens(), [{ id: 't1' }]);
  assert.equal(await client.downloadCertificate('c1'), '-----BEGIN CERTIFICATE-----\n');
  assert.equal(last().path, '/certificates/c1/download?format=pem');
  await assert.rejects(client.downloadCertificate('c1', { format: 'pfx' }), /password is required/);
  await assert.rejects(client.downloadCertificate('c1', { format: 'der' }), /Invalid certificate format/);
  const binary = stub({ 'GET /certificates/c1/download': pfx });
  const bytes = await binary.client.downloadCertificate('c1', { format: 'p12', password: 'p&w=1' });
  assert.ok(bytes instanceof Uint8Array);
  assert.deepEqual([...bytes], [...pfx]);
  assert.equal(binary.last().path, '/certificates/c1/download?format=p12&password=p%26w%3D1');

  await client.sign('pkcs11', 'k1', new Uint8Array([0, 255, 1]), 'test');
  assert.deepEqual(last().body, { backend: 'pkcs11', key_id: 'k1', message: 'AP8B', purpose: 'test' });
  await client.sign('pkcs11', 'k1', 'héllo', 'test');
  assert.equal(last().body.message, Buffer.from('héllo', 'utf8').toString('base64'));
  await assert.rejects(client.sign('pkcs11', 'k1', '', 'test'), /between 1 byte and 1 MiB/);

  await client.exportToJSON({ includeSecrets: true, tags: ['prod'] });
  assert.deepEqual(last().body, { include_passwords: false, include_secrets: true, include_ssh_keys: false, include_certificates: false, tags: ['prod'] });
  await client.exportToKeychain();
  assert.equal('items' in last().body, false);

  await client.createWebhook('w', 'https://hooks.example.test', ['secret.update'], 'whsec');
  assert.deepEqual(last().body, { name: 'w', url: 'https://hooks.example.test', secret: 'whsec', events: ['secret.update'] });

  await client.getAuditLogs({ limit: 5, action: undefined, resource: 'a b&c', start_date: new Date('2026-01-02T03:04:05Z') });
  assert.equal(last().path, '/audit/logs?limit=5&resource=a+b%26c&start_date=2026-01-02T03%3A04%3A05.000Z');
  await client.exportAuditLogs();
  assert.equal(last().path, '/audit/logs/export?format=json');
}

// JKS / YubiKey updates are partial PUTs with no pre-read; gets and updates expose the ETag.
{
  const tagged = (body, etag) => new Response(JSON.stringify(body), { status: 200, headers: { etag } });
  const { client, log, last } = stub({
    'GET /jks-keystores/j1': () => tagged({ id: 'j1', name: 'ks' }, '"j-etag"'),
    'PUT /jks-keystores/j1': () => tagged({ message: 'updated' }, '"j-etag-2"'),
    'GET /yubikeys/y1': () => tagged({ id: 'y1', name: 'yk' }, '"y-etag"'),
    'PUT /yubikeys/y1': () => tagged({ message: 'updated' }, '"y-etag-2"'),
  });
  assert.equal((await client.getJKSKeystore('j1')).etag, '"j-etag"');
  assert.deepEqual(await client.updateJKSKeystore('j1', { notes: null, tags: undefined, password: 'rotated' }, { ifMatch: '"j-etag"' }), { message: 'updated', etag: '"j-etag-2"' });
  assert.deepEqual(last().body, { notes: null, password: 'rotated' });
  assert.equal(last().headers['If-Match'], '"j-etag"');
  await client.updateJKSKeystore('j1', { notes: '', container_id: null });
  assert.deepEqual(last().body, { notes: '', container_id: null });
  assert.equal('If-Match' in last().headers, false);
  assert.equal((await client.getYubikey('y1')).etag, '"y-etag"');
  assert.deepEqual(await client.updateYubikey('y1', { name: 'renamed', serial_number: null }), { message: 'updated', etag: '"y-etag-2"' });
  assert.deepEqual(last().body, { name: 'renamed', serial_number: null });
  await client.updateYubikey('y1', { notes: '', api_key: 'c2VjcmV0' }, { ifMatch: '"y-etag-2"' });
  assert.deepEqual(last().body, { notes: '', api_key: 'c2VjcmV0' });
  assert.equal(log.filter(e => e.method === 'GET').length, 2);
  const n = log.length;
  await assert.rejects(client.updateJKSKeystore('j1', { jks: 'AAAA' }), /password is required/);
  await assert.rejects(client.updateYubikey('y1', { public_id: 'short' }), /12 modhex/);
  await assert.rejects(client.updateYubikey('y1', { public_id: null }), /12 modhex/);
  assert.equal(log.length, n);
}

console.log('contract + security tests PASS');
