import assert from "node:assert/strict";
import { SecretServerClient, SecretServerError } from "../dist/index.js";

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
assert.equal(JSON.parse(calls[1].init.body).name, "prod/db");
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

console.log('contract + security tests PASS');
