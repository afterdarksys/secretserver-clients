import assert from "node:assert/strict";
import { SecretServerClient } from "../dist/index.js";

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
