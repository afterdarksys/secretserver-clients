// cliCredentialProvider against fake `ss` executables (no real CLI or server).
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SecretServerClient, SecretServerError, AuthError, cliCredentialProvider } from "../dist/index.js";

delete process.env.SS_API_URL;
const TOKEN = "eyJ.cli-session-token-do-not-leak.sig";

// A fake `ss` that counts its runs, rejects any argv but the documented one, then runs body.
function fakeSS(body) {
  const dir = mkdtempSync(join(tmpdir(), "fake-ss-"));
  const path = join(dir, "ss"), count = join(dir, "count");
  writeFileSync(path, `#!/bin/sh
echo run >> '${count}'
if [ "$#" -ne 4 ] || [ "$1" != auth ] || [ "$2" != print-access-token ] || [ "$3" != --format ] || [ "$4" != json ]; then
  echo "unexpected argv: $*" >&2; exit 1
fi
${body}
`, { mode: 0o700 });
  return { path, runs: () => existsSync(count) ? readFileSync(count, "utf8").split("\n").filter(Boolean).length : 0 };
}
const tokenJSON = (expiresInMs, apiUrl = "", token = TOKEN) =>
  `printf '%s' '${JSON.stringify({ access_token: token, expires_at: new Date(Date.now() + expiresInMs).toISOString().replace(/\.\d+Z$/, "Z"), api_url: apiUrl, tenant_id: "t-1" })}'`;
const noToken = (e) => !e.message.includes(TOKEN) && !String(e.stack).includes(TOKEN) && !JSON.stringify(e).includes(TOKEN);

// Success + cached reuse.
{
  const ss = fakeSS(tokenJSON(3600_000, "https://api.example.test"));
  const p = cliCredentialProvider({ cliPath: ss.path });
  for (let i = 0; i < 3; i++) assert.equal(await p(), TOKEN);
  assert.equal(await p.apiUrl(), "https://api.example.test");
  assert.equal(ss.runs(), 1, "token is cached until 60 s before expiry");
  // Concurrent first calls share one CLI run.
  const ss2 = fakeSS(tokenJSON(3600_000));
  const p2 = cliCredentialProvider({ cliPath: ss2.path });
  await Promise.all([p2(), p2(), p2()]);
  assert.equal(ss2.runs(), 1);
}

// Refresh when the token expires within 60 s.
{
  const ss = fakeSS(tokenJSON(30_000));
  const p = cliCredentialProvider({ cliPath: ss.path });
  await p(); await p();
  assert.equal(ss.runs(), 2);
}

// SS_CLI_PATH is honoured.
{
  const ss = fakeSS(tokenJSON(3600_000));
  process.env.SS_CLI_PATH = ss.path;
  assert.equal(await cliCredentialProvider()(), TOKEN);
  delete process.env.SS_CLI_PATH;
  assert.equal(ss.runs(), 1);
}

// Exit 2: AuthError telling the user to run `ss login`.
{
  const p = cliCredentialProvider({ cliPath: fakeSS(`echo "not logged in" >&2; exit 2`).path });
  await assert.rejects(p(), (e) => e instanceof AuthError && e.message.includes("ss login"));
}

// Failures fail closed and never leak the token.
const bigOut = `head -c 70000 /dev/zero | tr '\\0' a; ${tokenJSON(3600_000)}`;
for (const [name, body, want] of [
  ["exit 1", `echo "network unreachable" >&2; printf '${TOKEN}'; exit 1`, /exit 1\): network unreachable/],
  ["malformed json", `printf '{"access_token":"${TOKEN}",'`, /invalid JSON/],
  ["bad expires_at", `printf '{"access_token":"${TOKEN}","expires_at":"soon"}'`, /expires_at/],
  ["empty token", `printf '{"access_token":"","expires_at":"2099-01-01T00:00:00Z"}'`, /access_token/],
  ["header injection", `printf '{"access_token":"a\\\\r\\\\nX: y","expires_at":"2099-01-01T00:00:00Z"}'`, /access_token/],
  ["oversized stdout", bigOut, /exceeds 65536 bytes/],
]) {
  const p = cliCredentialProvider({ cliPath: fakeSS(body).path });
  await assert.rejects(p(), (e) => e instanceof SecretServerError && !(e instanceof AuthError) && want.test(e.message) && noToken(e), name);
}

// Timeout (configurable so the test is fast).
{
  const p = cliCredentialProvider({ cliPath: fakeSS("exec sleep 10").path, timeoutMs: 200 });
  const start = Date.now();
  await assert.rejects(p(), /timed out/);
  assert.ok(Date.now() - start < 5000);
}

// Missing binary.
await assert.rejects(cliCredentialProvider({ cliPath: join(tmpdir(), "no-such-ss-binary") })(), /not found/);
assert.throws(() => cliCredentialProvider({ timeoutMs: 0 }), /timeoutMs/);

// Client integration: bearer token per request, api_url from the CLI, AuthError surfaces unchanged.
{
  const ss = fakeSS(tokenJSON(3600_000, "https://cli.example.test/api/v1"));
  const seen = [];
  const client = new SecretServerClient({
    credentialProvider: cliCredentialProvider({ cliPath: ss.path }),
    fetchFn: async (url, init) => { seen.push([url, init.headers.Authorization]); return new Response('{"secrets":[],"total":0}'); },
  });
  await client.listSecrets(); await client.listSecrets();
  assert.deepEqual(seen, [["https://cli.example.test/api/v1/secrets", `Bearer ${TOKEN}`], ["https://cli.example.test/api/v1/secrets", `Bearer ${TOKEN}`]]);
  assert.equal(ss.runs(), 1);

  const explicit = [];
  const pinned = new SecretServerClient({
    apiUrl: "https://pinned.example.test",
    credentialProvider: cliCredentialProvider({ cliPath: fakeSS(tokenJSON(3600_000, "https://cli.example.test")).path }),
    fetchFn: async (url) => { explicit.push(url); return new Response("{}"); },
  });
  await pinned.request("GET", "/health");
  assert.deepEqual(explicit, ["https://pinned.example.test/api/v1/health"], "caller's apiUrl wins");

  const loggedOut = new SecretServerClient({
    credentialProvider: cliCredentialProvider({ cliPath: fakeSS("exit 2").path }),
    fetchFn: async () => assert.fail("request sent without a token"),
  });
  await assert.rejects(loggedOut.listSecrets(), (e) => e instanceof AuthError && e.message.includes("ss login"));

  const badUrl = new SecretServerClient({
    credentialProvider: cliCredentialProvider({ cliPath: fakeSS(tokenJSON(3600_000, "http://evil.example.test")).path }),
    fetchFn: async () => assert.fail("token sent to a non-https URL"),
  });
  await assert.rejects(badUrl.listSecrets(), SecretServerError);
}

console.log("PASS: cliCredentialProvider (fake ss: cache, refresh, exit codes, limits, timeout, redaction)");
