import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {SecretServerClient, AuthError, PermissionError, ConflictError, NotFoundError, SecretServerError} from '../dist/index.js';
// Only ever run against the disposable loopback stack: SS_LIVE_URL and SS_LIVE_KEY are
// required and never fall back to SS_API_URL/SS_API_KEY or the production default.
function refuse(msg){ console.error(`live test refused: ${msg}`); process.exit(2); }
if (!process.env.SS_LIVE_URL) refuse('SS_LIVE_URL is not set');
let liveHost;
try { liveHost=new URL(process.env.SS_LIVE_URL).hostname; } catch { refuse('SS_LIVE_URL is not a valid URL'); }
if (!['localhost','127.0.0.1','[::1]'].includes(liveHost)) refuse('SS_LIVE_URL host must be loopback (localhost, 127.0.0.1, ::1)');
if (!process.env.SS_LIVE_KEY) refuse('SS_LIVE_KEY is not set');
if (!process.env.SS_LIVE_WRITE_KEY) refuse('SS_LIVE_WRITE_KEY is not set');
// This stack runs a partial-update server (3075630+), so both clients opt in.
const c=new SecretServerClient({apiKey:process.env.SS_LIVE_KEY,apiUrl:process.env.SS_LIVE_URL,partialUpdates:true});
// Key holding ONLY secrets:write.
const writer=new SecretServerClient({apiKey:process.env.SS_LIVE_WRITE_KEY,apiUrl:process.env.SS_LIVE_URL,partialUpdates:true});
const container=process.env.SS_LIVE_CONTAINER;
const cleanup=[];
// Register an undo step; call the returned function after an explicit delete to drop it.
function onCleanup(fn){ const entry={fn,active:true}; cleanup.push(entry); return ()=>{entry.active=false;}; }
async function conflictEtag(fn){
  let etag;
  await assert.rejects(fn(),e=>{ etag=e.etag; return e instanceof ConflictError&&e.statusCode===409&&typeof e.etag==='string'&&e.etag.length>2; });
  return etag;
}
const secretReads=async name=>(await c.getAuditLogs({action:'secret.read',resource:name,limit:1000})).logs.length;
// JKS integrity digest: SHA-1(password as UTF-16BE || "Mighty Aphrodite" || body) == trailing 20 bytes.
function jksPasswordMatches(b64,password){
  const raw=Buffer.from(b64,'base64');
  const pw=Buffer.alloc(password.length*2);
  for (let i=0;i<password.length;i++) pw.writeUInt16BE(password.charCodeAt(i),i*2);
  const digest=createHash('sha1').update(pw).update('Mighty Aphrodite','utf8').update(raw.subarray(0,raw.length-20)).digest();
  return digest.equals(raw.subarray(raw.length-20));
}
try {
  // Secrets: create in the prod container, then prove path access and metadata survive partial updates.
  await c.createSecret('node-live','first',{containerID:container,description:'node live desc'});
  onCleanup(()=>c.deleteSecret('node-live'));
  assert.equal(await c.secret('prod/node-live'),'first');
  assert.ok((await c.listSecrets()).some(s=>s.name==='node-live'));
  const record=await c.getSecret('node-live');
  await c.updateHistorySettings('secret',record.id,true,5);
  await c.updateSecret('node-live',undefined,{tags:['node','live']});

  // Write-only key: updates the value without a pre-read (no 403) and cannot read.
  await assert.rejects(writer.secret('node-live'),e=>e instanceof PermissionError);
  const readsBefore=await secretReads('node-live');
  assert.ok(readsBefore>=1,'audit filter must see the earlier admin reads');
  const written=await writer.updateSecret('node-live','second');
  assert.equal(typeof written.etag,'string');
  assert.equal(await secretReads('node-live'),readsBefore,'update must not emit a secret.read audit event');
  assert.equal(await c.secret('node-live'),'second');
  assert.equal(await c.secret('prod/node-live'),'second');
  const byPath=await c.getSecret('prod/node-live');
  assert.equal(byPath.meta.secret_id,record.id);
  assert.equal(byPath.data.value,'second');
  const after=await c.getSecret('node-live');
  assert.equal(after.container_id,container);
  assert.equal(after.description,'node live desc');
  assert.deepEqual(after.tags,['node','live']);

  // Explicit null clears description; omitted value, tags and container are kept.
  await c.updateSecret('node-live',undefined,{description:null});
  const cleared=await c.getSecret('node-live');
  assert.ok(!cleared.description);
  assert.deepEqual(cleared.tags,['node','live']);
  assert.equal(cleared.container_id,container);
  assert.equal(cleared.data.value,'second');

  // ETag: a fresh ETag succeeds; the same, now stale, ETag -> ConflictError with the current one.
  const fresh=await c.getSecret('node-live');
  assert.match(fresh.etag,/^"[^"]+"$/);
  const third=await c.updateSecret('node-live','third',{ifMatch:fresh.etag});
  assert.notEqual(third.etag,fresh.etag);
  const current=await conflictEtag(()=>c.updateSecret('node-live','stale-write',{ifMatch:fresh.etag}));
  assert.equal(current,third.etag);
  assert.equal(await c.secret('node-live'),'third');
  await conflictEtag(()=>c.updateSecret('node-live','stale-write',{expectedVersion:third.version+100}));
  await c.updateSecret('node-live','fourth',{ifMatch:third.etag});
  assert.equal(await c.secret('prod/node-live'),'fourth');

  // Without the opt-in, a partial update is refused client-side unless ifMatch is an ETag from get().
  const plain=new SecretServerClient({apiKey:process.env.SS_LIVE_KEY,apiUrl:process.env.SS_LIVE_URL,partialUpdates:false});
  await assert.rejects(plain.updateSecret('node-live','refused'),/require secretserver\.io 3075630/);
  await assert.rejects(plain.updateSecret('node-live','refused',{ifMatch:third.version+1}),/require secretserver\.io 3075630/);
  const beforePlain=await plain.getSecret('node-live');
  assert.equal(beforePlain.data.value,'fourth');
  await plain.updateSecret('node-live','fifth',{ifMatch:beforePlain.etag});
  const afterPlain=await c.getSecret('node-live');
  assert.equal(afterPlain.data.value,'fifth');
  assert.equal(afterPlain.container_id,container);
  assert.deepEqual(afterPlain.tags,['node','live']);
  assert.equal(await c.secret('prod/node-live'),'fifth');
  const history=await c.getHistory('secret',record.id);
  assert.ok(Array.isArray(history)&&history.length>=1);

  // Wrong key -> AuthError whose message carries neither key.
  const badKey='sk_wrong_'+'x'.repeat(24);
  const bad=new SecretServerClient({apiKey:badKey,apiUrl:process.env.SS_LIVE_URL});
  await assert.rejects(bad.listSecrets(),e=>e instanceof AuthError&&!e.message.includes(badKey)&&!e.message.includes(process.env.SS_LIVE_KEY));

  // Variables (admin:all).
  await c.assignVariable('NODE_LIVE',{secret_type:'secret',secret_id:record.id,field:'value'});
  onCleanup(()=>c.deleteVariable('NODE_LIVE'));
  assert.equal(await c.render('x=%%NODE_LIVE%%'),'x=fifth');
  assert.deepEqual(await c.resolveDocument({password:'%%NODE_LIVE%%',count:2}),{password:'fifth',count:2});
  assert.equal((await c.getVariable('NODE_LIVE')).secret_id,record.id);
  assert.ok((await c.listVariables()).some(v=>v.name==='NODE_LIVE'));

  // Passwords: create sends value; generate persists a record and returns the value.
  const pw=await c.createPassword('node-live-pw','svc','Correct-Horse-9-Battery');
  onCleanup(()=>c.request('DELETE',`/passwords/${pw.id}`));
  const gen=await c.generatePassword('node-live-gen',{length:24,useSymbols:false});
  onCleanup(()=>c.request('DELETE',`/passwords/${gen.id}`));
  assert.equal(gen.value.length,24);
  assert.match(gen.value,/^[A-Za-z0-9]+$/);
  assert.ok((await c.listPasswords()).some(p=>p.id===gen.id));

  // API tokens: create with value + environment, rotate with a new value.
  const tok=await c.createAPIToken('node-live-token','node-live','tok_first_value_123','development');
  onCleanup(()=>c.request('DELETE',`/api-tokens/${tok.id}`));
  assert.equal(tok.environment,'development');
  const rotated=await c.rotateAPIToken(tok.id,'tok_second_value_456');
  assert.equal(rotated.value,'tok_second_value_456');
  assert.ok((await c.listAPITokens()).some(t=>t.id===tok.id));

  // GPG: generate, list, export public and private armor, delete.
  const gpg=await c.generateGPGKey('Node Live','node-live@example.test',{algorithm:'ED25519'});
  const gpgUndo=onCleanup(()=>c.request('DELETE',`/gpg-keys/${encodeURIComponent(gpg.id)}?hard_delete=true`));
  assert.match(gpg.fingerprint,/^[0-9A-Fa-f]{40}$/);
  assert.ok((await c.listGPGKeys()).some(k=>k.id===gpg.id));
  const gpgPub=await c.exportGPGKey(gpg.id,'public');
  assert.equal(gpgPub.format,'public');
  assert.equal(gpgPub.fingerprint,gpg.fingerprint);
  assert.match(gpgPub.key,/BEGIN PGP PUBLIC KEY BLOCK/);
  const gpgPriv=await c.exportGPGKey(gpg.id,'private');
  assert.equal(gpgPriv.format,'private');
  assert.match(gpgPriv.key,/BEGIN PGP PRIVATE KEY BLOCK/);
  // Default delete is a soft revoke; hard_delete=true removes the record.
  await c.deleteGPGKey(gpg.id);
  assert.equal((await c.listGPGKeys()).find(k=>k.id===gpg.id)?.revoked,true);
  await c.request('DELETE',`/gpg-keys/${encodeURIComponent(gpg.id)}?hard_delete=true`); gpgUndo();
  assert.ok(!(await c.listGPGKeys()).some(k=>k.id===gpg.id));

  // OpenSSL: generate ECDSA with curve.
  const ossl=await c.generateOpenSSLKey('node-live-ossl','ecdsa',{curve:'P-256'});
  onCleanup(()=>c.deleteOpenSSLKey(ossl.id));
  assert.equal(ossl.algorithm,'ecdsa');
  assert.match(ossl.public_key,/BEGIN PUBLIC KEY/);

  // TOTP: create, list (envelope), get, code, export uri, delete.
  const totp=await c.createTOTPToken('node-live-totp','Example','live@example.test','JBSWY3DPEHPK3PXP');
  const totpUndo=onCleanup(()=>c.deleteTOTPToken(totp.id));
  assert.ok((await c.listTOTPTokens()).some(t=>t.id===totp.id));
  assert.equal((await c.getTOTPToken(totp.id)).name,'node-live-totp');
  const code=await c.generateTOTPCode(totp.id);
  assert.match(code.code,/^\d{6}$/);
  assert.equal(code.period,30);
  assert.match((await c.exportTOTPToURI(totp.id)).uri,/^otpauth:\/\/totp\/.*secret=JBSWY3DPEHPK3PXP/);
  await c.deleteTOTPToken(totp.id); totpUndo();
  await assert.rejects(c.getTOTPToken(totp.id),e=>e instanceof NotFoundError);

  // Export JSON with include flags: only secrets, and the secret's current value is included.
  const all=await c.exportToJSON({includeSecrets:true});
  const items=all.items??[];
  assert.equal(all.format,'json');
  assert.equal(all.count,items.length);
  assert.ok(items.every(i=>i.type==='secret'));
  const exported=items.find(i=>i.name==='node-live');
  assert.ok(exported,'export json must include node-live');
  assert.equal(JSON.parse(exported.value).value,'fifth');

  // Certificates: self-signed enroll works locally; download PEM as raw text and PKCS#12 as bytes.
  const cert=await c.enrollCertificate('node-live-cert','node-live.example.test',['www.node-live.example.test'],false);
  onCleanup(()=>c.revokeCertificate(cert.id));
  assert.equal(cert.issuer_type,'self-signed');
  assert.equal((await c.getCertificate(cert.id)).common_name,'node-live.example.test');
  assert.ok((await c.listCertificates()).some(x=>x.id===cert.id));
  const pem=await c.downloadCertificate(cert.id);
  assert.match(pem,/^-----BEGIN CERTIFICATE-----/);
  const p12=await c.downloadCertificate(cert.id,{format:'p12',password:'Node-Live-Export-1'});
  assert.ok(p12 instanceof Uint8Array&&p12.byteLength>100&&p12[0]===0x30);
  // pfx/p12 travel by POST; the server refuses a password in the URL.
  await assert.rejects(c.request('GET',`/certificates/${cert.id}/download?format=pfx&password=Node-Live-Export-1`),e=>e instanceof SecretServerError&&e.statusCode===400);

  // JKS: create managed keystore, partial update (notes clear via null + password rotation), ETag conflict, delete.
  const jks=await c.createJKSKeystore({name:'node-live-jks',store_type:'managed',password:'Jks-First-1',container_id:container,notes:'jks notes',tags:['jks']});
  const jksUndo=onCleanup(()=>c.deleteJKSKeystore(jks.id));
  const jks1=await c.getJKSKeystore(jks.id);
  assert.equal(jks1.notes,'jks notes');
  assert.match(jks1.etag,/^"[^"]+"$/);
  assert.ok(jksPasswordMatches((await c.exportJKSKeystore(jks.id)).jks,'Jks-First-1'));
  const jksUpdated=await c.updateJKSKeystore(jks.id,{notes:null,password:'Jks-Rotated-2'},{ifMatch:jks1.etag});
  assert.notEqual(jksUpdated.etag,jks1.etag);
  const jks2=await c.getJKSKeystore(jks.id);
  assert.ok(!jks2.notes);
  assert.equal(jks2.name,'node-live-jks');
  assert.deepEqual(jks2.tags,['jks']);
  assert.equal(jks2.container_id,container);
  const jksExport=(await c.exportJKSKeystore(jks.id)).jks;
  assert.ok(jksPasswordMatches(jksExport,'Jks-Rotated-2'));
  assert.ok(!jksPasswordMatches(jksExport,'Jks-First-1'));
  assert.equal(await conflictEtag(()=>c.updateJKSKeystore(jks.id,{notes:'stale'},{ifMatch:jks1.etag})),jks2.etag);
  assert.ok(!(await c.getJKSKeystore(jks.id)).notes);
  await c.deleteJKSKeystore(jks.id); jksUndo();
  await assert.rejects(c.getJKSKeystore(jks.id),e=>e instanceof NotFoundError);

  // YubiKey: create, partial update (serial_number clear via null), ETag conflict, delete.
  const yk=await c.createYubikey('node-live-yk','cccccccccccb','12345',Buffer.from('node-live-yubico-key').toString('base64'),{serialNumber:'7654321',notes:'yk notes'});
  const ykUndo=onCleanup(()=>c.deleteYubikey(yk.id));
  const yk1=await c.getYubikey(yk.id);
  assert.equal(yk1.serial_number,'7654321');
  const ykUpdated=await c.updateYubikey(yk.id,{serial_number:null,notes:'yk notes 2'},{ifMatch:yk1.etag});
  assert.notEqual(ykUpdated.etag,yk1.etag);
  const yk2=await c.getYubikey(yk.id);
  assert.ok(!yk2.serial_number);
  assert.equal(yk2.notes,'yk notes 2');
  assert.equal(yk2.name,'node-live-yk');
  assert.equal(yk2.public_id,'cccccccccccb');
  assert.equal(yk2.client_id,'12345');
  assert.equal(await conflictEtag(()=>c.updateYubikey(yk.id,{notes:'stale'},{ifMatch:yk1.etag})),yk2.etag);
  assert.ok((await c.listYubikeys()).some(y=>y.id===yk.id));
  await c.deleteYubikey(yk.id); ykUndo();
  await assert.rejects(c.getYubikey(yk.id),e=>e instanceof NotFoundError);

  // Audit: filtered query and JSON export.
  const logs=await c.getAuditLogs({limit:5,action:'secret.update'});
  assert.ok(logs.logs.length>=1);
  assert.ok(Array.isArray((await c.exportAuditLogs()).logs));
} finally {
  for (const {fn,active} of cleanup.reverse()) {
    if (!active) continue;
    try { await fn(); } catch (e) { console.error(`cleanup failed: ${e.message}`); process.exitCode=1; }
  }
}
// Checks that need something outside this disposable stack.
for (const reason of [
  'yubikey OTP validation (needs the Yubico validation service and a real device OTP)',
  'crypto sign (needs a configured PKCS#11/HSM signing backend)',
  'share (needs a second active user or a group in the tenant)',
  'webhook create/test (SSRF guard refuses loopback receivers; a public receiver is external)',
]) console.log(`SKIP (external): ${reason}`);
console.log('TypeScript live contract PASS');
