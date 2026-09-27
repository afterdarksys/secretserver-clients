package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	ss "github.com/afterdarksys/secretserver-go/secretserver"
)

// liveEnv returns SS_LIVE_URL, SS_LIVE_KEY and SS_LIVE_WRITE_KEY, exiting
// non-zero before any client exists unless all are set and the URL's host is
// loopback. It never falls back to SS_API_URL, SS_API_KEY or the default
// production URL.
func liveEnv() (liveURL, key, writeKey string) {
	liveURL, key, writeKey = os.Getenv("SS_LIVE_URL"), os.Getenv("SS_LIVE_KEY"), os.Getenv("SS_LIVE_WRITE_KEY")
	fail := func(msg string) {
		fmt.Fprintln(os.Stderr, "platform-smoke: "+msg)
		os.Exit(2)
	}
	if liveURL == "" {
		fail("SS_LIVE_URL must be set to a loopback test server (localhost, 127.0.0.1 or ::1)")
	}
	u, err := url.Parse(liveURL)
	if err != nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
		fail("SS_LIVE_URL host must be loopback (localhost, 127.0.0.1 or ::1); refusing to run against another host")
	}
	if key == "" || writeKey == "" {
		fail("SS_LIVE_KEY and SS_LIVE_WRITE_KEY must be set")
	}
	return liveURL, key, writeKey
}

func main() {
	liveURL, key, writeKey := liveEnv()
	// The live server is 3075630 or newer, so the clients opt in to partial
	// updates; plain below proves the ETag path without the opt-in.
	c, e := ss.NewClient(&ss.Config{APIURL: liveURL, APIKey: key, PartialUpdates: true})
	must(e)
	ctx := context.Background()
	name := "go-live"
	container := os.Getenv("SS_LIVE_CONTAINER")

	// Wrong key -> 401 without key material in the error.
	wrongKey := "sk_wrong_" + strings.Repeat("0", 40)
	bad, e := ss.NewClient(&ss.Config{APIURL: liveURL, APIKey: wrongKey})
	must(e)
	_, e = bad.Secrets.List(ctx, nil)
	var apiErr *ss.ErrorResponse
	check(errors.As(e, &apiErr) && apiErr.Response.StatusCode == http.StatusUnauthorized, "wrong key did not return 401")
	check(!strings.Contains(e.Error(), wrongKey) && !strings.Contains(e.Error(), key), "auth error contains key")

	_, e = c.Secrets.Create(ctx, &ss.SecretCreateRequest{Name: name, Data: map[string]string{"value": "first"}, ContainerID: &container, Description: "go live", Tags: []string{"go-live", "smoke"}})
	must(e)
	v, e := c.Secrets.Get(ctx, name, nil)
	must(e)
	check(v.Data["value"] == "first", "read mismatch")
	check(readPath(ctx, c, name) == "first", "path mismatch")

	// List, with client-side tag filtering and a bounded limit.
	all, e := c.Secrets.List(ctx, &ss.SecretListOptions{Limit: 1000})
	must(e)
	check(containsSecret(all, name), "list missing secret")
	tagged, e := c.Secrets.List(ctx, &ss.SecretListOptions{Tags: []string{"go-live", "smoke"}})
	must(e)
	check(len(tagged) == 1 && tagged[0].Name == name, "tag filter mismatch")
	_, e = c.Secrets.Get(ctx, name, &ss.SecretGetOptions{Version: "1"})
	check(e != nil, "Get with version accepted")

	// Partial update with a secrets:write-only key: no 403, value replaced,
	// container/description/tags kept, and no secret.read audit entry.
	writer, e := ss.NewClient(&ss.Config{APIURL: liveURL, APIKey: writeKey, PartialUpdates: true})
	must(e)
	readsBefore := auditCount(ctx, c, "secret.read", name)
	_, e = writer.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Data: map[string]string{"value": "second"}})
	must(e)
	check(auditCount(ctx, c, "secret.read", name) == readsBefore, "write-only update produced a secret.read audit entry")
	v, e = c.Secrets.Get(ctx, name, nil)
	must(e)
	check(v.Data["value"] == "second", "update mismatch")
	check(v.ContainerID != nil && *v.ContainerID == container, "update dropped container")
	check(v.Description == "go live" && len(v.Tags) == 2, "update dropped description/tags")
	check(readPath(ctx, c, name) == "second", "path read after update mismatch")
	_, e = c.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Data: map[string]string{}})
	check(e != nil, "empty update data accepted")

	// Explicit clear: description sent as null is cleared; omitted data,
	// container and tags are kept.
	_, e = c.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Clear: []string{"description"}})
	must(e)
	v, e = c.Secrets.Get(ctx, name, nil)
	must(e)
	check(v.Description == "" && v.Data["value"] == "second" && len(v.Tags) == 2, "clear description changed other fields")
	check(v.ContainerID != nil && *v.ContainerID == container, "clear description dropped container")

	// ETag: Get's ETag succeeds, then the now-stale ETag conflicts.
	check(v.ETag != "", "Get returned no ETag")
	desc := "etag"
	updated, e := c.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Description: &desc, IfMatch: v.ETag})
	must(e)
	check(updated.ETag != "" && updated.ETag != v.ETag, "update returned no new ETag")
	_, e = c.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Description: &desc, IfMatch: v.ETag})
	var conflict *ss.ConflictError
	check(errors.As(e, &conflict), "stale ETag did not return ConflictError")
	check(conflict.ETag == updated.ETag, "conflict did not carry the current ETag")
	check(!strings.Contains(e.Error(), key), "conflict error contains key")

	// Without the opt-in an update is refused unless it carries an ETag from
	// Get; with that ETag it succeeds.
	plain, e := ss.NewClient(&ss.Config{APIURL: liveURL, APIKey: key})
	must(e)
	_, e = plain.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Description: &desc, IfMatch: "3"})
	check(errors.Is(e, ss.ErrPartialUpdatesUnconfirmed), "update without opt-in or ETag was not refused")
	cur, e := plain.Secrets.Get(ctx, name, nil)
	must(e)
	plainDesc := "etag without opt-in"
	updated, e = plain.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Description: &plainDesc, IfMatch: cur.ETag})
	must(e)
	check(updated.ETag != "" && updated.ETag != cur.ETag, "ETag update without opt-in returned no new ETag")
	cur, e = plain.Secrets.Get(ctx, name, nil)
	must(e)
	check(cur.Description == plainDesc && cur.Data["value"] == "second" && len(cur.Tags) == 2, "ETag update without opt-in changed other fields")
	check(cur.ContainerID != nil && *cur.ContainerID == container, "ETag update without opt-in dropped container")
	fmt.Println("partial update without opt-in: refused without ETag, applied with ETag from Get")
	expected := updated.Version
	_, e = c.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Description: &desc, ExpectedVersion: &expected})
	must(e)
	stale := expected + 1
	_, e = c.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Description: &desc, ExpectedVersion: &stale})
	check(errors.As(e, &conflict), "wrong expected_version did not return ConflictError")

	// /export/json carries secret contents.
	var export struct {
		Items []struct {
			Type  string `json:"type"`
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"items"`
	}
	_, e = c.Call(ctx, "POST", "/export/json", map[string]interface{}{"include_secrets": true}, &export)
	must(e)
	secretExported := false
	for _, item := range export.Items {
		if item.Type == "secret" && item.Name == name {
			secretExported = strings.Contains(item.Value, "second")
		}
	}
	check(secretExported, "export/json missing secret contents")

	// History is a bare array.
	var history []map[string]interface{}
	_, e = c.Call(ctx, "GET", "/secret/"+v.ID+"/history", nil, &history)
	must(e)
	fmt.Printf("history entries: %d\n", len(history))

	_, e = c.AssignVariable(ctx, "GO_LIVE", ss.VariableAssignment{SecretType: "secret", SecretID: v.ID, Field: "value"})
	must(e)
	rendered, e := c.Render(ctx, "x=%%GO_LIVE%%")
	must(e)
	check(rendered == "x=second", "render mismatch")
	document, e := c.ResolveDocument(ctx, json.RawMessage(`{"password":"%%GO_LIVE%%","count":2}`))
	must(e)
	var doc map[string]interface{}
	must(json.Unmarshal(document, &doc))
	check(doc["password"] == "second" && doc["count"] == float64(2), "document mismatch")
	_, e = c.GetVariable(ctx, "GO_LIVE")
	must(e)
	_, e = c.ListVariables(ctx)
	must(e)
	must(c.DeleteVariable(ctx, "GO_LIVE"))
	must(c.Secrets.Delete(ctx, name))

	// SSH: generate with default key type, export decodes bits + private key.
	sshKey, e := c.SSHKeys.Generate(ctx, &ss.GenerateSSHKeyRequest{Name: "go-live-ssh"})
	must(e)
	check(sshKey.KeyType == "ed25519", "ssh default key type")
	exported, e := c.SSHKeys.Export(ctx, sshKey.ID)
	must(e)
	check(strings.Contains(exported.PrivateKey, "PRIVATE KEY") && exported.PublicKey != "", "ssh export missing key material")
	rsaKey, e := c.SSHKeys.Generate(ctx, &ss.GenerateSSHKeyRequest{Name: "go-live-ssh-rsa", KeyType: "rsa", Bits: 2048})
	must(e)
	rsaExport, e := c.SSHKeys.Export(ctx, rsaKey.ID)
	must(e)
	check(rsaExport.Bits == 2048, "ssh export bits")
	imported, e := c.SSHKeys.Import(ctx, &ss.ImportSSHKeyRequest{Name: "go-live-ssh-import", PrivateKey: exported.PrivateKey})
	must(e)
	check(imported.Fingerprint == sshKey.Fingerprint, "ssh import fingerprint mismatch")
	for _, id := range []string{sshKey.ID, rsaKey.ID, imported.ID} {
		must(c.SSHKeys.Delete(ctx, id))
	}

	// Extraction and LDAP import use multipart uploads.
	scan, e := c.Extraction.ExtractFromDB(ctx, "go-live.env", strings.NewReader("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), true)
	must(e)
	check(scan.Status == "completed" && scan.ImportStatus == "ready", "extraction result")
	ldif := "dn: cn=go-live,dc=example,dc=test\nobjectClass: person\ncn: go-live\nsn: live\n\n"
	imp, e := c.LDAP.Import(ctx, "go-live.ldif", strings.NewReader(ldif), &ss.LDAPImportOptions{DryRun: true})
	must(e)
	check(imp.DryRun && imp.TotalEntries == 1, "ldap import result")
	var ldifOut bytes.Buffer
	must(c.LDAP.Export(ctx, &ss.LDAPExportOptions{BaseDN: "dc=example,dc=test"}, &ldifOut))
	fmt.Printf("ldap export bytes: %d\n", ldifOut.Len())
	certPEM := liveCertificates(ctx, c)
	liveJKS(ctx, c, container, certPEM)
	liveGPG(ctx, c)
	liveTOTP(ctx, c)
	liveYubiKey(ctx, c)
	fmt.Println("SKIP LDAP search: needs a reachable LDAP server behind a stored bind credential")
	fmt.Println("SKIP crypto signing keys: needs an operator-provisioned crypto backend and signing key binding")
	fmt.Println("SKIP YubiKey OTP validation: needs the external Yubico validation service")

	fmt.Println("verified: loopback-only live env, partial-update opt-in and ETag-without-opt-in, write-only partial update without secret.read audit, null clear, If-Match/expected_version 409, export/json, certificates, JKS, GPG, TOTP, YubiKey")
	fmt.Println("Go live contract PASS")
}

// liveCertificates returns the enrolled certificate PEM.
func liveCertificates(ctx context.Context, c *ss.Client) string {
	cert, e := c.Certificates.Enroll(ctx, &ss.CertificateEnrollRequest{Name: "go-live-cert", CommonName: "go-live.example.test", DNSNames: []string{"go-live.example.test"}, KeyType: "rsa", KeySize: 2048, ValidityDays: 30})
	must(e)
	check(cert.ID != "" && cert.CommonName == "go-live.example.test", "certificate enroll result")
	list, e := c.Certificates.List(ctx)
	must(e)
	found := false
	for _, item := range list {
		found = found || item.ID == cert.ID
	}
	check(found, "certificate list missing enrolled certificate")
	got, e := c.Certificates.Get(ctx, cert.ID)
	must(e)
	check(got.Name == "go-live-cert", "certificate get mismatch")
	withPEM, e := c.Certificates.GetWithPEM(ctx, cert.ID)
	must(e)
	check(strings.Contains(withPEM.CertificatePEM, "BEGIN CERTIFICATE"), "GetWithPEM missing PEM")
	var pem, bundle, pfx bytes.Buffer
	must(c.Certificates.Download(ctx, cert.ID, nil, &pem))
	check(strings.Contains(pem.String(), "BEGIN CERTIFICATE") && !strings.Contains(pem.String(), "PRIVATE KEY"), "pem download")
	must(c.Certificates.Download(ctx, cert.ID, &ss.CertificateDownloadOptions{Format: "pem-bundle"}, &bundle))
	check(strings.Contains(bundle.String(), "PRIVATE KEY"), "pem-bundle download missing key")
	must(c.Certificates.Download(ctx, cert.ID, &ss.CertificateDownloadOptions{Format: "pfx", Password: "go-live-pfx"}, &pfx))
	check(pfx.Len() > 0, "pfx download empty")
	// The server must refuse a password in the URL; the SDK never sends one.
	_, e = c.Call(ctx, "GET", "/certificates/"+cert.ID+"/download?format=pfx&password=go-live-pfx", nil, io.Discard)
	var apiErr *ss.ErrorResponse
	check(errors.As(e, &apiErr) && apiErr.Response.StatusCode == 400, "GET pfx with password in URL was not rejected with 400")
	must(c.Certificates.Revoke(ctx, cert.ID))
	fmt.Println("certificates: enroll/list/get/pem/pem-bundle/pfx(POST)/GET-password-rejected/revoke ok")
	return withPEM.CertificatePEM
}

func liveJKS(ctx context.Context, c *ss.Client, container, certPEM string) {
	ks, e := c.JKS.Create(ctx, &ss.CreateJKSKeystoreRequest{Name: "go-live-jks", ContainerID: container, Password: "changeit-1", Notes: "go notes", Tags: []string{"go-live"}})
	must(e)
	check(ks.ID != "", "jks create returned no id")
	got, e := c.JKS.Get(ctx, ks.ID)
	must(e)
	check(got.Notes == "go notes" && got.ETag != "", "jks get mismatch")

	// Clear notes via null and rotate the password; name/tags/container kept.
	pw := "changeit-2"
	etag, e := c.JKS.Update(ctx, ks.ID, &ss.JKSKeystoreUpdate{Password: &pw, Clear: []string{"notes"}, IfMatch: got.ETag})
	must(e)
	check(etag != "" && etag != got.ETag, "jks update returned no new ETag")
	after, e := c.JKS.Get(ctx, ks.ID)
	must(e)
	check(after.Notes == "" && after.Name == "go-live-jks" && len(after.Tags) == 1, "jks partial update changed other fields")
	check(after.ContainerID != nil && *after.ContainerID == container, "jks update dropped container")
	check(after.ETag == etag, "jks update ETag differs from Get")

	renamed := "go-live-jks-2"
	_, e = c.JKS.Update(ctx, ks.ID, &ss.JKSKeystoreUpdate{Name: &renamed, IfMatch: got.ETag})
	var conflict *ss.ConflictError
	check(errors.As(e, &conflict) && conflict.ETag == etag, "stale jks ETag did not return ConflictError with current ETag")

	list, e := c.JKS.List(ctx)
	must(e)
	check(len(list) > 0, "jks list empty")
	export, e := c.JKS.Export(ctx, ks.ID)
	must(e)
	check(export.JKS != "", "jks export empty")
	entry, e := c.JKS.CreateEntry(ctx, ks.ID, &ss.CreateJKSEntryRequest{Alias: "go-live-ca", EntryType: "trusted_cert", Certificate: certPEM})
	must(e)
	check(entry.Alias == "go-live-ca", "jks entry create")
	entries, e := c.JKS.Entries(ctx, ks.ID)
	must(e)
	check(len(entries) == 1 && entries[0].Alias == "go-live-ca", "jks entries list")
	withEntry, e := c.JKS.Export(ctx, ks.ID)
	must(e)
	check(len(withEntry.JKS) > len(export.JKS), "jks export did not include the entry")
	must(c.JKS.DeleteEntry(ctx, ks.ID, "go-live-ca"))
	must(c.JKS.Delete(ctx, ks.ID))
	fmt.Println("jks: create/get/partial update/password rotation/etag conflict/entry/export/delete ok")
}

func liveGPG(ctx context.Context, c *ss.Client) {
	var key struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
		PublicKey   string `json:"public_key"`
	}
	_, e := c.Call(ctx, "POST", "/gpg-keys/generate", map[string]string{"name": "go-live-gpg", "email": "go-live@example.test", "algorithm": "ED25519"}, &key)
	must(e)
	check(key.ID != "" && strings.Contains(key.PublicKey, "PGP PUBLIC KEY"), "gpg generate result")
	var list interface{}
	_, e = c.Call(ctx, "GET", "/gpg-keys", nil, &list)
	must(e)
	for _, format := range []string{"public", "private"} {
		var export struct {
			Key         string `json:"key"`
			Format      string `json:"format"`
			Fingerprint string `json:"fingerprint"`
		}
		_, e = c.Call(ctx, "GET", "/gpg-keys/"+url.PathEscape(key.ID)+"/export?format="+format, nil, &export)
		must(e)
		check(export.Format == format && export.Fingerprint == key.Fingerprint && strings.Contains(export.Key, "PGP"), "gpg "+format+" export")
	}
	_, e = c.Call(ctx, "DELETE", "/gpg-keys/"+url.PathEscape(key.ID), nil, nil)
	must(e)
	fmt.Println("gpg: generate/list/export public+private/delete ok")
}

func liveTOTP(ctx context.Context, c *ss.Client) {
	var token struct {
		ID string `json:"id"`
	}
	_, e := c.Call(ctx, "POST", "/totp-tokens", map[string]string{"name": "go-live-totp", "issuer": "GoLive", "account_name": "go@example.test", "secret_key": "JBSWY3DPEHPK3PXP"}, &token)
	must(e)
	check(token.ID != "", "totp create returned no id")
	var list struct {
		Tokens []struct {
			ID string `json:"id"`
		} `json:"tokens"`
		Total int `json:"total"`
	}
	_, e = c.Call(ctx, "GET", "/totp-tokens", nil, &list)
	must(e)
	found := false
	for _, t := range list.Tokens {
		found = found || t.ID == token.ID
	}
	check(found && list.Total == len(list.Tokens), "totp list envelope")
	id := url.PathEscape(token.ID)
	var export struct {
		URI string `json:"uri"`
	}
	_, e = c.Call(ctx, "GET", "/totp-tokens/"+id+"/export", nil, &export)
	must(e)
	check(strings.HasPrefix(export.URI, "otpauth://totp/"), "totp export uri")
	var code map[string]interface{}
	_, e = c.Call(ctx, "POST", "/totp-tokens/"+id+"/generate", nil, &code)
	must(e)
	check(code["code"] != nil, "totp generate code")
	_, e = c.Call(ctx, "DELETE", "/totp-tokens/"+id, nil, nil)
	must(e)
	fmt.Println("totp: create/list/export/generate/delete ok")
}

// liveYubiKey uses Call: the Go SDK has no typed YubiKey service.
func liveYubiKey(ctx context.Context, c *ss.Client) {
	var created struct {
		ID string `json:"id"`
	}
	_, e := c.Call(ctx, "POST", "/yubikeys", map[string]string{"name": "go-live-yubikey", "serial_number": "12345678", "public_id": "cccccccccccb", "client_id": "1", "api_key": "c2VjcmV0", "notes": "go notes"}, &created)
	must(e)
	check(created.ID != "", "yubikey create returned no id")
	id := url.PathEscape(created.ID)
	_, e = c.Call(ctx, "PUT", "/yubikeys/"+id, map[string]interface{}{"serial_number": nil}, nil)
	must(e)
	var got struct {
		Name         string `json:"name"`
		SerialNumber string `json:"serial_number"`
		PublicID     string `json:"public_id"`
		Notes        string `json:"notes"`
	}
	_, e = c.Call(ctx, "GET", "/yubikeys/"+id, nil, &got)
	must(e)
	check(got.SerialNumber == "" && got.Name == "go-live-yubikey" && got.PublicID == "cccccccccccb" && got.Notes == "go notes", "yubikey partial update")
	_, e = c.Call(ctx, "DELETE", "/yubikeys/"+id, nil, nil)
	must(e)
	fmt.Println("yubikey: create/partial update (serial_number cleared)/get/delete ok")
}

// auditCount returns how many audit entries match action and resource.
func auditCount(ctx context.Context, c *ss.Client, action, resource string) int {
	var out struct {
		Logs []json.RawMessage `json:"logs"`
	}
	q := url.Values{"action": {action}, "resource": {resource}, "limit": {"1000"}}
	_, e := c.Call(ctx, "GET", "/audit/logs?"+q.Encode(), nil, &out)
	must(e)
	return len(out.Logs)
}

func readPath(ctx context.Context, c *ss.Client, name string) string {
	var envelope struct {
		Data map[string]string `json:"data"`
	}
	_, e := c.Call(ctx, "GET", "/s/prod/"+name, nil, &envelope)
	must(e)
	return envelope.Data["value"]
}

func containsSecret(list []*ss.Secret, name string) bool {
	for _, s := range list {
		if s.Name == name {
			return true
		}
	}
	return false
}

func check(ok bool, msg string) {
	if !ok {
		panic(msg)
	}
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
