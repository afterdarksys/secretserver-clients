package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	ss "github.com/afterdarksys/secretserver-go/secretserver"
)

func main() {
	key := os.Getenv("SS_LIVE_KEY")
	c, e := ss.NewClient(&ss.Config{APIURL: os.Getenv("SS_LIVE_URL"), APIKey: key})
	must(e)
	ctx := context.Background()
	name := "go-live"
	container := os.Getenv("SS_LIVE_CONTAINER")

	// Wrong key -> 401 without key material in the error.
	wrongKey := "sk_wrong_" + strings.Repeat("0", 40)
	bad, e := ss.NewClient(&ss.Config{APIURL: os.Getenv("SS_LIVE_URL"), APIKey: wrongKey})
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

	// Update without ContainerID: read-merge-write must keep the container,
	// description and tags so the /s/prod path still resolves.
	_, e = c.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Data: map[string]string{"value": "second"}})
	must(e)
	v, e = c.Secrets.Get(ctx, name, nil)
	must(e)
	check(v.Data["value"] == "second", "update mismatch")
	check(v.ContainerID != nil && *v.ContainerID == container, "update dropped container")
	check(v.Description == "go live" && len(v.Tags) == 2, "update dropped description/tags")
	check(readPath(ctx, c, name) == "second", "path read after update mismatch")
	_, e = c.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Data: map[string]string{}})
	check(e != nil, "empty update data accepted")

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
	fmt.Println("SKIP certificate enroll/download/GetWithPEM: server enroll returns 500 (dns_names NOT NULL / JSON column mismatch); covered by unit tests")
	fmt.Println("SKIP JKS create/entry: server writes keystores outside the Vault KV mount (500 failed to store keystore); covered by unit tests")
	fmt.Println("SKIP LDAP search: needs a reachable LDAP server behind a stored bind credential")
	fmt.Println("SKIP crypto signing keys: needs an HSM/crypto backend")

	fmt.Println("Go live contract PASS")
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
