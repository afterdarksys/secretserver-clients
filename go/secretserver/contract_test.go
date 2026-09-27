package secretserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// capturedRequest is one request seen by updateServer.
type capturedRequest struct {
	method, ifMatch string
	body            map[string]json.RawMessage
}

// updateServer records each request's method, raw body and If-Match header
// and answers with the given status and ETag. The client opts in to partial
// updates.
func updateServer(t *testing.T, status int, etag string, got *[]capturedRequest) *Client {
	t.Helper()
	return newTestClientConfig(t, func(w http.ResponseWriter, r *http.Request) {
		req := capturedRequest{method: r.Method, ifMatch: r.Header.Get("If-Match")}
		if r.Method == http.MethodPut {
			if err := json.NewDecoder(r.Body).Decode(&req.body); err != nil {
				t.Error(err)
			}
		}
		*got = append(*got, req)
		w.Header().Set("ETag", etag)
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"id":"1","name":"db","version":4}`))
		} else {
			_, _ = w.Write([]byte(`{"error":"conflict body sk_test_do_not_leak"}`))
		}
	}, Config{PartialUpdates: true})
}

func rawBody(t *testing.T, body map[string]json.RawMessage) map[string]string {
	t.Helper()
	out := make(map[string]string, len(body))
	for k, v := range body {
		out[k] = string(v)
	}
	return out
}

func TestSecretUpdateSendsOnlyProvidedFields(t *testing.T) {
	var got []capturedRequest
	c := updateServer(t, http.StatusOK, `"2026-09-27T10:00:00.123456789Z"`, &got)
	ctx := context.Background()

	sec, err := c.Secrets.Update(ctx, "db", &SecretUpdateRequest{Data: map[string]string{"v": "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if sec.ETag != `"2026-09-27T10:00:00.123456789Z"` || sec.Version != 4 {
		t.Fatalf("update result = %#v", sec)
	}
	if len(got) != 1 || got[0].method != http.MethodPut {
		t.Fatalf("expected a single PUT with no pre-read GET, got %#v", got)
	}
	if b := rawBody(t, got[0].body); !reflect.DeepEqual(b, map[string]string{"data": `{"v":"new"}`}) {
		t.Fatalf("body = %v", b)
	}
	if got[0].ifMatch != "" {
		t.Fatalf("If-Match sent without being requested: %q", got[0].ifMatch)
	}

	got = nil
	empty, other, tags := "", "c-2", []string{}
	if _, err := c.Secrets.Update(ctx, "db", &SecretUpdateRequest{Description: &empty, ContainerID: &other, Tags: &tags}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"description": `""`, "container_id": `"c-2"`, "tags": `[]`}
	if b := rawBody(t, got[0].body); !reflect.DeepEqual(b, want) {
		t.Fatalf("body = %v, want %v", b, want)
	}
}

func TestSecretUpdateClearSendsNull(t *testing.T) {
	var got []capturedRequest
	c := updateServer(t, http.StatusOK, `"e"`, &got)
	if _, err := c.Secrets.Update(context.Background(), "db", &SecretUpdateRequest{Clear: []string{"description", "tags", "container_id"}}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"description": "null", "tags": "null", "container_id": "null"}
	if b := rawBody(t, got[0].body); !reflect.DeepEqual(b, want) {
		t.Fatalf("body = %v, want %v", b, want)
	}
}

func TestSecretUpdateSendsIfMatchAndExpectedVersion(t *testing.T) {
	var got []capturedRequest
	c := updateServer(t, http.StatusOK, `"e"`, &got)
	v := 3
	if _, err := c.Secrets.Update(context.Background(), "db", &SecretUpdateRequest{IfMatch: `"etag-1"`, ExpectedVersion: &v, Data: map[string]string{"v": "x"}}); err != nil {
		t.Fatal(err)
	}
	if got[0].ifMatch != `"etag-1"` {
		t.Fatalf("If-Match = %q", got[0].ifMatch)
	}
	if string(got[0].body["expected_version"]) != "3" {
		t.Fatalf("expected_version = %s", got[0].body["expected_version"])
	}
}

func TestSecretUpdateConflictReturnsConflictError(t *testing.T) {
	var got []capturedRequest
	c := updateServer(t, http.StatusConflict, `"2026-09-27T11:00:00Z"`, &got)
	_, err := c.Secrets.Update(context.Background(), "db", &SecretUpdateRequest{IfMatch: `"stale"`, Data: map[string]string{"v": "x"}})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %T %v, want *ConflictError", err, err)
	}
	if conflict.ETag != `"2026-09-27T11:00:00Z"` {
		t.Fatalf("conflict ETag = %q", conflict.ETag)
	}
	var apiErr *ErrorResponse
	if !errors.As(err, &apiErr) || apiErr.Response.StatusCode != http.StatusConflict {
		t.Fatalf("ConflictError does not unwrap to *ErrorResponse: %v", err)
	}
	if msg := err.Error(); msg != "SecretServer request failed (HTTP 409)" || strings.Contains(msg, testKey) || strings.Contains(msg, "conflict body") {
		t.Fatalf("conflict error text = %q", msg)
	}
}

func TestSecretGetExposesETag(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"g-1"`)
		_, _ = w.Write([]byte(`{"id":"1","name":"db","data":{"v":"x"}}`))
	})
	sec, err := c.Secrets.Get(context.Background(), "db", nil)
	if err != nil {
		t.Fatal(err)
	}
	if sec.ETag != `"g-1"` {
		t.Fatalf("ETag = %q", sec.ETag)
	}
}

func TestSecretUpdateRejectsInvalidInputWithoutRequest(t *testing.T) {
	c := newTestClientConfig(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	}, Config{PartialUpdates: true})
	ctx := context.Background()
	d, empty := "d", ""
	for name, req := range map[string]*SecretUpdateRequest{
		"nil":             nil,
		"no fields":       {},
		"empty data":      {Data: map[string]string{}},
		"unknown clear":   {Clear: []string{"data"}},
		"set and clear":   {Description: &d, Clear: []string{"description"}},
		"empty container": {ContainerID: &empty},
	} {
		if _, err := c.Secrets.Update(ctx, "db", req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := c.Secrets.Get(ctx, "db", &SecretGetOptions{Version: "1"}); err == nil {
		t.Fatal("Get with version accepted")
	}
	if _, err := c.Secrets.List(ctx, &SecretListOptions{Limit: 1001}); err == nil {
		t.Fatal("limit 1001 accepted")
	}
	if _, err := c.Secrets.List(ctx, &SecretListOptions{Limit: -1}); err == nil {
		t.Fatal("negative limit accepted")
	}
}

func TestListFiltersTagsClientSide(t *testing.T) {
	var query string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"secrets":[{"name":"a","tags":["x","y"]},{"name":"b","tags":["x"]},{"name":"c"}]}`))
	})
	got, err := c.Secrets.List(context.Background(), &SecretListOptions{Tags: []string{"x", "y"}, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("filtered = %#v", got)
	}
	if query != "limit=5" {
		t.Fatalf("query = %q", query)
	}
}

func TestSigningKeysBackendParamOnlyWhenSet(t *testing.T) {
	var query string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	})
	if _, err := c.Crypto.SigningKeys(context.Background(), ""); err != nil || query != "" {
		t.Fatalf("empty backend: query=%q err=%v", query, err)
	}
	if _, err := c.Crypto.SigningKeys(context.Background(), "soft hsm"); err != nil || query != "backend=soft+hsm" {
		t.Fatalf("backend: query=%q err=%v", query, err)
	}
}

func TestCertificateDownloadStreamsRawBytes(t *testing.T) {
	var query, accept string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query, accept = r.URL.RawQuery, r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"))
	})
	var buf bytes.Buffer
	if err := c.Certificates.Download(context.Background(), "id/1", nil, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "-----BEGIN CERTIFICATE-----") || accept != "*/*" || query != "" {
		t.Fatalf("download body=%q accept=%q query=%q", buf.String(), accept, query)
	}
	buf.Reset()
	if err := c.Certificates.Download(context.Background(), "1", &CertificateDownloadOptions{Format: "pfx", Password: "p&w"}, &buf); err != nil {
		t.Fatal(err)
	}
	if query != "format=pfx&password=p%26w" {
		t.Fatalf("pfx query = %q", query)
	}
	for _, bad := range []*CertificateDownloadOptions{{Format: "pfx"}, {Format: "der"}, {Format: "pem", Password: "x"}} {
		if err := c.Certificates.Download(context.Background(), "1", bad, &buf); err == nil {
			t.Fatalf("Download accepted %#v", bad)
		}
	}
	if err := c.Certificates.Download(context.Background(), "1", nil, nil); err == nil {
		t.Fatal("nil writer accepted")
	}
}

func TestCertificateGetWithPEM(t *testing.T) {
	var query string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"certificate":{"id":"1","name":"n","issuer_name":"CA","fingerprint":"ff","days_until_expiry":30,"renew_before":7,"updated_at":"t"},"certificate_pem":"PEM"}`))
	})
	cert, err := c.Certificates.GetWithPEM(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	if query != "include_pem=true" || cert.CertificatePEM != "PEM" || cert.IssuerName != "CA" || cert.Fingerprint != "ff" || cert.DaysUntilExpiry != 30 || cert.RenewBefore != 7 || cert.UpdatedAt != "t" {
		t.Fatalf("GetWithPEM = %#v (query %q)", cert, query)
	}
}

func TestSSHKeyContracts(t *testing.T) {
	var body map[string]interface{}
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body = nil
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		_, _ = w.Write([]byte(`{"id":"k","name":"n","key_type":"rsa","bits":4096,"fingerprint":"f","public_key":"ssh-rsa A","private_key":"PRIV"}`))
	})
	ctx := context.Background()
	key, err := c.SSHKeys.Export(ctx, "k")
	if err != nil || key.Bits != 4096 || key.PrivateKey != "PRIV" {
		t.Fatalf("Export = %#v, %v", key, err)
	}
	req := &GenerateSSHKeyRequest{Name: "n"}
	if _, err := c.SSHKeys.Generate(ctx, req); err != nil {
		t.Fatal(err)
	}
	if body["key_type"] != "ed25519" || req.KeyType != "" {
		t.Fatalf("generate body = %#v, caller request mutated: %q", body, req.KeyType)
	}
	if _, err := c.SSHKeys.Import(ctx, &ImportSSHKeyRequest{Name: "n", PrivateKey: "PEM", Passphrase: "pp"}); err != nil {
		t.Fatal(err)
	}
	if body["private_key"] != "PEM" || body["passphrase"] != "pp" {
		t.Fatalf("import body = %#v", body)
	}
	if _, ok := body["public_key"]; ok {
		t.Fatal("import still sends public_key")
	}
	if _, err := c.SSHKeys.Import(ctx, &ImportSSHKeyRequest{Name: "n"}); err == nil {
		t.Fatal("import without private_key accepted")
	}
}

func parseUpload(t *testing.T, r *http.Request) (string, string, map[string]string) {
	t.Helper()
	if r.Header.Get("Authorization") != "Bearer "+testKey {
		t.Errorf("missing bearer auth")
	}
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("not multipart: %v", err)
	}
	f, h, err := r.FormFile("file")
	if err != nil {
		t.Fatalf("no file part: %v", err)
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	fields := map[string]string{}
	for k, v := range r.MultipartForm.Value {
		fields[k] = v[0]
	}
	return h.Filename, string(data), fields
}

func TestExtractionAndLDAPImportUseMultipart(t *testing.T) {
	var name, content string
	var fields map[string]string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		name, content, fields = parseUpload(t, r)
		if r.URL.Path == "/api/v1/ldap/import" {
			_, _ = w.Write([]byte(`{"message":"ok","result":{"total_entries":2,"processed_entries":2,"dry_run":true}}`))
			return
		}
		_, _ = w.Write([]byte(`{"scan_id":"s","status":"completed","findings_count":0,"findings":[],"import_status":"ready"}`))
	})
	ctx := context.Background()
	res, err := c.Extraction.ExtractFromDB(ctx, "/tmp/dir/app.db", strings.NewReader("DATA"), true)
	if err != nil || res.ScanID != "s" || res.ImportStatus != "ready" {
		t.Fatalf("ExtractFromDB = %#v, %v", res, err)
	}
	if name != "app.db" || content != "DATA" || fields["auto_import"] != "true" {
		t.Fatalf("upload name=%q content=%q fields=%v", name, content, fields)
	}
	if _, err := c.Extraction.ExtractFromDB(ctx, "x.db", strings.NewReader("D"), false); err != nil || len(fields) != 0 {
		t.Fatalf("auto_import sent when false: %v %v", fields, err)
	}
	if _, err := c.Extraction.ExtractFromDB(ctx, "", strings.NewReader("D"), false); err == nil {
		t.Fatal("empty filename accepted")
	}

	imp, err := c.LDAP.Import(ctx, "dir.ldif", strings.NewReader("dn: cn=a"), &LDAPImportOptions{CreatePasswords: true, DryRun: true})
	if err != nil || imp.TotalEntries != 2 || !imp.DryRun {
		t.Fatalf("Import = %#v, %v", imp, err)
	}
	if fields["create_passwords"] != "true" || fields["dry_run"] != "true" || content != "dn: cn=a" {
		t.Fatalf("import fields = %v content=%q", fields, content)
	}
}

func TestLDAPSearchAndExport(t *testing.T) {
	var body map[string]interface{}
	var query string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&body)
			_, _ = w.Write([]byte(`{"results":[{"dn":"cn=a","attributes":{"cn":["a"]}}],"result_count":1}`))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("dn: cn=a,dc=x\ncn: a\n"))
	})
	ctx := context.Background()
	res, err := c.LDAP.Search(ctx, "conn", &LDAPSearchRequest{Filter: "(cn=a)", BaseDN: "dc=x", Attributes: []string{"cn"}, SizeLimit: 5})
	if err != nil || res.ResultCount != 1 || res.Results[0].Attributes["cn"][0] != "a" {
		t.Fatalf("Search = %#v, %v", res, err)
	}
	if body["filter"] != "(cn=a)" || body["base_dn"] != "dc=x" || body["size_limit"] != float64(5) {
		t.Fatalf("search body = %#v", body)
	}
	if _, err := c.LDAP.Search(ctx, "conn", &LDAPSearchRequest{Filter: "(cn=a)"}); err == nil {
		t.Fatal("search without base_dn accepted")
	}
	var buf bytes.Buffer
	if err := c.LDAP.Export(ctx, &LDAPExportOptions{Passwords: true, BaseDN: "dc=x"}, &buf); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "dn: cn=a,dc=x\ncn: a\n" || query != "base_dn=dc%3Dx&passwords=true" {
		t.Fatalf("export = %q query=%q", buf.String(), query)
	}
}

func TestJKSCreateEntrySetsKeystoreID(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"e1","alias":"a","entry_type":"trusted_cert"}`))
	})
	entry, err := c.JKS.CreateEntry(context.Background(), "ks-1", &CreateJKSEntryRequest{Alias: "a", EntryType: "trusted_cert", Certificate: "PEM"})
	if err != nil || entry.KeystoreID != "ks-1" || entry.ID != "e1" {
		t.Fatalf("CreateEntry = %#v, %v", entry, err)
	}
}
