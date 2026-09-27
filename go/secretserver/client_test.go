package secretserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClientMatchesBackendContract(t *testing.T) {
	var updateBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk_test" {
			t.Errorf("Authorization = %q", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/proxy/api/v1/secrets":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"secrets":[{"id":"1","name":"prod/db"}],"total":1}`))
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/proxy/api/v1/secrets/prod%2Fdb":
			_, _ = w.Write([]byte(`{"id":"1","name":"prod/db","data":{"value":"old"}}`))
		case r.Method == http.MethodPut && r.URL.EscapedPath() == "/proxy/api/v1/secrets/prod%2Fdb":
			if err := json.NewDecoder(r.Body).Decode(&updateBody); err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","name":"prod/db"}`))
		case r.Method == http.MethodDelete && r.URL.EscapedPath() == "/proxy/api/v1/jks-keystores/store/entries/release%2Fkey":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, r.Method+" "+r.URL.EscapedPath(), http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewClient(&Config{APIURL: server.URL + "/proxy/api/v1", APIKey: "sk_test"})
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := client.Secrets.List(context.Background(), nil)
	if err != nil || len(secrets) != 1 || secrets[0].Name != "prod/db" {
		t.Fatalf("Secrets.List() = %#v, %v", secrets, err)
	}
	_, err = client.Secrets.Update(context.Background(), "prod/db", &SecretUpdateRequest{Data: map[string]string{"value": "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, sent := updateBody["name"]; sent || len(updateBody) != 1 {
		t.Fatalf("partial update sent more than the data field: %#v", updateBody)
	}
	if err := client.JKS.DeleteEntry(context.Background(), "store", "release/key"); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientRequiresAPIKey(t *testing.T) {
	if _, err := NewClient(nil); err == nil {
		t.Fatal("NewClient(nil) accepted an empty API key")
	}
}

const testKey = "sk_test_do_not_leak_0123456789"

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(&Config{APIURL: srv.URL, APIKey: testKey})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewClientRejectsUnsafeURLs(t *testing.T) {
	for _, raw := range []string{
		"http://api.example.com",
		"http://10.0.0.1:8080",
		"http://localhost.example.com",
		"https://user:pass@api.example.com",
		"http://user@localhost:8080",
		"ftp://api.example.com",
		"https://",
		"api.example.com",
		"https://api.example.com/?x=1",
	} {
		_, err := NewClient(&Config{APIURL: raw, APIKey: testKey})
		if err == nil {
			t.Errorf("NewClient(%q) accepted an unsafe URL", raw)
			continue
		}
		if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), "pass") {
			t.Errorf("NewClient(%q) error leaks credentials: %v", raw, err)
		}
	}
}

func TestNewClientAcceptsHTTPSAndLoopbackHTTP(t *testing.T) {
	for _, raw := range []string{
		"https://api.example.com",
		"https://api.example.com/api/v1",
		"http://localhost:8080",
		"http://127.0.0.1:8080/api/v1",
		"http://[::1]:8080",
	} {
		if _, err := NewClient(&Config{APIURL: raw, APIKey: testKey}); err != nil {
			t.Errorf("NewClient(%q) = %v", raw, err)
		}
	}
}

func TestDefaultTransportEnforcesTLS12AndVerification(t *testing.T) {
	c, err := NewClient(&Config{APIKey: testKey})
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatal("default client has no explicit TLS config")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x", tr.TLSClientConfig.MinVersion)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default client skips TLS verification")
	}
	if tr == http.DefaultTransport {
		t.Fatal("default client mutates the shared http.DefaultTransport")
	}
}

func TestNewClientRejectsInsecureSkipVerify(t *testing.T) {
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // negative test
	if _, err := NewClient(&Config{APIKey: testKey, HTTPClient: hc}); err == nil {
		t.Fatal("NewClient accepted an HTTP client that disables TLS verification")
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	var followed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, r *http.Request) {
		followed.Add(1)
		_, _ = w.Write([]byte(`{"secrets":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, hc := range []*http.Client{nil, {}} {
		c, err := NewClient(&Config{APIURL: srv.URL, APIKey: testKey, HTTPClient: hc})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Secrets.List(context.Background(), nil)
		var apiErr *ErrorResponse
		if !errors.As(err, &apiErr) || apiErr.Response.StatusCode != http.StatusFound {
			t.Fatalf("redirect not surfaced as error: %v", err)
		}
	}
	if followed.Load() != 0 {
		t.Fatal("client followed a redirect")
	}
}

func TestErrorsExcludeBodyAndKey(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"leaked-secret-value ` + r.Header.Get("Authorization") + `"}`))
	})
	_, err := c.Secrets.Get(context.Background(), "x", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if strings.Contains(msg, "leaked-secret-value") || strings.Contains(msg, testKey) {
		t.Fatalf("error leaks body or key: %q", msg)
	}
	if !strings.Contains(msg, "HTTP 500") {
		t.Fatalf("error lacks status: %q", msg)
	}
}

func TestWrongKeyReturnsAuthErrorWithoutKey(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid key `+r.Header.Get("Authorization")+`"}`, http.StatusUnauthorized)
	})
	_, err := c.Secrets.List(context.Background(), nil)
	var apiErr *ErrorResponse
	if !errors.As(err, &apiErr) || apiErr.Response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 ErrorResponse, got %v", err)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatal("error contains API key")
	}
}

func TestInvalidJSONSuccessIsRejected(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>secret-body-text</html>`))
	})
	_, err := c.Secrets.Get(context.Background(), "x", nil)
	if err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if strings.Contains(err.Error(), "secret-body-text") || strings.Contains(err.Error(), "<") {
		t.Fatalf("error leaks body: %v", err)
	}
}

func TestOversizeJSONResponseIsRejected(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"`))
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxJSONResponseBytes))
		_, _ = w.Write([]byte(`"}`))
	})
	_, err := c.Secrets.Get(context.Background(), "x", nil)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversize JSON: got %v", err)
	}
}

func TestJSONAtCapIsAccepted(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		prefix, suffix := `{"name":"`, `"}`
		_, _ = w.Write([]byte(prefix))
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxJSONResponseBytes-len(prefix)-len(suffix)))
		_, _ = w.Write([]byte(suffix))
	})
	s, err := c.Secrets.Get(context.Background(), "x", nil)
	if err != nil || len(s.Name) == 0 {
		t.Fatalf("JSON at cap rejected: %v", err)
	}
}

func TestOversizeDownloadIsRejected(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("b"), maxDownloadBytes+1))
	})
	var sink countingWriter
	_, err := c.Call(context.Background(), http.MethodGet, "/raw", nil, &sink)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversize download: got %v", err)
	}
	if sink.n != 0 {
		t.Fatalf("wrote %d bytes of an oversize download", sink.n)
	}
}

func TestDownloadAtCapIsAccepted(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("b"), maxDownloadBytes))
	})
	var sink countingWriter
	if _, err := c.Call(context.Background(), http.MethodGet, "/raw", nil, &sink); err != nil {
		t.Fatal(err)
	}
	if sink.n != maxDownloadBytes {
		t.Fatalf("wrote %d bytes", sink.n)
	}
}

func TestTransportErrorRedactsQuery(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, err := NewClient(&Config{APIURL: url, APIKey: testKey})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Call(context.Background(), http.MethodGet, "/certificates/x/download?format=pfx&password=hunter2", nil, io.Discard)
	if err == nil {
		t.Fatal("expected connection error")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), testKey) {
		t.Fatalf("transport error leaks query or key: %v", err)
	}
}

func TestPathSegmentsAreEscaped(t *testing.T) {
	var got string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{}`))
	})
	_, _ = c.LDAP.Search(context.Background(), "../x/y?z", &LDAPSearchRequest{Filter: "(cn=*)", BaseDN: "dc=x"})
	if want := "/api/v1/ldap/connections/..%2Fx%2Fy%3Fz/search"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }
