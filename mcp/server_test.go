package main

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testClient(t *testing.T, rawURL string) *Client {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("sk_test_agent_identity_123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(rawURL, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func connect(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	result, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func TestDefaultBridgeExposesNoSecretReturningTool(t *testing.T) {
	opts, err := loadOptions(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	names := toolNames(t, connect(t, newServer(testClient(t, "https://secrets.example.test"), opts)))
	if strings.Join(names, ",") != "list_key_metadata,sign_with_key" {
		t.Fatalf("default tools = %v", names)
	}
}

func TestResolutionRequiresExplicitAllowlist(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	for _, bad := range []map[string]string{
		{"SECRETSERVER_ENABLE_SECRET_RESOLUTION": "1"},
		{"SECRETSERVER_ENABLE_SECRET_RESOLUTION": "1", "SECRETSERVER_RESOLVE_ALLOW": " , "},
		{"SECRETSERVER_ENABLE_SECRET_RESOLUTION": "1", "SECRETSERVER_RESOLVE_ALLOW": "OK,lower"},
		{"SECRETSERVER_ENABLE_SECRET_RESOLUTION": "1", "SECRETSERVER_RESOLVE_ALLOW": "*"},
	} {
		if _, err := loadOptions(env(bad)); err == nil {
			t.Fatalf("accepted unsafe resolution config %v", bad)
		}
	}
	opts, err := loadOptions(env(map[string]string{"SECRETSERVER_ENABLE_SECRET_RESOLUTION": "1", "SECRETSERVER_RESOLVE_ALLOW": "DB_PASS, API_TOKEN"}))
	if err != nil || !opts.resolveAllow["DB_PASS"] || !opts.resolveAllow["API_TOKEN"] || len(opts.resolveAllow) != 2 {
		t.Fatalf("allowlist = %v, %v", opts.resolveAllow, err)
	}
}

func TestResolveToolRefusesUnlistedVariablesBeforeCallingServer(t *testing.T) {
	var requests atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.WriteString(w, `{"rendered":"pw=hunter2"}`)
	}))
	defer api.Close()
	cs := connect(t, newServer(testClient(t, api.URL), serverOptions{resolveAllow: map[string]bool{"DB_PASS": true}}))
	call := func(template string) *mcp.CallToolResult {
		t.Helper()
		result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "resolve_secret_template", Arguments: map[string]any{"template": template}})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, template := range []string{"%%OTHER%%", "pw=%%DB_PASS%% %%ROOT_KEY%%", "%%DB_PASS", "%%lower%%"} {
		if result := call(template); !result.IsError {
			t.Fatalf("template %q was not refused", template)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("refused templates reached the server %d times", requests.Load())
	}
	result := call("pw=%%DB_PASS%% literal=%%%%OTHER%%%%")
	if result.IsError || requests.Load() != 1 {
		t.Fatalf("allowlisted template failed: %#v", result)
	}
}

func TestTemplateVariablesMatchesServerGrammar(t *testing.T) {
	names, err := templateVariables("a=%%A%% b=%%%%B%%%% c=%%C_1%%")
	if err != nil || strings.Join(names, ",") != "A,C_1" {
		t.Fatalf("names = %v, %v", names, err)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
		io.WriteString(w, `[]`)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	client := testClient(t, origin.URL)
	if _, err := client.ListSigningKeys(context.Background(), "pkcs11"); err == nil {
		t.Fatal("redirect response treated as success")
	}
	if leaked.Load() != 0 {
		t.Fatal("bearer token followed a redirect")
	}
}

func TestClientKeepsProxyPrefixAndRequiresTLS12(t *testing.T) {
	var path string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		io.WriteString(w, `[]`)
	}))
	defer api.Close()
	client := testClient(t, api.URL+"/ss/api/v1/")
	if _, err := client.ListSigningKeys(context.Background(), "pkcs11"); err != nil {
		t.Fatal(err)
	}
	if path != "/ss/api/v1/crypto/signing-keys" {
		t.Fatalf("request path = %q", path)
	}
	transport := newHTTPClient().Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("unsafe TLS configuration")
	}
}

func TestSignRejectsOutOfBoundsInputWithoutCallingServer(t *testing.T) {
	var requests atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer api.Close()
	client := testClient(t, api.URL)
	ctx := context.Background()
	for _, tc := range []struct{ key, msg, purpose string }{
		{"", "aGk=", "audit"},
		{"k", "", "audit"},
		{"k", strings.Repeat("A", maxSignMessageChars+4), "audit"},
		{"k", "aGk=", "  "},
		{"k", "aGk=", strings.Repeat("p", maxShortField+1)},
	} {
		if _, err := client.Sign(ctx, "pkcs11", tc.key, tc.msg, tc.purpose); err == nil {
			t.Fatalf("accepted out-of-bounds sign input %q/%d/%q", tc.key, len(tc.msg), tc.purpose)
		}
	}
	if _, err := client.Render(ctx, strings.Repeat("x", maxTemplateBytes+1)); err == nil {
		t.Fatal("oversized template accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("rejected input reached the server")
	}
}
