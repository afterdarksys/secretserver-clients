package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// liveAdmin performs setup calls with the harness admin key.
func liveAdmin(t *testing.T, method, path string, body any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(method, os.Getenv("SS_LIVE_URL")+"/api/v1"+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SS_LIVE_KEY"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// TestLive runs only under scripts/live-integration.sh, which starts a
// disposable server and writes an owner-only token file.
func TestLive(t *testing.T) {
	rawURL, tokenFile := os.Getenv("SS_LIVE_URL"), os.Getenv("SS_LIVE_TOKEN_FILE")
	if rawURL == "" || tokenFile == "" {
		t.Skip("run scripts/live-integration.sh")
	}
	// Never exercise a non-disposable server: the live test writes and deletes data.
	if u, err := url.Parse(rawURL); err != nil || !isLoopback(u.Hostname()) || os.Getenv("SS_LIVE_KEY") == "" {
		t.Fatal("SS_LIVE_URL must be a loopback URL and SS_LIVE_KEY must be set")
	}
	client, err := NewClient(rawURL, tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// No HSM is configured on the disposable server: the signing path must
	// fail closed with an error rather than return fabricated metadata.
	if keys, err := client.ListSigningKeys(ctx, "pkcs11"); err == nil {
		t.Fatalf("expected unavailable backend error, got %d keys", len(keys))
	}
	if _, err := client.Sign(ctx, "pkcs11", "missing", "aGVsbG8=", "live test"); err == nil {
		t.Fatal("expected signing without a backend to fail")
	}
	// An unassigned variable must not resolve.
	if _, err := client.Render(ctx, "%%MCP_LIVE_UNASSIGNED%%"); err == nil {
		t.Fatal("unassigned variable resolved")
	}
	rendered, err := client.Render(ctx, "no variables here")
	if err != nil || rendered != "no variables here" {
		t.Fatalf("plain template render = %q, %v", rendered, err)
	}

	// End to end through the MCP tool layer with a real variable.
	created := liveAdmin(t, "POST", "/secrets", map[string]any{"name": "mcp-live", "data": map[string]string{"value": "mcp-secret"}, "container_id": os.Getenv("SS_LIVE_CONTAINER")})
	defer liveAdmin(t, "DELETE", "/secrets/mcp-live", nil)
	liveAdmin(t, "PUT", "/variables/MCP_LIVE", map[string]any{"secret_type": "secret", "secret_id": created["id"], "field": "value"})
	defer liveAdmin(t, "DELETE", "/variables/MCP_LIVE", nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := newServer(client, serverOptions{resolveAllow: map[string]bool{"MCP_LIVE": true}}).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "live", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "resolve_secret_template", Arguments: map[string]any{"template": "v=%%MCP_LIVE%%"}})
	if err != nil || result.IsError {
		t.Fatalf("allowlisted resolve failed: %v", err)
	}
	if got := result.StructuredContent.(map[string]any)["rendered"]; got != "v=mcp-secret" {
		t.Fatalf("rendered = %v", got)
	}
	result, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "resolve_secret_template", Arguments: map[string]any{"template": "%%OTHER_SECRET%%"}})
	if err != nil || !result.IsError {
		t.Fatal("unlisted variable was not refused")
	}
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
