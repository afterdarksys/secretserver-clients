package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLive runs only under scripts/live-integration.sh, which starts a
// disposable server and writes an owner-only token file.
func TestLive(t *testing.T) {
	rawURL, tokenFile := os.Getenv("SS_LIVE_URL"), os.Getenv("SS_LIVE_TOKEN_FILE")
	if rawURL == "" || tokenFile == "" {
		t.Skip("run scripts/live-integration.sh")
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
}
