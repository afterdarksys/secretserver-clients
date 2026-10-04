package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secretserver "github.com/afterdarksys/secretserver-clients/go/secretserver"
)

const cliTestToken = "eyJ.mcp-cli-session-token-do-not-leak.sig"

// fakeSS writes an `ss` stand-in that counts its runs and refuses any argv
// other than `auth print-access-token --format json`.
func fakeSS(t *testing.T, body string) (*secretserver.CLICredentialProvider, func() int) {
	t.Helper()
	dir := t.TempDir()
	path, count := filepath.Join(dir, "ss"), filepath.Join(dir, "count")
	script := fmt.Sprintf(`#!/bin/sh
echo run >> '%s'
if [ "$#" -ne 4 ] || [ "$1" != auth ] || [ "$2" != print-access-token ] || [ "$3" != --format ] || [ "$4" != json ]; then
  echo "unexpected argv" >&2; exit 1
fi
%s
`, count, body)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	runs := func() int {
		b, err := os.ReadFile(count)
		if err != nil {
			return 0
		}
		return strings.Count(string(b), "run\n")
	}
	return &secretserver.CLICredentialProvider{Path: path}, runs
}

func cliTokenJSON(expiresIn time.Duration, apiURL string) string {
	return fmt.Sprintf(`printf '%%s' '{"access_token":"%s","expires_at":"%s","api_url":"%s"}'`,
		cliTestToken, time.Now().Add(expiresIn).UTC().Format(time.RFC3339), apiURL)
}

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestCLILoginClientUsesSSOTokenAndURL(t *testing.T) {
	creds, runs := fakeSS(t, cliTokenJSON(time.Hour, "https://cli.example.test"))
	client, err := newClientFromEnv(context.Background(), envMap(map[string]string{"SECRETSERVER_USE_CLI_LOGIN": "1"}), creds)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var seen []string
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.URL.Host+" "+r.Header.Get("Authorization"))
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`[]`))}, nil
	})
	for i := 0; i < 2; i++ {
		if _, err := client.ListSigningKeys(context.Background(), "pkcs11"); err != nil {
			t.Fatal(err)
		}
	}
	want := "cli.example.test Bearer " + cliTestToken
	if len(seen) != 2 || seen[0] != want || seen[1] != want {
		t.Fatalf("requests = %q", seen)
	}
	if runs() != 1 {
		t.Fatalf("CLI ran %d times, want 1 (cached)", runs())
	}
	client.Close()
	if _, err := client.ListSigningKeys(context.Background(), "pkcs11"); err == nil {
		t.Fatal("closed client still sent requests")
	}
}

func TestCLILoginExplicitURLWinsAndRefreshes(t *testing.T) {
	// Explicit URL matches (modulo case) the CLI's session, so it is used
	// as given rather than the CLI's own casing, and still refreshes.
	creds, runs := fakeSS(t, cliTokenJSON(30*time.Second, "https://Pinned.example.test"))
	client, err := newClientFromEnv(context.Background(), envMap(map[string]string{
		"SECRETSERVER_USE_CLI_LOGIN": "1", "SECRETSERVER_URL": "https://pinned.example.test",
	}), creds)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "pinned.example.test" {
			t.Errorf("host = %s", r.URL.Host)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`[]`))}, nil
	})
	if _, err := client.ListSigningKeys(context.Background(), "pkcs11"); err != nil {
		t.Fatal(err)
	}
	// Startup check + one request; the token expires within 60 s so each use refreshes.
	if runs() != 2 {
		t.Fatalf("CLI ran %d times, want 2", runs())
	}
}

func TestCLILoginRefusesMismatchedURL(t *testing.T) {
	creds, runs := fakeSS(t, cliTokenJSON(time.Hour, "https://cli.example.test"))
	_, err := newClientFromEnv(context.Background(), envMap(map[string]string{
		"SECRETSERVER_USE_CLI_LOGIN": "1", "SECRETSERVER_URL": "https://pinned.example.test",
	}), creds)
	if err == nil || !strings.Contains(err.Error(), "https://pinned.example.test") || !strings.Contains(err.Error(), "https://cli.example.test") {
		t.Fatalf("err = %v, want a mismatch error naming both URLs", err)
	}
	if strings.Contains(err.Error(), cliTestToken) {
		t.Fatalf("error leaks the access token: %v", err)
	}
	if runs() != 1 {
		t.Fatalf("CLI ran %d times, want 1", runs())
	}
}

func TestCLILoginConfigurationFailsClosed(t *testing.T) {
	creds, _ := fakeSS(t, cliTokenJSON(time.Hour, "https://cli.example.test"))
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("sk_test_agent_identity_123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string]map[string]string{
		"both":    {"SECRETSERVER_USE_CLI_LOGIN": "1", "SECRETSERVER_TOKEN_FILE": tokenPath},
		"invalid": {"SECRETSERVER_USE_CLI_LOGIN": "yes"},
		"http":    {"SECRETSERVER_USE_CLI_LOGIN": "1", "SECRETSERVER_URL": "http://secrets.example.test"},
	} {
		if _, err := newClientFromEnv(context.Background(), envMap(env), creds); err == nil {
			t.Errorf("%s: configuration accepted", name)
		}
	}
	plainHTTP, _ := fakeSS(t, cliTokenJSON(time.Hour, "http://cli.example.test"))
	if _, err := newClientFromEnv(context.Background(), envMap(map[string]string{"SECRETSERVER_USE_CLI_LOGIN": "1"}), plainHTTP); err == nil {
		t.Error("non-loopback http api_url from the CLI accepted")
	}
	client, err := newClientFromEnv(context.Background(), envMap(map[string]string{"SECRETSERVER_URL": "https://secrets.example.test", "SECRETSERVER_TOKEN_FILE": tokenPath}), creds)
	if err != nil {
		t.Fatalf("token-file mode: %v", err)
	}
	client.Close()
}

func TestCLILoginNotLoggedIn(t *testing.T) {
	creds, _ := fakeSS(t, `exit 2`)
	_, err := newClientFromEnv(context.Background(), envMap(map[string]string{"SECRETSERVER_USE_CLI_LOGIN": "1"}), creds)
	if err == nil || !strings.Contains(err.Error(), "ss login") {
		t.Fatalf("err = %v, want run `ss login`", err)
	}
	leaky, _ := fakeSS(t, `printf '{"access_token":"`+cliTestToken+`",'`)
	_, err = newClientFromEnv(context.Background(), envMap(map[string]string{"SECRETSERVER_USE_CLI_LOGIN": "1"}), leaky)
	if err == nil || strings.Contains(err.Error(), cliTestToken) {
		t.Fatalf("err = %v, want an error without the token", err)
	}
}
