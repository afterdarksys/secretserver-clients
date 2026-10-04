package secretserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const cliTestToken = "eyJ.cli-session-token-do-not-leak.sig"

// fakeSS writes an executable `ss` stand-in that records each run in a count
// file, refuses any argv other than the documented one, and then runs body.
func fakeSS(t *testing.T, body string) (path, countFile string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "ss")
	countFile = filepath.Join(dir, "count")
	script := fmt.Sprintf(`#!/bin/sh
echo run >> '%s'
if [ "$#" -ne 4 ] || [ "$1" != auth ] || [ "$2" != print-access-token ] || [ "$3" != --format ] || [ "$4" != json ]; then
  echo "unexpected argv: $*" >&2
  exit 1
fi
%s
`, countFile, body)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, countFile
}

func tokenJSON(token string, expires time.Time, apiURL string) string {
	return fmt.Sprintf(`printf '%%s' '{"access_token":"%s","expires_at":"%s","api_url":"%s","tenant_id":"t-1"}'`,
		token, expires.UTC().Format(time.RFC3339), apiURL)
}

func runs(t *testing.T, countFile string) int {
	t.Helper()
	b, err := os.ReadFile(countFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		t.Fatal(err)
	}
	return strings.Count(string(b), "run\n")
}

func assertNoToken(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), cliTestToken) || strings.Contains(fmt.Sprintf("%+v", err), cliTestToken) {
		t.Fatalf("error leaks the access token: %v", err)
	}
}

func TestCLICredentialsSuccessAndCache(t *testing.T) {
	path, count := fakeSS(t, tokenJSON(cliTestToken, time.Now().Add(time.Hour), "https://api.example.com"))
	p := &CLICredentialProvider{Path: path}
	for i := 0; i < 3; i++ {
		got, err := p.Token(context.Background())
		if err != nil || got != cliTestToken {
			t.Fatalf("Token() = %q, %v", got, err)
		}
	}
	if n := runs(t, count); n != 1 {
		t.Fatalf("CLI ran %d times, want 1 (cached)", n)
	}
	apiURL, err := p.APIURL(context.Background())
	if err != nil || apiURL != "https://api.example.com" {
		t.Fatalf("APIURL() = %q, %v", apiURL, err)
	}
	if n := runs(t, count); n != 1 {
		t.Fatalf("APIURL re-ran the CLI: %d runs", n)
	}
}

func TestCLICredentialsRefreshesNearExpiry(t *testing.T) {
	path, count := fakeSS(t, tokenJSON(cliTestToken, time.Now().Add(30*time.Second), ""))
	p := &CLICredentialProvider{Path: path}
	for i := 0; i < 2; i++ {
		if _, err := p.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := runs(t, count); n != 2 {
		t.Fatalf("CLI ran %d times, want 2 (token within 60 s of expiry)", n)
	}
}

func TestCLICredentialsUsesSSCLIPath(t *testing.T) {
	path, count := fakeSS(t, tokenJSON(cliTestToken, time.Now().Add(time.Hour), ""))
	t.Setenv("SS_CLI_PATH", path)
	if got, err := CLICredentials().Token(context.Background()); err != nil || got != cliTestToken {
		t.Fatalf("Token() = %q, %v", got, err)
	}
	if runs(t, count) != 1 {
		t.Fatal("SS_CLI_PATH was not used")
	}
}

func TestCLICredentialsNotLoggedIn(t *testing.T) {
	path, _ := fakeSS(t, `echo "not logged in" >&2; exit 2`)
	_, err := (&CLICredentialProvider{Path: path}).Token(context.Background())
	if !errors.Is(err, ErrCLINotLoggedIn) || !strings.Contains(err.Error(), "ss login") {
		t.Fatalf("Token() error = %v, want ErrCLINotLoggedIn mentioning `ss login`", err)
	}
}

func TestCLICredentialsFailuresNeverLeakToken(t *testing.T) {
	big := `head -c 70000 /dev/zero | tr '\0' a; ` + tokenJSON(cliTestToken, time.Now().Add(time.Hour), "")
	cases := map[string]struct{ body, want string }{
		"exit 1":           {`echo "network unreachable" >&2; printf '` + cliTestToken + `'; exit 1`, "network unreachable"},
		"malformed json":   {`printf '{"access_token":"` + cliTestToken + `",'`, "invalid JSON"},
		"bad expires_at":   {`printf '{"access_token":"` + cliTestToken + `","expires_at":"soon"}'`, "expires_at"},
		"empty token":      {`printf '{"access_token":"","expires_at":"2099-01-01T00:00:00Z"}'`, "access_token"},
		"header inject":    {`printf '{"access_token":"a b\\r\\nX: y","expires_at":"2099-01-01T00:00:00Z"}'`, "access_token"},
		"oversized stdout": {big, "exceeds 65536 bytes"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path, _ := fakeSS(t, tc.body)
			_, err := (&CLICredentialProvider{Path: path}).Token(context.Background())
			assertNoToken(t, err)
			if errors.Is(err, ErrCLINotLoggedIn) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Token() error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestCLICredentialsTimeout(t *testing.T) {
	path, _ := fakeSS(t, `exec sleep 10`)
	start := time.Now()
	p := &CLICredentialProvider{Path: path}
	p.timeout = 200 * time.Millisecond
	_, err := p.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("Token() error = %v, want timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
}

func TestCLICredentialsMissingBinary(t *testing.T) {
	_, err := (&CLICredentialProvider{Path: filepath.Join(t.TempDir(), "no-such-ss")}).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Token() error = %v, want not found", err)
	}
}

func TestClientUsesTokenProviderPerRequest(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"secrets":[],"total":0}`))
	}))
	defer srv.Close()
	path, count := fakeSS(t, tokenJSON(cliTestToken, time.Now().Add(time.Hour), srv.URL))
	t.Setenv("SS_CLI_PATH", path)
	c, err := NewCLIClient(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Secrets.List(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 || seen[0] != "Bearer "+cliTestToken || seen[1] != seen[0] {
		t.Fatalf("Authorization headers = %q", seen)
	}
	if runs(t, count) != 1 {
		t.Fatal("token was not cached across requests")
	}
	if _, err := NewCLIClient(context.Background(), &Config{APIKey: "sk_x"}); err == nil {
		t.Fatal("NewCLIClient accepted an API key")
	}
}

func TestClientTokenProviderFailsClosed(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	for name, provider := range map[string]func(context.Context) (string, error){
		"error":     func(context.Context) (string, error) { return "", ErrCLINotLoggedIn },
		"empty":     func(context.Context) (string, error) { return "", nil },
		"malformed": func(context.Context) (string, error) { return "a\r\nX-Injected: 1", nil },
	} {
		c, err := NewClient(&Config{APIURL: srv.URL, TokenProvider: provider})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Secrets.List(context.Background(), nil); err == nil {
			t.Fatalf("%s: request succeeded without a valid token", name)
		}
	}
	if hits != 0 {
		t.Fatalf("server saw %d requests without a valid token", hits)
	}
}

func TestNewClientCredentialExclusivity(t *testing.T) {
	tp := func(context.Context) (string, error) { return "x", nil }
	if _, err := NewClient(&Config{APIKey: testKey, TokenProvider: tp}); err == nil {
		t.Fatal("NewClient accepted both APIKey and TokenProvider")
	}
	if _, err := NewClient(&Config{TokenProvider: tp}); err != nil {
		t.Fatalf("NewClient(TokenProvider) = %v", err)
	}
}
