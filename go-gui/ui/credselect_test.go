package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"github.com/zalando/go-keyring"
)

const cliToken = "eyJ.gui-cli-token-do-not-leak.sig"

// fakeSS installs an `ss` stand-in via SS_CLI_PATH that runs body.
func fakeSS(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ss")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SS_CLI_PATH", path)
}

func loggedIn(t *testing.T, apiURL string) {
	fakeSS(t, fmt.Sprintf(`printf '%%s' '{"access_token":"%s","expires_at":"%s","api_url":"%s","tenant_id":"t-42"}'`,
		cliToken, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), apiURL))
}

func cliPrefs(t *testing.T) fyne.Preferences {
	prefs := test.NewTempApp(t).Preferences()
	prefs.SetString(prefAuthMode, authModeCLILogin)
	return prefs
}

func assertNoSecret(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, cliToken) {
		t.Fatalf("token leaked: %q", s)
	}
}

func TestAuthModeDefaultsToAPIKey(t *testing.T) {
	prefs := test.NewTempApp(t).Preferences()
	if got := authMode(prefs); got != authModeAPIKey {
		t.Fatalf("authMode = %q", got)
	}
	prefs.SetString(prefAuthMode, "bogus")
	if got := authMode(prefs); got != authModeAPIKey {
		t.Fatalf("unknown mode should fall back to API key, got %q", got)
	}
}

func TestBuildClientCLIUsesSessionURL(t *testing.T) {
	keyring.MockInitWithError(errors.New("keychain must not be used"))
	loggedIn(t, testURL)
	prefs := cliPrefs(t)

	client, account, err := buildClient(context.Background(), prefs)
	if err != nil || client == nil {
		t.Fatalf("buildClient = %v, %v", client, err)
	}
	if !strings.Contains(account, testURL) || !strings.Contains(account, "t-42") {
		t.Fatalf("account = %q", account)
	}
	assertNoSecret(t, account)
	for _, k := range []string{prefAPIURL, prefLegacyAPIKey, prefAuthMode} {
		assertNoSecret(t, prefs.String(k))
	}
}

func TestBuildClientCLIEquivalentURL(t *testing.T) {
	loggedIn(t, testURL)
	prefs := cliPrefs(t)
	prefs.SetString(prefAPIURL, "HTTPS://api.example.test:443/")
	if client, _, err := buildClient(context.Background(), prefs); err != nil || client == nil {
		t.Fatalf("buildClient = %v, %v", client, err)
	}
}

func TestBuildClientCLIRefusesMismatchedURL(t *testing.T) {
	loggedIn(t, testURL)
	prefs := cliPrefs(t)
	prefs.SetString(prefAPIURL, "https://evil.example.test")

	client, _, err := buildClient(context.Background(), prefs)
	if client != nil || err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("buildClient = %v, %v; want mismatch error", client, err)
	}
	assertNoSecret(t, err.Error())
}

func TestBuildClientCLINotLoggedIn(t *testing.T) {
	fakeSS(t, `echo "not logged in" >&2; exit 2`)
	client, _, err := buildClient(context.Background(), cliPrefs(t))
	if client != nil || err == nil || !strings.Contains(err.Error(), "run `ss login` in a terminal") {
		t.Fatalf("buildClient = %v, %v", client, err)
	}
}

func TestBuildClientCLIOtherFailureFailsClosed(t *testing.T) {
	fakeSS(t, `printf '%s' 'not json'`)
	client, _, err := buildClient(context.Background(), cliPrefs(t))
	if client != nil || err == nil {
		t.Fatalf("buildClient = %v, %v; want error", client, err)
	}
}

func TestBuildClientAPIKeyModeUsesKeychain(t *testing.T) {
	keyring.MockInit()
	fakeSS(t, `exit 99`) // must not be run in API-key mode
	prefs := test.NewTempApp(t).Preferences()

	if client, _, err := buildClient(context.Background(), prefs); client != nil || err != nil {
		t.Fatalf("no key stored: buildClient = %v, %v", client, err)
	}
	if err := saveAPIKey(prefs, testURL, "sk_test"); err != nil {
		t.Fatal(err)
	}
	client, account, err := buildClient(context.Background(), prefs)
	if err != nil || client == nil || !strings.Contains(account, testURL) {
		t.Fatalf("buildClient = %v, %q, %v", client, account, err)
	}
	if strings.Contains(account, "sk_test") {
		t.Fatalf("API key leaked in account line: %q", account)
	}
}
