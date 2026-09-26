package ui

import (
	"errors"
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"
	"github.com/zalando/go-keyring"
)

const testURL = "https://api.example.test"

func TestLoadAPIKeyMigratesPlaintextToKeychain(t *testing.T) {
	keyring.MockInit()
	prefs := test.NewTempApp(t).Preferences()
	prefs.SetString(prefLegacyAPIKey, "sk_plain")

	key, err := loadAPIKey(prefs, testURL)
	if err != nil || key != "sk_plain" {
		t.Fatalf("loadAPIKey = %q, %v", key, err)
	}
	if prefs.String(prefLegacyAPIKey) != "" {
		t.Fatal("plaintext API key still in preferences after migration")
	}
	if stored, err := keyring.Get(keyringService, testURL); err != nil || stored != "sk_plain" {
		t.Fatalf("keychain = %q, %v", stored, err)
	}
}

func TestLoadAPIKeyNoKey(t *testing.T) {
	keyring.MockInit()
	prefs := test.NewTempApp(t).Preferences()
	if key, err := loadAPIKey(prefs, testURL); err != nil || key != "" {
		t.Fatalf("loadAPIKey = %q, %v", key, err)
	}
}

func TestLoadAPIKeyKeychainFailureFailsClosed(t *testing.T) {
	keyring.MockInitWithError(errors.New("no secret service"))
	defer keyring.MockInit()
	prefs := test.NewTempApp(t).Preferences()
	prefs.SetString(prefLegacyAPIKey, "sk_plain")

	key, err := loadAPIKey(prefs, testURL)
	if err == nil || key != "" {
		t.Fatalf("loadAPIKey = %q, %v; want error and no key", key, err)
	}
	if prefs.String(prefLegacyAPIKey) != "" {
		t.Fatal("plaintext API key kept in preferences after failed migration")
	}
	if strings.Contains(err.Error(), "sk_plain") {
		t.Fatal("error contains the API key")
	}
}

func TestSaveAPIKeyFailureDoesNotPersistPlaintext(t *testing.T) {
	keyring.MockInitWithError(errors.New("locked"))
	defer keyring.MockInit()
	prefs := test.NewTempApp(t).Preferences()

	if err := saveAPIKey(prefs, testURL, "sk_new"); err == nil {
		t.Fatal("saveAPIKey succeeded without a keychain")
	}
	if prefs.String(prefLegacyAPIKey) != "" || prefs.String(prefAPIURL) != "" {
		t.Fatal("preferences written despite keychain failure")
	}
}

func TestSaveAPIKeyStoresInKeychainAndDropsOldURL(t *testing.T) {
	keyring.MockInit()
	prefs := test.NewTempApp(t).Preferences()
	if err := saveAPIKey(prefs, testURL, "sk_one"); err != nil {
		t.Fatal(err)
	}
	if err := saveAPIKey(prefs, "https://other.example.test", "sk_two"); err != nil {
		t.Fatal(err)
	}
	if prefs.String(prefLegacyAPIKey) != "" {
		t.Fatal("API key written to preferences")
	}
	if prefs.String(prefAPIURL) != "https://other.example.test" {
		t.Fatalf("api_url = %q", prefs.String(prefAPIURL))
	}
	if _, err := keyring.Get(keyringService, testURL); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("old URL key not removed: %v", err)
	}
	if key, err := loadAPIKey(prefs, "https://other.example.test"); err != nil || key != "sk_two" {
		t.Fatalf("loadAPIKey = %q, %v", key, err)
	}
}
