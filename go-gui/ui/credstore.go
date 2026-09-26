package ui

import (
	"errors"
	"fmt"

	"fyne.io/fyne/v2"
	"github.com/zalando/go-keyring"
)

// Threats: keeps the API key out of plaintext Fyne preferences by storing it
// in the OS keychain (service keyringService, account = API URL). Legacy
// plaintext keys are moved into the keychain and deleted from preferences.
// If the keychain is unavailable it fails closed: the key is never written to
// preferences and no client is built. It does not protect against malware
// running as the same OS user, which can read the keychain entry.

const (
	keyringService    = "com.afterdarksys.secretserver"
	prefAPIURL        = "api_url"
	prefLegacyAPIKey  = "api_key"
	defaultAPIURL     = "https://api.secretserver.io"
	errKeychainPrefix = "OS keychain unavailable"
)

// loadAPIKey returns the stored API key for apiURL ("" when none), migrating
// any legacy plaintext preference into the keychain first. The plaintext copy
// is removed even when migration fails so it never lingers on disk.
func loadAPIKey(prefs fyne.Preferences, apiURL string) (string, error) {
	if legacy := prefs.String(prefLegacyAPIKey); legacy != "" {
		err := keyring.Set(keyringService, apiURL, legacy)
		prefs.RemoveValue(prefLegacyAPIKey)
		if err != nil {
			return "", fmt.Errorf("%s: the API key stored in plaintext settings was removed and could not be migrated; re-enter it in Settings once the keychain is available: %w", errKeychainPrefix, err)
		}
	}
	key, err := keyring.Get(keyringService, apiURL)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", errKeychainPrefix, err)
	}
	return key, nil
}

// saveAPIKey stores key for apiURL in the keychain and only then records the
// URL in preferences. A previous URL's keychain entry is removed.
func saveAPIKey(prefs fyne.Preferences, apiURL, key string) error {
	if err := keyring.Set(keyringService, apiURL, key); err != nil {
		return fmt.Errorf("%s; the API key was not saved: %w", errKeychainPrefix, err)
	}
	prefs.RemoveValue(prefLegacyAPIKey)
	if old := prefs.String(prefAPIURL); old != "" && old != apiURL {
		if err := keyring.Delete(keyringService, old); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("%s; could not remove the key stored for the previous URL: %w", errKeychainPrefix, err)
		}
	}
	prefs.SetString(prefAPIURL, apiURL)
	return nil
}
