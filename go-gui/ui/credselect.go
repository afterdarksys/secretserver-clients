package ui

import (
	"context"
	"errors"
	"fmt"

	"fyne.io/fyne/v2"
	"github.com/afterdarksys/secretserver-clients/go/secretserver"
)

// Threats: the "ss login" mode builds the client from the CLI's SSO session
// (secretserver.CLICredentials); no token is stored in preferences or the
// keychain, only the chosen mode. The session token is never shown: the UI
// gets the API URL and tenant only. It refuses to send the session token to
// an API URL other than the one `ss login` recorded. It does not protect
// against a malicious `ss` binary on PATH / in SS_CLI_PATH.

const (
	prefAuthMode     = "auth_mode"
	authModeAPIKey   = "api_key"
	authModeCLILogin = "cli_login"
	guiUserAgent     = "SecretServer-GUI/1.0"
)

// authMode returns the stored credential choice (API key by default).
func authMode(prefs fyne.Preferences) string {
	if prefs.String(prefAuthMode) == authModeCLILogin {
		return authModeCLILogin
	}
	return authModeAPIKey
}

// buildClient returns a client for the stored credential choice and a
// human-readable account line (never a token). A nil client with a nil
// error means nothing is configured yet.
func buildClient(ctx context.Context, prefs fyne.Preferences) (*secretserver.Client, string, error) {
	if authMode(prefs) == authModeCLILogin {
		return buildCLIClient(ctx, prefs.String(prefAPIURL))
	}

	apiURL := prefs.StringWithFallback(prefAPIURL, defaultAPIURL)
	apiKey, err := loadAPIKey(prefs, apiURL)
	if err != nil || apiKey == "" {
		return nil, "", err
	}
	client, err := secretserver.NewClient(&secretserver.Config{
		APIURL:    apiURL,
		APIKey:    apiKey,
		UserAgent: guiUserAgent,
	})
	if err != nil {
		return nil, "", err
	}
	return client, "API key (OS keychain) for " + apiURL, nil
}

// buildCLIClient authenticates with the `ss login` session. apiURL may be
// empty, meaning the URL recorded by `ss login`; otherwise it must match it.
func buildCLIClient(ctx context.Context, apiURL string) (*secretserver.Client, string, error) {
	p := secretserver.CLICredentials()
	cliURL, err := p.APIURL(ctx)
	if errors.Is(err, secretserver.ErrCLINotLoggedIn) {
		return nil, "", errors.New("not signed in: run `ss login` in a terminal, then reload Settings")
	}
	if err != nil {
		return nil, "", err
	}
	tenant, err := p.TenantID(ctx)
	if err != nil {
		return nil, "", err
	}
	if apiURL == "" {
		apiURL = cliURL
	}
	if apiURL == "" {
		return nil, "", errors.New("`ss login` did not report an API URL; set one in Settings")
	}
	if cliURL != "" && secretserver.NormalizeAPIURL(apiURL) != secretserver.NormalizeAPIURL(cliURL) {
		return nil, "", fmt.Errorf("API URL %s does not match the `ss login` session for %s; clear the API URL in Settings or run `ss login` against %s", apiURL, cliURL, apiURL)
	}
	client, err := secretserver.NewClient(&secretserver.Config{
		APIURL:        apiURL,
		TokenProvider: p.Token,
		UserAgent:     guiUserAgent,
	})
	if err != nil {
		return nil, "", err
	}
	account := "ss login session for " + apiURL
	if tenant != "" {
		account += " (tenant " + tenant + ")"
	}
	return client, account, nil
}
