package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	secretserver "github.com/afterdarksys/secretserver-clients/go/secretserver"
	"github.com/afterdarksys/secretserver-clients/mcp/internal/securemem"
)

const (
	maxResponseBytes = 4 << 20
	// base64 of the server's 1 MiB signing limit.
	maxSignMessageChars = 1398104
	maxTemplateBytes    = 1 << 20
	maxShortField       = 256
)

// Client holds exactly one credential source: token (an API key read from
// SECRETSERVER_TOKEN_FILE into locked memory) or cliToken (short-lived access
// tokens from the `ss login` session, SECRETSERVER_USE_CLI_LOGIN=1).
type Client struct {
	baseURL  *url.URL
	token    *securemem.Buffer
	cliToken func(context.Context) (string, error)
	http     *http.Client
}

type SigningKey struct {
	ID        string            `json:"id"`
	Label     string            `json:"label"`
	Algorithm string            `json:"algorithm"`
	Backend   string            `json:"backend"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type SignResult struct {
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	AuditID   string `json:"audit_id"`
}

func NewClient(rawURL, tokenFile string) (*Client, error) {
	baseURL, err := validateBaseURL(rawURL)
	if err != nil {
		return nil, err
	}
	token, err := readTokenFile(tokenFile)
	if err != nil {
		return nil, err
	}
	return &Client{baseURL: baseURL, token: token, http: newHTTPClient()}, nil
}

// NewCLIClient authenticates with the `ss` CLI's SSO session through
// creds, which refreshes the short-lived access token as needed. An empty
// rawURL means the API URL the CLI is logged in to. When rawURL is set and
// differs from the API URL the CLI reports, NewCLIClient refuses rather
// than send the `ss login` token to a host the session was not issued for.
// Unlike the token-file mode, the access token is held in ordinary process
// memory.
func NewCLIClient(ctx context.Context, rawURL string, creds *secretserver.CLICredentialProvider) (*Client, error) {
	cliAPIURL, err := creds.APIURL(ctx)
	if err != nil {
		return nil, err
	}
	if rawURL == "" {
		rawURL = cliAPIURL
	} else if cliAPIURL != "" && secretserver.NormalizeAPIURL(rawURL) != secretserver.NormalizeAPIURL(cliAPIURL) {
		return nil, fmt.Errorf("API URL %s does not match the `ss login` session for %s", rawURL, cliAPIURL)
	}
	baseURL, err := validateBaseURL(rawURL)
	if err != nil {
		return nil, err
	}
	return &Client{baseURL: baseURL, cliToken: creds.Token, http: newHTTPClient()}, nil
}

// newClientFromEnv builds the client from SECRETSERVER_URL plus exactly one of
// SECRETSERVER_TOKEN_FILE or SECRETSERVER_USE_CLI_LOGIN=1.
func newClientFromEnv(ctx context.Context, getenv func(string) string, creds *secretserver.CLICredentialProvider) (*Client, error) {
	rawURL, tokenFile := getenv("SECRETSERVER_URL"), getenv("SECRETSERVER_TOKEN_FILE")
	switch getenv("SECRETSERVER_USE_CLI_LOGIN") {
	case "", "0":
		return NewClient(rawURL, tokenFile)
	case "1":
		if tokenFile != "" {
			return nil, fmt.Errorf("SECRETSERVER_TOKEN_FILE and SECRETSERVER_USE_CLI_LOGIN=1 are mutually exclusive")
		}
		return NewCLIClient(ctx, rawURL, creds)
	default:
		return nil, fmt.Errorf("SECRETSERVER_USE_CLI_LOGIN must be 0 or 1")
	}
}

// newHTTPClient never follows redirects, so the bearer token cannot be replayed
// to another scheme or host, and it refuses TLS below 1.2.
func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.cliToken = nil
	if c.token == nil {
		return nil
	}
	err := c.token.Destroy()
	return err
}

func (c *Client) ListSigningKeys(ctx context.Context, backend string) ([]SigningKey, error) {
	if backend != "pkcs11" && backend != "ehsm" {
		return nil, fmt.Errorf("unsupported signing backend %q", backend)
	}
	var keys []SigningKey
	path := "/api/v1/crypto/signing-keys?" + url.Values{"backend": []string{backend}}.Encode()
	if err := c.call(ctx, http.MethodGet, path, nil, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (c *Client) Sign(ctx context.Context, backend, keyID, message, purpose string) (*SignResult, error) {
	if backend != "pkcs11" && backend != "ehsm" {
		return nil, fmt.Errorf("unsupported signing backend %q", backend)
	}
	if keyID == "" || len(keyID) > maxShortField {
		return nil, fmt.Errorf("key_id must be 1-%d characters", maxShortField)
	}
	if strings.TrimSpace(purpose) == "" || len(purpose) > maxShortField {
		return nil, fmt.Errorf("purpose must be 1-%d characters", maxShortField)
	}
	if message == "" || len(message) > maxSignMessageChars {
		return nil, fmt.Errorf("message must be base64 of 1 byte to 1 MiB")
	}
	body := map[string]string{"backend": backend, "key_id": keyID, "message": message, "purpose": purpose}
	var result SignResult
	if err := c.call(ctx, http.MethodPost, "/api/v1/crypto/sign", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) call(ctx context.Context, method, path string, body, output any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		defer wipe(encoded)
		reader = bytes.NewReader(encoded)
	}
	endpoint := *c.baseURL
	endpoint.Path = c.baseURL.Path + path
	if queryAt := strings.IndexByte(path, '?'); queryAt >= 0 {
		endpoint.Path = c.baseURL.Path + path[:queryAt]
		endpoint.RawQuery = path[queryAt+1:]
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case c.cliToken != nil:
		token, err := c.cliToken(ctx)
		if err != nil {
			return fmt.Errorf("SecretServer CLI login: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	case c.token != nil:
		if err := c.token.WithBytes(func(token []byte) error {
			req.Header.Set("Authorization", "Bearer "+string(token))
			return nil
		}); err != nil {
			return fmt.Errorf("access API token: %w", err)
		}
	default:
		return fmt.Errorf("client is closed")
	}
	resp, err := c.http.Do(req)
	req.Header.Del("Authorization")
	if err != nil {
		return fmt.Errorf("SecretServer request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read SecretServer response: %w", err)
	}
	defer wipe(data)
	if len(data) > maxResponseBytes {
		return fmt.Errorf("SecretServer response exceeds 4 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("SecretServer returned HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode SecretServer response: %w", err)
	}
	return nil
}

func validateBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid SECRETSERVER_URL")
	}
	host := u.Hostname()
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, fmt.Errorf("SECRETSERVER_URL must use HTTPS (HTTP is allowed only for loopback)")
	}
	// Keep any reverse-proxy prefix; request paths carry /api/v1 themselves.
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1")
	u.RawPath = ""
	return u, nil
}

func readTokenFile(path string) (*securemem.Buffer, error) {
	if path == "" {
		return nil, fmt.Errorf("SECRETSERVER_TOKEN_FILE is required")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect token file: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("token file must be regular and accessible only by its owner")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open token file: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, fmt.Errorf("token file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(data) > 8192 {
		wipe(data)
		return nil, fmt.Errorf("read token file")
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 16 {
		wipe(data)
		return nil, fmt.Errorf("token file is empty or invalid")
	}
	protected, err := securemem.Consume(trimmed)
	wipe(data)
	return protected, err
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func (c *Client) Render(ctx context.Context, template string) (string, error) {
	if len(template) > maxTemplateBytes {
		return "", fmt.Errorf("template exceeds 1 MiB")
	}
	var out struct {
		Rendered *string `json:"rendered"`
	}
	if err := c.call(ctx, http.MethodPost, "/api/v1/variables/resolve", map[string]string{"template": template}, &out); err != nil {
		return "", err
	}
	if out.Rendered == nil {
		return "", fmt.Errorf("invalid rendered response")
	}
	return *out.Rendered, nil
}
