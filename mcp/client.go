package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/secretserver-clients/mcp/internal/securemem"
)

const maxResponseBytes = 4 << 20

type Client struct {
	baseURL *url.URL
	token   *securemem.Buffer
	http    *http.Client
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
	return &Client{baseURL: baseURL, token: token, http: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (c *Client) Close() error {
	if c == nil || c.token == nil {
		return nil
	}
	err := c.token.Destroy()
	c.token = nil
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
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: path})
	if queryAt := strings.IndexByte(path, '?'); queryAt >= 0 {
		endpoint.Path = path[:queryAt]
		endpoint.RawQuery = path[queryAt+1:]
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token == nil {
		return fmt.Errorf("client is closed")
	}
	if err := c.token.WithBytes(func(token []byte) error {
		req.Header.Set("Authorization", "Bearer "+string(token))
		return nil
	}); err != nil {
		return fmt.Errorf("access API token: %w", err)
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
	u.Path = strings.TrimRight(u.Path, "/") + "/"
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
