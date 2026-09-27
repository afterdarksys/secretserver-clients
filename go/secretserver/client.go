package secretserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
	defaultBaseURL = "https://api.secretserver.io"

	// maxJSONResponseBytes caps decoded JSON responses.
	maxJSONResponseBytes = 4 << 20
	// maxDownloadBytes caps raw downloads streamed to an io.Writer.
	maxDownloadBytes = 16 << 20
)

// ErrResponseTooLarge is returned when a response body exceeds the client cap.
var ErrResponseTooLarge = errors.New("SecretServer response exceeds size limit")

// Client is the SecretServer API client
type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
	userAgent  string

	// Service clients
	Secrets      *SecretsService
	Certificates *CertificatesService
	GPGKeys      *GPGKeysService
	SSHKeys      *SSHKeysService
	Passwords    *PasswordsService
	Tokens       *TokensService
	OpenSSLKeys  *OpenSSLKeysService
	NTLMHashes   *NTLMHashesService
	Transform    *TransformService
	Intelligence *IntelligenceService
	Extraction   *ExtractionService
	LDAP         *LDAPService
	Mock         *MockService
	Integrations *IntegrationsService
	Crypto       *CryptoService
	JKS          *JKSService
}

// Config holds client configuration.
//
// APIURL must use https; plain http is accepted only for loopback hosts
// (localhost, 127.0.0.1, ::1).
//
// HTTPClient is optional. When set, its Transport must be nil (meaning
// http.DefaultTransport) or an *http.Transport; any other RoundTripper,
// including wrappers, is refused because its TLS behaviour cannot be
// inspected. The transport is refused if TLSClientConfig.InsecureSkipVerify
// is set or if DialTLS/DialTLSContext is set. NewClient clones the transport,
// so later changes to it (or to http.DefaultTransport) do not affect the
// client, and raises TLS MinVersion to 1.2. To trust a private CA, pass an
// *http.Transport whose TLSClientConfig.RootCAs contains it. Redirects are
// never followed.
type Config struct {
	APIURL     string
	APIKey     string
	HTTPClient *http.Client
	UserAgent  string
}

// NewClient creates a new SecretServer client
func NewClient(cfg *Config) (*Client, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.APIURL == "" {
		cfg.APIURL = defaultBaseURL
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	baseURL, err := ValidateAPIURL(cfg.APIURL)
	if err != nil {
		return nil, err
	}
	baseURL.Path = strings.TrimSuffix(strings.TrimRight(baseURL.Path, "/"), "/api/v1")

	var httpClient *http.Client
	if cfg.HTTPClient == nil {
		transport, err := safeTransport(http.DefaultTransport)
		if err != nil {
			return nil, err
		}
		// The default client never inherits TLS settings from the shared
		// transport; only the minimum version is set.
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		httpClient = &http.Client{Timeout: defaultTimeout, Transport: transport}
	} else {
		rt := cfg.HTTPClient.Transport
		if rt == nil {
			rt = http.DefaultTransport
		}
		transport, err := safeTransport(rt)
		if err != nil {
			return nil, err
		}
		copied := *cfg.HTTPClient
		copied.Transport = transport
		httpClient = &copied
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	c := &Client{
		baseURL:    baseURL,
		apiKey:     cfg.APIKey,
		httpClient: httpClient,
		userAgent:  cfg.UserAgent,
	}

	// Initialize service clients
	c.Secrets = &SecretsService{client: c}
	c.Certificates = &CertificatesService{client: c}
	c.GPGKeys = &GPGKeysService{client: c}
	c.SSHKeys = &SSHKeysService{client: c}
	c.Passwords = &PasswordsService{client: c}
	c.Tokens = &TokensService{client: c}
	c.OpenSSLKeys = &OpenSSLKeysService{client: c}
	c.NTLMHashes = &NTLMHashesService{client: c}
	c.Transform = &TransformService{client: c}
	c.Intelligence = &IntelligenceService{client: c}
	c.Extraction = &ExtractionService{client: c}
	c.LDAP = &LDAPService{client: c}
	c.Mock = &MockService{client: c}
	c.Integrations = &IntegrationsService{client: c}
	c.Crypto = &CryptoService{client: c}
	c.JKS = &JKSService{client: c}

	return c, nil
}

// safeTransport returns a private clone of rt with TLS MinVersion of at least
// 1.2. It refuses any RoundTripper that is not an *http.Transport (a wrapper
// could disable verification out of sight), a transport that skips
// certificate verification, and one with a custom TLS dialer.
func safeTransport(rt http.RoundTripper) (*http.Transport, error) {
	t, ok := rt.(*http.Transport)
	if !ok || t == nil {
		return nil, fmt.Errorf("unsupported HTTP transport: HTTPClient.Transport must be nil or an *http.Transport")
	}
	if t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("TLS certificate verification cannot be disabled")
	}
	//lint:ignore SA1019 the deprecated DialTLS hook still bypasses TLSClientConfig and must be refused
	if t.DialTLS != nil || t.DialTLSContext != nil {
		return nil, fmt.Errorf("unsupported HTTP transport: custom TLS dialers are not allowed")
	}
	clone := t.Clone()
	if clone.TLSClientConfig == nil {
		clone.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else if clone.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		clone.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	return clone, nil
}

// seg percent-encodes one caller-supplied path segment. Empty, "." and ".."
// are rejected because escaping leaves them unchanged and they would address
// a different resource.
func seg(s string) (string, error) {
	switch s {
	case "":
		return "", fmt.Errorf("path segment must not be empty")
	case ".", "..":
		return "", fmt.Errorf("path segment must not be %q", s)
	}
	return url.PathEscape(s), nil
}

// ValidateAPIURL parses and checks a SecretServer base URL: https is required
// unless the host is loopback, and embedded credentials are rejected.
func ValidateAPIURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL")
	}
	if u.User != nil {
		return nil, fmt.Errorf("invalid API URL: credentials in the URL are not allowed")
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid API URL: host is required")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		switch strings.ToLower(u.Hostname()) {
		case "localhost", "127.0.0.1", "::1":
		default:
			return nil, fmt.Errorf("invalid API URL: https is required for non-loopback hosts")
		}
	default:
		return nil, fmt.Errorf("invalid API URL: scheme must be https")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid API URL: query and fragment are not allowed")
	}
	return u, nil
}

// NewRequest creates a JSON API request
func (c *Client) NewRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	var buf io.Reader
	if body != nil {
		b := new(bytes.Buffer)
		if err := json.NewEncoder(b).Encode(body); err != nil {
			return nil, err
		}
		buf = b
	}
	return c.newRequest(ctx, method, path, buf, "application/json")
}

// newRequest builds an authenticated request with an explicit body content type.
func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Request, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "/api/v1" {
		path = ""
	} else if !strings.HasPrefix(path, "/api/v1/") {
		path = "/api/v1" + path
	}
	ref, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + ref.Path
	u.RawPath = strings.TrimRight(c.baseURL.EscapedPath(), "/") + ref.EscapedPath()
	if u.RawPath == u.Path {
		u.RawPath = ""
	}
	u.RawQuery = ref.RawQuery

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	return req, nil
}

// Do executes an API request. When v is an io.Writer the raw body (at most
// 16 MiB) is read completely into memory and only then written to v, so an
// oversized or interrupted download writes nothing; otherwise the body (at
// most 4 MiB) is decoded as JSON into v. Oversized or malformed responses
// return an error that never includes the response body.
func (c *Client) Do(req *http.Request, v interface{}) (*Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Strip the query string: it can carry caller-supplied values such as
		// export passwords.
		var ue *url.Error
		if errors.As(err, &ue) && req.URL != nil {
			redacted := *req.URL
			redacted.RawQuery = ""
			ue.URL = redacted.String()
		}
		return nil, err
	}
	defer resp.Body.Close()

	response := &Response{Response: resp}

	// Check for errors
	if err := checkResponse(resp); err != nil {
		return response, err
	}

	if v == nil {
		return response, nil
	}
	if w, ok := v.(io.Writer); ok {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes+1))
		if err != nil {
			return response, err
		}
		if len(body) > maxDownloadBytes {
			return response, ErrResponseTooLarge
		}
		if _, err := w.Write(body); err != nil {
			return response, err
		}
		return response, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONResponseBytes+1))
	if err != nil {
		return response, err
	}
	if len(body) > maxJSONResponseBytes {
		return response, ErrResponseTooLarge
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return response, nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return response, fmt.Errorf("SecretServer returned an invalid JSON response (HTTP %d)", resp.StatusCode)
	}
	return response, nil
}

// uploadFile POSTs a multipart/form-data body with r as the "file" part plus
// the given form fields, decoding the JSON response into v.
func (c *Client) uploadFile(ctx context.Context, path, filename string, r io.Reader, fields map[string]string, v interface{}) error {
	if r == nil {
		return fmt.Errorf("file reader is required")
	}
	filename = filepath.Base(filename)
	if filename == "" || filename == "." || filename == string(filepath.Separator) {
		return fmt.Errorf("file name is required")
	}
	body := new(bytes.Buffer)
	mw := multipart.NewWriter(body)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, r); err != nil {
		return err
	}
	for k, val := range fields {
		if err := mw.WriteField(k, val); err != nil {
			return err
		}
	}
	if err := mw.Close(); err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPost, path, body, mw.FormDataContentType())
	if err != nil {
		return err
	}
	_, err = c.Do(req, v)
	return err
}

// Call invokes any REST endpoint. Path may be relative to /api/v1 or include
// that prefix, providing forward-compatible access before a typed helper exists.
func (c *Client) Call(ctx context.Context, method, path string, body, output interface{}) (*Response, error) {
	req, err := c.NewRequest(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	return c.Do(req, output)
}

// Response wraps http.Response
type Response struct {
	*http.Response
}

// ErrorResponse represents an API error
type ErrorResponse struct {
	Response *http.Response `json:"-"`
	Message  string         `json:"error"`
	Code     string         `json:"code"`
	Details  []ErrorDetail  `json:"details,omitempty"`
}

// ErrorDetail provides additional error information
type ErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *ErrorResponse) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Message
}

// ConflictError is returned for HTTP 409, for example when an update's
// If-Match precondition no longer matches. ETag is the resource's current
// entity tag from the response; re-read the resource and retry with it.
// errors.As also matches the wrapped *ErrorResponse.
type ConflictError struct {
	*ErrorResponse
	ETag string
}

// Unwrap exposes the underlying *ErrorResponse.
func (e *ConflictError) Unwrap() error { return e.ErrorResponse }

func checkResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}

	errorResponse := &ErrorResponse{Response: r, Message: fmt.Sprintf("SecretServer request failed (HTTP %d)", r.StatusCode)}
	if r.StatusCode == http.StatusConflict {
		return &ConflictError{ErrorResponse: errorResponse, ETag: r.Header.Get("ETag")}
	}

	return errorResponse
}

// callWithIfMatch is Call with an optional If-Match header.
func (c *Client) callWithIfMatch(ctx context.Context, method, path, ifMatch string, body, output interface{}) (*Response, error) {
	req, err := c.NewRequest(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	return c.Do(req, output)
}

// patchClear adds an explicit JSON null to body for every field in clear.
// Only the names in allowed may be cleared, and a field cannot be both set
// and cleared.
func patchClear(body map[string]interface{}, clear []string, allowed ...string) error {
	for _, field := range clear {
		ok := false
		for _, a := range allowed {
			if field == a {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("field %q cannot be cleared; allowed: %s", field, strings.Join(allowed, ", "))
		}
		if v, set := body[field]; set && v != nil {
			return fmt.Errorf("field %q is both set and cleared", field)
		}
		body[field] = nil
	}
	return nil
}

// Common types

// Secret represents a secret
type Secret struct {
	ContainerID *string           `json:"container_id,omitempty"`
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Data        map[string]string `json:"data,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Version     int               `json:"version"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
	// ETag is the entity tag from the response header of Get or Update. Pass
	// it as SecretUpdateRequest.IfMatch for an optimistic-concurrency update.
	ETag string `json:"-"`
}

// Certificate represents TLS certificate metadata. CertificatePEM is only
// populated by CertificatesService.GetWithPEM; private keys are never part of
// this type (use CertificatesService.Download with format "key").
type Certificate struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	CommonName      string   `json:"common_name"`
	DNSNames        []string `json:"dns_names,omitempty"`
	IssuerType      string   `json:"issuer_type"`
	IssuerName      string   `json:"issuer_name,omitempty"`
	SerialNumber    string   `json:"serial_number,omitempty"`
	Status          string   `json:"status"`
	NotBefore       string   `json:"not_before,omitempty"`
	NotAfter        string   `json:"not_after,omitempty"`
	DaysUntilExpiry int      `json:"days_until_expiry,omitempty"`
	AutoRenew       bool     `json:"auto_renew"`
	RenewBefore     int      `json:"renew_before"`
	Fingerprint     string   `json:"fingerprint,omitempty"`
	CertificatePEM  string   `json:"certificate_pem,omitempty"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
}

// GPGKey represents a GPG keypair
type GPGKey struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	KeyID       string `json:"key_id"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Revoked     bool   `json:"revoked"`
	CreatedAt   string `json:"created_at"`
}

// SSHKey represents an SSH keypair
type SSHKey struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Comment     string `json:"comment,omitempty"`
	KeyType     string `json:"key_type"`
	Bits        int    `json:"bits,omitempty"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// Password represents a stored password
type Password struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Username    string   `json:"username,omitempty"`
	URL         string   `json:"url,omitempty"`
	Value       string   `json:"value,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// APIToken represents a stored API token
type APIToken struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Service     string   `json:"service,omitempty"`
	TokenType   string   `json:"token_type,omitempty"`
	Token       string   `json:"token,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}
