package secretserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
	defaultBaseURL = "https://api.secretserver.io"
)

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
}

// Config holds client configuration
type Config struct {
	APIURL     string
	APIKey     string
	HTTPClient *http.Client
	UserAgent  string
}

// NewClient creates a new SecretServer client
func NewClient(cfg *Config) (*Client, error) {
	if cfg.APIURL == "" {
		cfg.APIURL = defaultBaseURL
	}

	baseURL, err := url.Parse(cfg.APIURL)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL: %w", err)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: defaultTimeout,
		}
	}

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

	return c, nil
}

// NewRequest creates an API request
func (c *Client) NewRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	u, err := c.baseURL.Parse(path)
	if err != nil {
		return nil, err
	}

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		if err := enc.Encode(body); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	return req, nil
}

// Do executes an API request
func (c *Client) Do(req *http.Request, v interface{}) (*Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	response := &Response{Response: resp}

	// Check for errors
	if err := checkResponse(resp); err != nil {
		return response, err
	}

	// Decode response
	if v != nil {
		if w, ok := v.(io.Writer); ok {
			_, err = io.Copy(w, resp.Body)
		} else {
			err = json.NewDecoder(resp.Body).Decode(v)
		}
	}

	return response, err
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

func checkResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}

	errorResponse := &ErrorResponse{Response: r}
	data, err := io.ReadAll(r.Body)
	if err == nil && data != nil {
		json.Unmarshal(data, errorResponse)
	}

	if errorResponse.Message == "" {
		errorResponse.Message = http.StatusText(r.StatusCode)
	}

	return errorResponse
}

// Common types

// Secret represents a secret
type Secret struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Data        map[string]string `json:"data,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Version     int               `json:"version"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

// Certificate represents a TLS certificate
type Certificate struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	CommonName     string   `json:"common_name"`
	DNSNames       []string `json:"dns_names,omitempty"`
	IssuerType     string   `json:"issuer_type"`
	SerialNumber   string   `json:"serial_number,omitempty"`
	Status         string   `json:"status"`
	NotBefore      string   `json:"not_before,omitempty"`
	NotAfter       string   `json:"not_after,omitempty"`
	AutoRenew      bool     `json:"auto_renew"`
	CertificatePEM string   `json:"certificate_pem,omitempty"`
	ChainPEM       string   `json:"chain_pem,omitempty"`
	PrivateKeyPEM  string   `json:"private_key_pem,omitempty"`
	CreatedAt      string   `json:"created_at"`
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
