package secretserver

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// CryptoBackend describes a configured cryptographic backend without exposing
// credentials or private key material.
type CryptoBackend struct {
	Backend      string                 `json:"backend"`
	Name         string                 `json:"name"`
	Healthy      bool                   `json:"healthy"`
	Capabilities map[string]interface{} `json:"capabilities"`
}

// SigningKey is operation-only key metadata.
type SigningKey struct {
	ID        string            `json:"id"`
	Label     string            `json:"label"`
	Algorithm string            `json:"algorithm"`
	Backend   string            `json:"backend"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type SignRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Message string `json:"message"` // base64, maximum 1 MiB decoded
	Purpose string `json:"purpose"`
}

type SignResult struct {
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	AuditID   string `json:"audit_id"`
}

type CryptoService struct{ client *Client }

func (s *CryptoService) Backends(ctx context.Context) ([]CryptoBackend, error) {
	var result []CryptoBackend
	_, err := s.client.Call(ctx, http.MethodGet, "/crypto/backends", nil, &result)
	return result, err
}

func (s *CryptoService) SigningKeys(ctx context.Context, backend string) ([]SigningKey, error) {
	path := "/crypto/signing-keys?" + url.Values{"backend": []string{backend}}.Encode()
	var result []SigningKey
	_, err := s.client.Call(ctx, http.MethodGet, path, nil, &result)
	return result, err
}

func (s *CryptoService) Sign(ctx context.Context, input *SignRequest) (*SignResult, error) {
	if input == nil {
		return nil, fmt.Errorf("sign request is required")
	}
	var result SignResult
	_, err := s.client.Call(ctx, http.MethodPost, "/crypto/sign", input, &result)
	return &result, err
}

type JKSKeystore struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	StoreType  string   `json:"store_type"`
	EntryCount int      `json:"entry_count,omitempty"`
	Notes      string   `json:"notes,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	CreatedAt  string   `json:"created_at,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
}

type JKSEntry struct {
	ID          string `json:"id"`
	KeystoreID  string `json:"keystore_id"`
	Alias       string `json:"alias"`
	EntryType   string `json:"entry_type"`
	Subject     string `json:"subject,omitempty"`
	NotBefore   string `json:"not_before,omitempty"`
	NotAfter    string `json:"not_after,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type CreateJKSKeystoreRequest struct {
	ContainerID string   `json:"container_id,omitempty"`
	Name        string   `json:"name"`
	StoreType   string   `json:"store_type,omitempty"`
	JKS         string   `json:"jks,omitempty"`
	Password    string   `json:"password,omitempty"`
	Notes       string   `json:"notes,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type CreateJKSEntryRequest struct {
	Alias       string `json:"alias"`
	EntryType   string `json:"entry_type"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key,omitempty"`
	CertChain   string `json:"cert_chain,omitempty"`
	KeyPassword string `json:"key_password,omitempty"`
}

type JKSExport struct {
	JKS      string `json:"jks"`
	Format   string `json:"format,omitempty"`
	Filename string `json:"filename,omitempty"`
}

type JKSService struct{ client *Client }

func (s *JKSService) List(ctx context.Context) ([]JKSKeystore, error) {
	var result []JKSKeystore
	_, err := s.client.Call(ctx, http.MethodGet, "/jks-keystores", nil, &result)
	return result, err
}

func (s *JKSService) Get(ctx context.Context, id string) (*JKSKeystore, error) {
	var result JKSKeystore
	_, err := s.client.Call(ctx, http.MethodGet, "/jks-keystores/"+url.PathEscape(id), nil, &result)
	return &result, err
}

func (s *JKSService) Create(ctx context.Context, input *CreateJKSKeystoreRequest) (*JKSKeystore, error) {
	if input == nil {
		return nil, fmt.Errorf("create JKS request is required")
	}
	var result JKSKeystore
	_, err := s.client.Call(ctx, http.MethodPost, "/jks-keystores", input, &result)
	return &result, err
}

func (s *JKSService) Update(ctx context.Context, id string, input interface{}) (map[string]string, error) {
	var result map[string]string
	_, err := s.client.Call(ctx, http.MethodPut, "/jks-keystores/"+url.PathEscape(id), input, &result)
	return result, err
}

func (s *JKSService) Delete(ctx context.Context, id string) error {
	_, err := s.client.Call(ctx, http.MethodDelete, "/jks-keystores/"+url.PathEscape(id), nil, nil)
	return err
}

func (s *JKSService) Export(ctx context.Context, id string) (*JKSExport, error) {
	var result JKSExport
	_, err := s.client.Call(ctx, http.MethodGet, "/jks-keystores/"+url.PathEscape(id)+"/export", nil, &result)
	return &result, err
}

func (s *JKSService) Entries(ctx context.Context, id string) ([]JKSEntry, error) {
	var result []JKSEntry
	_, err := s.client.Call(ctx, http.MethodGet, "/jks-keystores/"+url.PathEscape(id)+"/entries", nil, &result)
	return result, err
}

func (s *JKSService) CreateEntry(ctx context.Context, id string, input *CreateJKSEntryRequest) (*JKSEntry, error) {
	if input == nil {
		return nil, fmt.Errorf("create JKS entry request is required")
	}
	var result JKSEntry
	_, err := s.client.Call(ctx, http.MethodPost, "/jks-keystores/"+url.PathEscape(id)+"/entries", input, &result)
	return &result, err
}

func (s *JKSService) DeleteEntry(ctx context.Context, id, alias string) error {
	path := "/jks-keystores/" + url.PathEscape(id) + "/entries/" + url.PathEscape(alias)
	_, err := s.client.Call(ctx, http.MethodDelete, path, nil, nil)
	return err
}
