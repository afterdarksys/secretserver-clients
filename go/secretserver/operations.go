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
	path := "/crypto/signing-keys"
	if backend != "" {
		path += "?" + url.Values{"backend": []string{backend}}.Encode()
	}
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
	ID          string   `json:"id"`
	ContainerID *string  `json:"container_id,omitempty"`
	Name        string   `json:"name"`
	StoreType   string   `json:"store_type"`
	EntryCount  int      `json:"entry_count,omitempty"`
	Notes       string   `json:"notes,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
	// ETag is the entity tag from the Get response header; pass it as
	// JKSKeystoreUpdate.IfMatch for an optimistic-concurrency update.
	ETag string `json:"-"`
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

// JKSKeystoreUpdate is a partial update (PUT /jks-keystores/:id).
//
// Convention: a nil field is OMITTED and the server keeps the stored value;
// to CLEAR a field, name it in Clear and it is sent as JSON null. Clearable
// fields are "notes", "tags" and "container_id". A field cannot be both set
// and cleared.
//
// Name, when set, must not be empty. Password alone rotates the stored
// keystore password; JKS (base64 keystore bytes, raw keystores only) replaces
// the keystore and requires Password. IfMatch, when set, is sent as the
// If-Match header (an ETag from Get or Update, or "*"); on a mismatch Update
// returns *ConflictError carrying the current ETag.
type JKSKeystoreUpdate struct {
	Name        *string
	ContainerID *string
	Notes       *string
	Tags        *[]string
	Password    *string
	JKS         *string
	Clear       []string
	IfMatch     string
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
	p, err := seg(id)
	if err != nil {
		return nil, err
	}
	var result JKSKeystore
	resp, err := s.client.Call(ctx, http.MethodGet, "/jks-keystores/"+p, nil, &result)
	if err != nil {
		return nil, err
	}
	result.ETag = resp.Header.Get("ETag")
	return &result, nil
}

func (s *JKSService) Create(ctx context.Context, input *CreateJKSKeystoreRequest) (*JKSKeystore, error) {
	if input == nil {
		return nil, fmt.Errorf("create JKS request is required")
	}
	var result JKSKeystore
	_, err := s.client.Call(ctx, http.MethodPost, "/jks-keystores", input, &result)
	return &result, err
}

// Update applies a partial update and returns the keystore's new ETag.
// Only the fields set in input are sent; see JKSKeystoreUpdate.
func (s *JKSService) Update(ctx context.Context, id string, input *JKSKeystoreUpdate) (string, error) {
	if input == nil {
		return "", fmt.Errorf("JKS keystore update is required")
	}
	p, err := seg(id)
	if err != nil {
		return "", err
	}
	body := map[string]interface{}{}
	if input.Name != nil {
		if *input.Name == "" {
			return "", fmt.Errorf("JKS keystore name must not be empty")
		}
		body["name"] = *input.Name
	}
	if input.ContainerID != nil {
		if *input.ContainerID == "" {
			return "", fmt.Errorf("container_id must not be empty; use Clear to remove the container")
		}
		body["container_id"] = *input.ContainerID
	}
	if input.Notes != nil {
		body["notes"] = *input.Notes
	}
	if input.Tags != nil {
		tags := *input.Tags
		if tags == nil {
			tags = []string{}
		}
		body["tags"] = tags
	}
	if input.JKS != nil {
		if *input.JKS == "" {
			return "", fmt.Errorf("JKS keystore data must not be empty")
		}
		if input.Password == nil {
			return "", fmt.Errorf("password is required with jks")
		}
		body["jks"] = *input.JKS
	}
	if input.Password != nil {
		if *input.Password == "" {
			return "", fmt.Errorf("JKS keystore password must not be empty")
		}
		body["password"] = *input.Password
	}
	if err := patchClear(body, input.Clear, "notes", "tags", "container_id"); err != nil {
		return "", err
	}
	if len(body) == 0 {
		return "", fmt.Errorf("update must set or clear at least one field")
	}
	resp, err := s.client.callWithIfMatch(ctx, http.MethodPut, "/jks-keystores/"+p, input.IfMatch, body, nil)
	if err != nil {
		return "", err
	}
	return resp.Header.Get("ETag"), nil
}

func (s *JKSService) Delete(ctx context.Context, id string) error {
	p, err := seg(id)
	if err != nil {
		return err
	}
	_, err = s.client.Call(ctx, http.MethodDelete, "/jks-keystores/"+p, nil, nil)
	return err
}

func (s *JKSService) Export(ctx context.Context, id string) (*JKSExport, error) {
	p, err := seg(id)
	if err != nil {
		return nil, err
	}
	var result JKSExport
	_, err = s.client.Call(ctx, http.MethodGet, "/jks-keystores/"+p+"/export", nil, &result)
	return &result, err
}

func (s *JKSService) Entries(ctx context.Context, id string) ([]JKSEntry, error) {
	p, err := seg(id)
	if err != nil {
		return nil, err
	}
	var result []JKSEntry
	_, err = s.client.Call(ctx, http.MethodGet, "/jks-keystores/"+p+"/entries", nil, &result)
	return result, err
}

func (s *JKSService) CreateEntry(ctx context.Context, id string, input *CreateJKSEntryRequest) (*JKSEntry, error) {
	if input == nil {
		return nil, fmt.Errorf("create JKS entry request is required")
	}
	p, err := seg(id)
	if err != nil {
		return nil, err
	}
	var result JKSEntry
	_, err = s.client.Call(ctx, http.MethodPost, "/jks-keystores/"+p+"/entries", input, &result)
	if err != nil {
		return nil, err
	}
	result.KeystoreID = id
	return &result, nil
}

func (s *JKSService) DeleteEntry(ctx context.Context, id, alias string) error {
	p, err := seg(id)
	if err != nil {
		return err
	}
	a, err := seg(alias)
	if err != nil {
		return err
	}
	_, err = s.client.Call(ctx, http.MethodDelete, "/jks-keystores/"+p+"/entries/"+a, nil, nil)
	return err
}
