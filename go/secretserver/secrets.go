package secretserver

import (
	"context"
	"fmt"
	"net/url"
)

// SecretsService handles secret operations
type SecretsService struct {
	client *Client
}

// SecretCreateRequest represents a secret creation request
type SecretCreateRequest struct {
	ContainerID *string           `json:"container_id,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Data        map[string]string `json:"data"`
	Tags        []string          `json:"tags,omitempty"`
}

// SecretUpdateRequest represents a secret update request.
//
// The server's PUT is a full replace of data, description, tags and
// container. SecretsService.Update therefore reads the current secret and
// keeps its ContainerID, Description and Tags when the caller leaves them
// nil/empty. Data is required and replaces all existing fields.
type SecretUpdateRequest struct {
	ContainerID *string           `json:"container_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Data        map[string]string `json:"data"`
	Tags        []string          `json:"tags"`
}

// SecretListOptions for listing secrets. Tags is applied client-side (the
// server does not filter by tag): only secrets carrying every listed tag are
// returned, so Limit/Offset count secrets before tag filtering.
type SecretListOptions struct {
	Tags   []string
	Limit  int // 1..1000; 0 uses the server default (100)
	Offset int
}

// SecretGetOptions for getting a secret. The server always returns the
// current version; Version must be empty. Read history with
// Call(ctx, "GET", "/secret/<id>/history", nil, &out).
type SecretGetOptions struct {
	Version string
}

// List returns secret metadata (no data values).
func (s *SecretsService) List(ctx context.Context, opts *SecretListOptions) ([]*Secret, error) {
	path := "/api/v1/secrets"

	if opts != nil {
		if opts.Limit != 0 && (opts.Limit < 1 || opts.Limit > 1000) {
			return nil, fmt.Errorf("limit must be between 1 and 1000")
		}
		if opts.Offset < 0 {
			return nil, fmt.Errorf("offset must not be negative")
		}
		params := url.Values{}
		if opts.Limit > 0 {
			params.Add("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Offset > 0 {
			params.Add("offset", fmt.Sprintf("%d", opts.Offset))
		}
		if len(params) > 0 {
			path = fmt.Sprintf("%s?%s", path, params.Encode())
		}
	}

	req, err := s.client.NewRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Secrets []*Secret `json:"secrets"`
	}
	_, err = s.client.Do(req, &response)
	if err != nil {
		return nil, err
	}

	if opts == nil || len(opts.Tags) == 0 {
		return response.Secrets, nil
	}
	filtered := make([]*Secret, 0, len(response.Secrets))
	for _, secret := range response.Secrets {
		if hasAllTags(secret.Tags, opts.Tags) {
			filtered = append(filtered, secret)
		}
	}
	return filtered, nil
}

func hasAllTags(have, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Get retrieves the current version of a secret by name.
func (s *SecretsService) Get(ctx context.Context, name string, opts *SecretGetOptions) (*Secret, error) {
	if opts != nil && opts.Version != "" {
		return nil, fmt.Errorf("secret versions are not selectable here; read history via Call on /secret/<id>/history")
	}
	p, err := seg(name)
	if err != nil {
		return nil, err
	}
	path := "/api/v1/secrets/" + p

	req, err := s.client.NewRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var secret Secret
	_, err = s.client.Do(req, &secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

// Create creates a new secret
func (s *SecretsService) Create(ctx context.Context, createReq *SecretCreateRequest) (*Secret, error) {
	req, err := s.client.NewRequest(ctx, "POST", "/api/v1/secrets", createReq)
	if err != nil {
		return nil, err
	}

	var secret Secret
	_, err = s.client.Do(req, &secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

// Update replaces a secret's data using read-merge-write: the current
// secret is fetched first and its ContainerID, Description and Tags are kept
// unless the request sets them (non-nil ContainerID/Tags, non-empty
// Description). Pass an empty non-nil Tags slice to clear tags. The request is
// not modified.
func (s *SecretsService) Update(ctx context.Context, name string, updateReq *SecretUpdateRequest) (*Secret, error) {
	if updateReq == nil {
		return nil, fmt.Errorf("update request is required")
	}
	if len(updateReq.Data) == 0 {
		return nil, fmt.Errorf("update data must not be empty")
	}
	if updateReq.Name != "" && updateReq.Name != name {
		return nil, fmt.Errorf("secret name is immutable")
	}
	p, err := seg(name)
	if err != nil {
		return nil, err
	}

	current, err := s.Get(ctx, name, nil)
	if err != nil {
		return nil, err
	}
	merged := *updateReq
	merged.Name = name
	if merged.ContainerID == nil {
		merged.ContainerID = current.ContainerID
	}
	if merged.Description == "" {
		merged.Description = current.Description
	}
	if merged.Tags == nil {
		merged.Tags = current.Tags
	}

	req, err := s.client.NewRequest(ctx, "PUT", "/api/v1/secrets/"+p, &merged)
	if err != nil {
		return nil, err
	}

	var secret Secret
	_, err = s.client.Do(req, &secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

// Delete deletes a secret
func (s *SecretsService) Delete(ctx context.Context, name string) error {
	p, err := seg(name)
	if err != nil {
		return err
	}

	req, err := s.client.NewRequest(ctx, "DELETE", "/api/v1/secrets/"+p, nil)
	if err != nil {
		return err
	}

	_, err = s.client.Do(req, nil)
	return err
}

// Placeholder service implementations
type CertificatesService struct{ client *Client }
type GPGKeysService struct{ client *Client }
type SSHKeysService struct{ client *Client }
type PasswordsService struct{ client *Client }
type TokensService struct{ client *Client }
type OpenSSLKeysService struct{ client *Client }
type NTLMHashesService struct{ client *Client }
