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
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Data        map[string]string `json:"data"`
	Tags        []string          `json:"tags,omitempty"`
}

// SecretUpdateRequest represents a secret update request
type SecretUpdateRequest struct {
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Data        map[string]string `json:"data,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

// SecretListOptions for listing secrets
type SecretListOptions struct {
	Tags   []string
	Limit  int
	Offset int
}

// SecretGetOptions for getting a secret
type SecretGetOptions struct {
	Version string
}

// List returns all secrets
func (s *SecretsService) List(ctx context.Context, opts *SecretListOptions) ([]*Secret, error) {
	path := "/api/v1/secrets"

	if opts != nil {
		params := url.Values{}
		for _, tag := range opts.Tags {
			params.Add("tags", tag)
		}
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

	return response.Secrets, nil
}

// Get retrieves a secret by name
func (s *SecretsService) Get(ctx context.Context, name string, opts *SecretGetOptions) (*Secret, error) {
	path := fmt.Sprintf("/api/v1/secrets/%s", name)

	if opts != nil && opts.Version != "" {
		path = fmt.Sprintf("%s?version=%s", path, opts.Version)
	}

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

// Update updates an existing secret
func (s *SecretsService) Update(ctx context.Context, name string, updateReq *SecretUpdateRequest) (*Secret, error) {
	path := fmt.Sprintf("/api/v1/secrets/%s", name)

	req, err := s.client.NewRequest(ctx, "PUT", path, updateReq)
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
	path := fmt.Sprintf("/api/v1/secrets/%s", name)

	req, err := s.client.NewRequest(ctx, "DELETE", path, nil)
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
