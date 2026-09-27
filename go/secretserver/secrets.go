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

// SecretUpdateRequest is a partial update (PUT /secrets/:name).
//
// Convention: a nil field is OMITTED and the server keeps the stored value;
// to CLEAR a field, name it in Clear and it is sent as JSON null. Clearable
// fields are "description", "tags" and "container_id". A field cannot be both
// set and cleared. A pointer to "" sends an empty description; a pointer to an
// empty slice sends [] (no tags).
//
// Data, when non-nil, must be non-empty and replaces the whole value (the
// previous value is kept in history when history is enabled); nil Data leaves
// the value untouched, so metadata-only updates never read or rewrite it.
//
// IfMatch, when set, is sent as the If-Match header: an ETag from Get or
// Update, a secret version number such as "3", or "*". ExpectedVersion, when
// set, is sent as the expected_version body field. On a mismatch Update
// returns *ConflictError carrying the current ETag.
//
// Minimum server: secretserver.io 3075630 (partial, conditional updates).
// Unless the client was built with Config.PartialUpdates, IfMatch must be an
// ETag from Get or Update (a quoted "..." or W/"..." value); a version
// number, "*" or ExpectedVersion alone does not qualify, and Update returns
// ErrPartialUpdatesUnconfirmed without sending a request.
type SecretUpdateRequest struct {
	Data            map[string]string
	Description     *string
	Tags            *[]string
	ContainerID     *string
	Clear           []string
	IfMatch         string
	ExpectedVersion *int
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
	resp, err := s.client.Do(req, &secret)
	if err != nil {
		return nil, err
	}
	secret.ETag = resp.Header.Get("ETag")

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

// Update applies a partial update and returns the updated secret metadata
// with its new ETag. Only the fields set in the request are sent; see
// SecretUpdateRequest for the omit/clear convention. It needs only the
// secrets:write permission and never reads the secret value.
//
// Minimum server: secretserver.io 3075630. Update refuses with
// ErrPartialUpdatesUnconfirmed, sending nothing, unless Config.PartialUpdates
// is set or updateReq.IfMatch is an ETag from Get or Update.
func (s *SecretsService) Update(ctx context.Context, name string, updateReq *SecretUpdateRequest) (*Secret, error) {
	if updateReq == nil {
		return nil, fmt.Errorf("update request is required")
	}
	p, err := seg(name)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{}
	if updateReq.Data != nil {
		if len(updateReq.Data) == 0 {
			return nil, fmt.Errorf("update data must not be empty")
		}
		body["data"] = updateReq.Data
	}
	if updateReq.Description != nil {
		body["description"] = *updateReq.Description
	}
	if updateReq.Tags != nil {
		tags := *updateReq.Tags
		if tags == nil {
			tags = []string{}
		}
		body["tags"] = tags
	}
	if updateReq.ContainerID != nil {
		if *updateReq.ContainerID == "" {
			return nil, fmt.Errorf("container_id must not be empty; use Clear to remove the container")
		}
		body["container_id"] = *updateReq.ContainerID
	}
	if updateReq.ExpectedVersion != nil {
		body["expected_version"] = *updateReq.ExpectedVersion
	}
	if err := patchClear(body, updateReq.Clear, "description", "tags", "container_id"); err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("update must set or clear at least one field")
	}

	if err := s.client.checkPartialUpdate(updateReq.IfMatch); err != nil {
		return nil, err
	}

	var secret Secret
	resp, err := s.client.callWithIfMatch(ctx, "PUT", "/api/v1/secrets/"+p, updateReq.IfMatch, body, &secret)
	if err != nil {
		return nil, err
	}
	secret.ETag = resp.Header.Get("ETag")

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
