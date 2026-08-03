package secretserver

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// IntegrationProvider describes one allowlisted provider credential schema.
type IntegrationProvider struct {
	ID           string     `json:"id"`
	DisplayName  string     `json:"display_name"`
	Category     string     `json:"category"`
	Required     []string   `json:"required,omitempty"`
	Optional     []string   `json:"optional,omitempty"`
	Alternatives [][]string `json:"alternatives,omitempty"`
}

// KeyCatalogItem describes a supported secret/key category without exposing material.
type KeyCatalogItem struct {
	ID               string   `json:"id"`
	Category         string   `json:"category"`
	Kind             string   `json:"kind"`
	Maturity         string   `json:"maturity"`
	Formats          []string `json:"formats,omitempty"`
	Algorithms       []string `json:"algorithms,omitempty"`
	NonExportable    bool     `json:"non_exportable,omitempty"`
	EnabledByDefault bool     `json:"enabled_by_default"`
}

type IntegrationCredential struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Provider    string                 `json:"provider"`
	AuthType    string                 `json:"auth_type,omitempty"`
	Endpoint    string                 `json:"endpoint,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Credentials map[string]interface{} `json:"credentials,omitempty"`
}

type IntegrationCredentialCreateRequest struct {
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	AuthType    string            `json:"auth_type,omitempty"`
	Endpoint    string            `json:"endpoint,omitempty"`
	Credentials map[string]string `json:"credentials"`
	Tags        []string          `json:"tags,omitempty"`
}

type IntegrationsService struct{ client *Client }

func (s *IntegrationsService) Providers(ctx context.Context) ([]IntegrationProvider, error) {
	req, err := s.client.NewRequest(ctx, http.MethodGet, "/api/v1/integration-providers", nil)
	if err != nil {
		return nil, err
	}
	var providers []IntegrationProvider
	_, err = s.client.Do(req, &providers)
	return providers, err
}

func (s *IntegrationsService) KeyCatalog(ctx context.Context) ([]KeyCatalogItem, error) {
	req, err := s.client.NewRequest(ctx, http.MethodGet, "/api/v1/key-catalog", nil)
	if err != nil {
		return nil, err
	}
	var catalog []KeyCatalogItem
	_, err = s.client.Do(req, &catalog)
	return catalog, err
}

func (s *IntegrationsService) Create(ctx context.Context, input *IntegrationCredentialCreateRequest) (string, error) {
	req, err := s.client.NewRequest(ctx, http.MethodPost, "/api/v1/integrations", input)
	if err != nil {
		return "", err
	}
	var result struct {
		ID string `json:"id"`
	}
	_, err = s.client.Do(req, &result)
	return result.ID, err
}

// Get returns metadata by default. reveal=true requires export:read and should
// only be used by an interactive caller that can protect the returned values.
func (s *IntegrationsService) Get(ctx context.Context, id string, reveal bool) (*IntegrationCredential, error) {
	path := fmt.Sprintf("/api/v1/integrations/%s", url.PathEscape(id))
	if reveal {
		path += "?reveal=true"
	}
	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var credential IntegrationCredential
	_, err = s.client.Do(req, &credential)
	return &credential, err
}
