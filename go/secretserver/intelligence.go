package secretserver

import (
	"context"
	"fmt"
)

// TransformService handles data transformation
type TransformService struct {
	client *Client
}

type TransformRequest struct {
	Input      string                 `json:"input"`
	TargetType string                 `json:"target_type,omitempty"`
	SourceType string                 `json:"source_type,omitempty"`
	Options    map[string]interface{} `json:"options,omitempty"`
}

type TransformResponse struct {
	Result       interface{} `json:"result"`
	Type         string      `json:"type,omitempty"`
	DetectedType string      `json:"detected_type,omitempty"`
}

func (s *TransformService) Encode(ctx context.Context, input, targetType string, opts map[string]interface{}) (*TransformResponse, error) {
	reqBody := &TransformRequest{Input: input, TargetType: targetType, Options: opts}
	req, err := s.client.NewRequest(ctx, "POST", "/api/v1/transform/encode", reqBody)
	if err != nil {
		return nil, err
	}
	var resp TransformResponse
	_, err = s.client.Do(req, &resp)
	return &resp, err
}

func (s *TransformService) Decode(ctx context.Context, input, sourceType string) (*TransformResponse, error) {
	reqBody := &TransformRequest{Input: input, SourceType: sourceType}
	req, err := s.client.NewRequest(ctx, "POST", "/api/v1/transform/decode", reqBody)
	if err != nil {
		return nil, err
	}
	var resp TransformResponse
	_, err = s.client.Do(req, &resp)
	return &resp, err
}

func (s *TransformService) Detect(ctx context.Context, input string) (*TransformResponse, error) {
	reqBody := &TransformRequest{Input: input}
	req, err := s.client.NewRequest(ctx, "POST", "/api/v1/transform/detect", reqBody)
	if err != nil {
		return nil, err
	}
	var resp TransformResponse
	_, err = s.client.Do(req, &resp)
	return &resp, err
}

// IntelligenceService handles security intelligence
type IntelligenceService struct {
	client *Client
}

type BreachCheckResponse struct {
	Leaked        bool `json:"leaked"`
	ExposureCount int  `json:"exposure_count"`
}

func (s *IntelligenceService) CheckBreach(ctx context.Context, password string) (*BreachCheckResponse, error) {
	reqBody := map[string]string{"password": password}
	req, err := s.client.NewRequest(ctx, "POST", "/api/v1/intelligence/check-breach", reqBody)
	if err != nil {
		return nil, err
	}
	var resp BreachCheckResponse
	_, err = s.client.Do(req, &resp)
	return &resp, err
}

// ExtractionService handles secret discovery from files
type ExtractionService struct {
	client *Client
}

type ExtractionResponse struct {
	ScanID        string        `json:"scan_id"`
	FindingsCount int           `json:"findings_count"`
	Findings      []interface{} `json:"findings"`
	Status        string        `json:"status"`
}

func (s *ExtractionService) ExtractFromDB(ctx context.Context, fileName string) (*ExtractionResponse, error) {
	// Note: Multi-part form upload would be better, but implementing as simplified JSON for now
	path := "/api/v1/extraction/db"
	req, err := s.client.NewRequest(ctx, "POST", path, map[string]string{"filename": fileName})
	if err != nil {
		return nil, err
	}
	var resp ExtractionResponse
	_, err = s.client.Do(req, &resp)
	return &resp, err
}

// LDAPService handles directory integration
type LDAPService struct {
	client *Client
}

func (s *LDAPService) Import(ctx context.Context, ldifData string) (map[string]interface{}, error) {
	req, err := s.client.NewRequest(ctx, "POST", "/api/v1/ldap/import", map[string]string{"data": ldifData})
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	_, err = s.client.Do(req, &resp)
	return resp, err
}

func (s *LDAPService) Search(ctx context.Context, connectionID string, query string) (interface{}, error) {
	path := fmt.Sprintf("/api/v1/ldap/connections/%s/search", connectionID)
	req, err := s.client.NewRequest(ctx, "POST", path, map[string]string{"query": query})
	if err != nil {
		return nil, err
	}
	var resp interface{}
	_, err = s.client.Do(req, &resp)
	return resp, err
}

func (s *LDAPService) Export(ctx context.Context) (string, error) {
	req, err := s.client.NewRequest(ctx, "GET", "/api/v1/ldap/export", nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Data string `json:"data"`
	}
	_, err = s.client.Do(req, &resp)
	return resp.Data, err
}

// MockService handles mocking framework integration
type MockService struct {
	client *Client
}

func (s *MockService) Configure(ctx context.Context, config map[string]interface{}) error {
	req, err := s.client.NewRequest(ctx, "POST", "/api/v1/mock/configure", config)
	if err != nil {
		return err
	}
	_, err = s.client.Do(req, nil)
	return err
}
