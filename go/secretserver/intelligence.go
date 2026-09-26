package secretserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	FileName      string        `json:"file_name,omitempty"`
	FileSize      int64         `json:"file_size,omitempty"`
	ScannedAt     string        `json:"scanned_at,omitempty"`
	ImportStatus  string        `json:"import_status,omitempty"`
	Message       string        `json:"message,omitempty"`
}

// ExtractFromDB uploads a file (multipart field "file") and scans it for
// secrets. autoImport marks findings as ready for review before import.
func (s *ExtractionService) ExtractFromDB(ctx context.Context, filename string, r io.Reader, autoImport bool) (*ExtractionResponse, error) {
	fields := map[string]string{}
	if autoImport {
		fields["auto_import"] = "true"
	}
	var resp ExtractionResponse
	if err := s.client.uploadFile(ctx, "/api/v1/extraction/db", filename, r, fields, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LDAPService handles directory integration
type LDAPService struct {
	client *Client
}

// LDAPImportOptions controls an LDIF import.
type LDAPImportOptions struct {
	CreatePasswords bool // create passwords from userPassword attributes
	DryRun          bool // validate only
}

// LDAPImportResult summarizes an LDIF import.
type LDAPImportResult struct {
	TotalEntries     int      `json:"total_entries"`
	ProcessedEntries int      `json:"processed_entries"`
	CreatedPasswords int      `json:"created_passwords"`
	SkippedEntries   int      `json:"skipped_entries"`
	Errors           []string `json:"errors,omitempty"`
	DryRun           bool     `json:"dry_run"`
}

// Import uploads LDIF data (multipart field "file").
func (s *LDAPService) Import(ctx context.Context, filename string, r io.Reader, opts *LDAPImportOptions) (*LDAPImportResult, error) {
	fields := map[string]string{}
	if opts != nil {
		if opts.CreatePasswords {
			fields["create_passwords"] = "true"
		}
		if opts.DryRun {
			fields["dry_run"] = "true"
		}
	}
	var resp struct {
		Result *LDAPImportResult `json:"result"`
	}
	if err := s.client.uploadFile(ctx, "/api/v1/ldap/import", filename, r, fields, &resp); err != nil {
		return nil, err
	}
	if resp.Result == nil {
		return nil, fmt.Errorf("invalid LDAP import response")
	}
	return resp.Result, nil
}

// LDAPSearchRequest searches a stored LDAP connection. Filter and BaseDN are
// required; SizeLimit 0 uses the server default (100).
type LDAPSearchRequest struct {
	Filter     string   `json:"filter"`
	BaseDN     string   `json:"base_dn"`
	Attributes []string `json:"attributes,omitempty"`
	SizeLimit  int      `json:"size_limit,omitempty"`
}

// LDAPSearchEntry is one search result.
type LDAPSearchEntry struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

// LDAPSearchResponse is the search result envelope.
type LDAPSearchResponse struct {
	Results     []LDAPSearchEntry `json:"results"`
	ResultCount int               `json:"result_count"`
	BaseDN      string            `json:"base_dn"`
	Filter      string            `json:"filter"`
	SearchedAt  string            `json:"searched_at"`
}

func (s *LDAPService) Search(ctx context.Context, connectionID string, input *LDAPSearchRequest) (*LDAPSearchResponse, error) {
	p, err := seg(connectionID)
	if err != nil {
		return nil, err
	}
	if input == nil || input.Filter == "" || input.BaseDN == "" {
		return nil, fmt.Errorf("LDAP search requires filter and base_dn")
	}
	if input.SizeLimit < 0 {
		return nil, fmt.Errorf("size_limit must not be negative")
	}
	var resp LDAPSearchResponse
	_, err = s.client.Call(ctx, http.MethodPost, "/ldap/connections/"+p+"/search", input, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// LDAPExportOptions controls an LDIF export. Passwords includes password
// values (userPassword); BaseDN overrides the server's default base DN.
type LDAPExportOptions struct {
	Passwords bool
	BaseDN    string
}

// Export streams LDIF text (at most 16 MiB) into w.
func (s *LDAPService) Export(ctx context.Context, opts *LDAPExportOptions, w io.Writer) error {
	if w == nil {
		return fmt.Errorf("export writer is required")
	}
	path := "/ldap/export"
	params := url.Values{}
	if opts != nil {
		if opts.Passwords {
			params.Set("passwords", "true")
		}
		if opts.BaseDN != "" {
			params.Set("base_dn", opts.BaseDN)
		}
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}
	req, err := s.client.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "*/*")
	_, err = s.client.Do(req, w)
	return err
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
