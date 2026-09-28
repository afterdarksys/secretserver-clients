package secretserver

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
)

type DocumentsService struct{ client *Client }
type Document struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pages       int    `json:"pages"`
	SizeBytes   int64  `json:"size_bytes"`
	CreatedAt   string `json:"created_at"`
	CanManage   bool   `json:"can_manage"`
	CanDownload bool   `json:"can_download"`
	CanPrint    bool   `json:"can_print"`
}
type DocumentList struct {
	Documents []Document `json:"documents"`
	CanManage bool       `json:"can_manage"`
	Limit     int        `json:"limit"`
}
type DocumentGrantRequest struct {
	UserID         string `json:"user_id,omitempty"`
	RecipientEmail string `json:"recipient_email,omitempty"`
	ExpiresAt      string `json:"expires_at"`
	AllowDownload  bool   `json:"allow_download"`
	AllowPrint     bool   `json:"allow_print"`
}
type DocumentGrant struct {
	DocumentGrantRequest
	ID        string  `json:"id"`
	RevokedAt *string `json:"revoked_at"`
}

func documentPath(id string) (string, error) {
	if id == "" || id == "." || id == ".." {
		return "", fmt.Errorf("invalid document ID")
	}
	return "/documents/" + url.PathEscape(id), nil
}
func (s *DocumentsService) List(ctx context.Context) (*DocumentList, error) {
	var out DocumentList
	_, err := s.client.Call(ctx, "GET", "/documents", nil, &out)
	return &out, err
}
func (s *DocumentsService) Get(ctx context.Context, id string) (*Document, error) {
	p, err := documentPath(id)
	if err != nil {
		return nil, err
	}
	var out Document
	_, err = s.client.Call(ctx, "GET", p, nil, &out)
	return &out, err
}

// Upload sends PDF bytes without multipart encoding. Configure an 80-second HTTP timeout for document workloads.
func (s *DocumentsService) Upload(ctx context.Context, name string, pdf []byte) (*Document, error) {
	if len(pdf) == 0 || len(pdf) > 8<<20 {
		return nil, fmt.Errorf("PDF must contain between 1 byte and 8 MiB")
	}
	req, err := s.client.newRequest(ctx, "POST", "/documents?"+url.Values{"name": {name}}.Encode(), bytes.NewReader(pdf), "application/pdf")
	if err != nil {
		return nil, err
	}
	var out Document
	_, err = s.client.Do(req, &out)
	return &out, err
}
func (s *DocumentsService) Download(ctx context.Context, id string) ([]byte, error) {
	p, err := documentPath(id)
	if err != nil {
		return nil, err
	}
	return s.raw(ctx, p+"/download")
}
func (s *DocumentsService) Preview(ctx context.Context, id string, page int, forPrint bool) ([]byte, error) {
	p, err := documentPath(id)
	if err != nil {
		return nil, err
	}
	if page < 1 || page > 50 {
		return nil, fmt.Errorf("page must be from 1 to 50")
	}
	p += fmt.Sprintf("/pages/%d", page)
	if forPrint {
		p += "?purpose=print"
	}
	return s.raw(ctx, p)
}
func (s *DocumentsService) raw(ctx context.Context, path string) ([]byte, error) {
	var out bytes.Buffer
	_, err := s.client.Call(ctx, "GET", path, nil, &out)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func (s *DocumentsService) Grant(ctx context.Context, id string, g DocumentGrantRequest) (string, error) {
	p, err := documentPath(id)
	if err != nil {
		return "", err
	}
	if (g.UserID == "") == (g.RecipientEmail == "") {
		return "", fmt.Errorf("specify exactly one user ID or recipient email")
	}
	var out struct {
		ID string `json:"id"`
	}
	_, err = s.client.Call(ctx, "POST", p+"/grants", g, &out)
	return out.ID, err
}
func (s *DocumentsService) Grants(ctx context.Context, id string) ([]DocumentGrant, error) {
	p, err := documentPath(id)
	if err != nil {
		return nil, err
	}
	var out struct {
		Grants []DocumentGrant `json:"grants"`
	}
	_, err = s.client.Call(ctx, "GET", p+"/grants", nil, &out)
	return out.Grants, err
}
func (s *DocumentsService) Revoke(ctx context.Context, id, grantID string) error {
	p, err := documentPath(id)
	if err != nil {
		return err
	}
	if _, err = documentPath(grantID); err != nil {
		return err
	}
	_, err = s.client.Call(ctx, "DELETE", p+"/grants/"+url.PathEscape(grantID), nil, nil)
	return err
}
