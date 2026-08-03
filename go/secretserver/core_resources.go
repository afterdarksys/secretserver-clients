package secretserver

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

type CertificateEnrollRequest struct {
	Name         string   `json:"name"`
	CommonName   string   `json:"common_name"`
	DNSNames     []string `json:"dns_names,omitempty"`
	KeyType      string   `json:"key_type,omitempty"`
	KeySize      int      `json:"key_size,omitempty"`
	ValidityDays int      `json:"validity_days,omitempty"`
	AutoRenew    bool     `json:"auto_renew"`
	RenewBefore  int      `json:"renew_before,omitempty"`
}

func (s *CertificatesService) List(ctx context.Context) ([]*Certificate, error) {
	var response struct {
		Certificates []*Certificate `json:"certificates"`
	}
	_, err := s.client.Call(ctx, http.MethodGet, "/certificates", nil, &response)
	return response.Certificates, err
}

func (s *CertificatesService) Get(ctx context.Context, id string) (*Certificate, error) {
	var result Certificate
	_, err := s.client.Call(ctx, http.MethodGet, "/certificates/"+url.PathEscape(id), nil, &result)
	return &result, err
}

func (s *CertificatesService) Enroll(ctx context.Context, input *CertificateEnrollRequest) (*Certificate, error) {
	if input == nil {
		return nil, fmt.Errorf("certificate enrollment request is required")
	}
	var result Certificate
	_, err := s.client.Call(ctx, http.MethodPost, "/certificates/enroll", input, &result)
	return &result, err
}

func (s *CertificatesService) Renew(ctx context.Context, id string) (*Certificate, error) {
	var result Certificate
	_, err := s.client.Call(ctx, http.MethodPost, "/certificates/"+url.PathEscape(id)+"/renew", nil, &result)
	return &result, err
}

func (s *CertificatesService) Revoke(ctx context.Context, id string) error {
	_, err := s.client.Call(ctx, http.MethodPost, "/certificates/"+url.PathEscape(id)+"/revoke", nil, nil)
	return err
}

func (s *CertificatesService) Download(ctx context.Context, id string) (map[string]interface{}, error) {
	var result map[string]interface{}
	_, err := s.client.Call(ctx, http.MethodGet, "/certificates/"+url.PathEscape(id)+"/download", nil, &result)
	return result, err
}

type GenerateSSHKeyRequest struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
	KeyType string `json:"key_type,omitempty"`
	Bits    int    `json:"bits,omitempty"`
}

type ImportSSHKeyRequest struct {
	Name       string `json:"name"`
	Comment    string `json:"comment,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

func (s *SSHKeysService) List(ctx context.Context) ([]*SSHKey, error) {
	var response struct {
		Keys []*SSHKey `json:"ssh_keys"`
	}
	_, err := s.client.Call(ctx, http.MethodGet, "/ssh-keys", nil, &response)
	return response.Keys, err
}

func (s *SSHKeysService) Get(ctx context.Context, id string) (*SSHKey, error) {
	var result SSHKey
	_, err := s.client.Call(ctx, http.MethodGet, "/ssh-keys/"+url.PathEscape(id), nil, &result)
	return &result, err
}

func (s *SSHKeysService) Generate(ctx context.Context, input *GenerateSSHKeyRequest) (*SSHKey, error) {
	if input == nil {
		return nil, fmt.Errorf("SSH key generation request is required")
	}
	var result SSHKey
	_, err := s.client.Call(ctx, http.MethodPost, "/ssh-keys/generate", input, &result)
	return &result, err
}

func (s *SSHKeysService) Import(ctx context.Context, input *ImportSSHKeyRequest) (*SSHKey, error) {
	if input == nil {
		return nil, fmt.Errorf("SSH key import request is required")
	}
	var result SSHKey
	_, err := s.client.Call(ctx, http.MethodPost, "/ssh-keys/import", input, &result)
	return &result, err
}

func (s *SSHKeysService) Export(ctx context.Context, id string) (map[string]string, error) {
	var result map[string]string
	_, err := s.client.Call(ctx, http.MethodGet, "/ssh-keys/"+url.PathEscape(id)+"/export", nil, &result)
	return result, err
}

func (s *SSHKeysService) Delete(ctx context.Context, id string) error {
	_, err := s.client.Call(ctx, http.MethodDelete, "/ssh-keys/"+url.PathEscape(id), nil, nil)
	return err
}
