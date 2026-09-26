package secretserver

import (
	"context"
	"fmt"
	"io"
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
	p, err := seg(id)
	if err != nil {
		return nil, err
	}
	var result Certificate
	_, err = s.client.Call(ctx, http.MethodGet, "/certificates/"+p, nil, &result)
	return &result, err
}

// GetWithPEM returns certificate metadata with CertificatePEM populated
// (GET /certificates/:id?include_pem=true). The private key is not included.
func (s *CertificatesService) GetWithPEM(ctx context.Context, id string) (*Certificate, error) {
	p, err := seg(id)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Certificate    *Certificate `json:"certificate"`
		CertificatePEM string       `json:"certificate_pem"`
	}
	_, err = s.client.Call(ctx, http.MethodGet, "/certificates/"+p+"?include_pem=true", nil, &envelope)
	if err != nil {
		return nil, err
	}
	if envelope.Certificate == nil {
		return nil, fmt.Errorf("invalid certificate response")
	}
	envelope.Certificate.CertificatePEM = envelope.CertificatePEM
	return envelope.Certificate, nil
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
	p, err := seg(id)
	if err != nil {
		return nil, err
	}
	var result Certificate
	_, err = s.client.Call(ctx, http.MethodPost, "/certificates/"+p+"/renew", nil, &result)
	return &result, err
}

func (s *CertificatesService) Revoke(ctx context.Context, id string) error {
	p, err := seg(id)
	if err != nil {
		return err
	}
	_, err = s.client.Call(ctx, http.MethodPost, "/certificates/"+p+"/revoke", nil, nil)
	return err
}

// CertificateDownloadOptions selects the download format. Format is one of
// pem (default, certificate only), pem-bundle (certificate + private key),
// key (private key only), pfx or p12. pfx/p12 require Password, which the
// server takes as a query parameter.
type CertificateDownloadOptions struct {
	Format   string
	Password string
}

// Download streams the raw certificate material (at most 16 MiB) into w.
func (s *CertificatesService) Download(ctx context.Context, id string, opts *CertificateDownloadOptions, w io.Writer) error {
	if w == nil {
		return fmt.Errorf("download writer is required")
	}
	p, err := seg(id)
	if err != nil {
		return err
	}
	params := url.Values{}
	if opts != nil {
		switch opts.Format {
		case "", "pem", "pem-bundle", "key":
			if opts.Password != "" {
				return fmt.Errorf("password is only used with pfx or p12 format")
			}
		case "pfx", "p12":
			if opts.Password == "" {
				return fmt.Errorf("password is required for %s format", opts.Format)
			}
			params.Set("password", opts.Password)
		default:
			return fmt.Errorf("invalid certificate format: must be pem, pem-bundle, key, pfx or p12")
		}
		if opts.Format != "" {
			params.Set("format", opts.Format)
		}
	}
	path := "/certificates/" + p + "/download"
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

// GenerateSSHKeyRequest generates a keypair server-side. KeyType is one of
// ed25519 (default when empty), rsa or ecdsa.
type GenerateSSHKeyRequest struct {
	Name       string `json:"name"`
	Comment    string `json:"comment,omitempty"`
	KeyType    string `json:"key_type"`
	Bits       int    `json:"bits,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// ImportSSHKeyRequest imports an existing private key (PEM/OpenSSH format);
// the public key is derived server-side.
type ImportSSHKeyRequest struct {
	Name       string `json:"name"`
	Comment    string `json:"comment,omitempty"`
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase,omitempty"`
}

func (s *SSHKeysService) List(ctx context.Context) ([]*SSHKey, error) {
	var response struct {
		Keys []*SSHKey `json:"ssh_keys"`
	}
	_, err := s.client.Call(ctx, http.MethodGet, "/ssh-keys", nil, &response)
	return response.Keys, err
}

func (s *SSHKeysService) Get(ctx context.Context, id string) (*SSHKey, error) {
	p, err := seg(id)
	if err != nil {
		return nil, err
	}
	var result SSHKey
	_, err = s.client.Call(ctx, http.MethodGet, "/ssh-keys/"+p, nil, &result)
	return &result, err
}

func (s *SSHKeysService) Generate(ctx context.Context, input *GenerateSSHKeyRequest) (*SSHKey, error) {
	if input == nil {
		return nil, fmt.Errorf("SSH key generation request is required")
	}
	body := *input
	if body.KeyType == "" {
		body.KeyType = "ed25519"
	}
	var result SSHKey
	_, err := s.client.Call(ctx, http.MethodPost, "/ssh-keys/generate", &body, &result)
	return &result, err
}

func (s *SSHKeysService) Import(ctx context.Context, input *ImportSSHKeyRequest) (*SSHKey, error) {
	if input == nil {
		return nil, fmt.Errorf("SSH key import request is required")
	}
	if input.Name == "" || input.PrivateKey == "" {
		return nil, fmt.Errorf("SSH key import requires name and private_key")
	}
	var result SSHKey
	_, err := s.client.Call(ctx, http.MethodPost, "/ssh-keys/import", input, &result)
	return &result, err
}

// Export returns the key including PrivateKey.
func (s *SSHKeysService) Export(ctx context.Context, id string) (*SSHKey, error) {
	p, err := seg(id)
	if err != nil {
		return nil, err
	}
	var result SSHKey
	_, err = s.client.Call(ctx, http.MethodGet, "/ssh-keys/"+p+"/export", nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *SSHKeysService) Delete(ctx context.Context, id string) error {
	p, err := seg(id)
	if err != nil {
		return err
	}
	_, err = s.client.Call(ctx, http.MethodDelete, "/ssh-keys/"+p, nil, nil)
	return err
}
