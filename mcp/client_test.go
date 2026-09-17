package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestClientListsMetadataAndSigns(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("sk_test_agent_identity_123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient("https://secrets.example.test", tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer sk_test_agent_identity_123456" {
			t.Errorf("missing agent authorization")
		}
		body := `[{"id":"01","label":"PIV signing","algorithm":"ECDSA-P256","backend":"pkcs11"}]`
		if request.URL.Path == "/api/v1/crypto/sign" {
			body = `{"signature":"c2ln","algorithm":"ECDSA-P256","key_id":"01","audit_id":"request-1"}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	keys, err := client.ListSigningKeys(context.Background(), "pkcs11")
	if err != nil || len(keys) != 1 || keys[0].ID != "01" {
		t.Fatalf("ListSigningKeys() = %#v, %v", keys, err)
	}
	result, err := client.Sign(context.Background(), "pkcs11", "01", "bWVzc2FnZQ==", "release signing")
	if err != nil || result.Signature != "c2ln" || result.AuditID != "request-1" {
		t.Fatalf("Sign() = %#v, %v", result, err)
	}
}

func TestClientRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := validateBaseURL("http://secrets.example.test"); err == nil {
		t.Fatal("non-loopback HTTP URL accepted")
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("sk_test_agent_identity_123456"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(tokenPath); err == nil {
		t.Fatal("world-readable token file accepted")
	}
}

func TestRenderUsesSharedResolverAndFailsClosed(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("fixture-token-for-render-test"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient("https://secrets.example.test", tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, test := range []struct {
		body    string
		status  int
		wantErr bool
	}{{`{"rendered":""}`, 200, false}, {`{"rendered":"literal %%OTHER%%"}`, 200, false}, {`{}`, 200, true}, {`{"error":"do-not-log"}`, 403, true}} {
		client.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/api/v1/variables/resolve" || req.Method != "POST" {
				t.Error("wrong resolver route")
			}
			return &http.Response{StatusCode: test.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(test.body))}, nil
		})
		_, err = client.Render(context.Background(), "%%VALUE%%")
		if (err != nil) != test.wantErr {
			t.Fatal("unexpected render failure state")
		}
		if err != nil && strings.Contains(err.Error(), "do-not-log") {
			t.Fatal("error body leaked")
		}
	}
}
