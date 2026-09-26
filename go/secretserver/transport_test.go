package secretserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// recordingTLSServer is a self-signed TLS server that counts every request
// and every Authorization header that reaches it.
func recordingTLSServer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var requests, auths atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" {
			auths.Add(1)
		}
		_, _ = w.Write([]byte(`{"secrets":[]}`))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &requests, &auths
}

type wrappingRoundTripper struct{ inner http.RoundTripper }

func (w wrappingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return w.inner.RoundTrip(r)
}

func TestNewClientRefusesWrappedInsecureTransport(t *testing.T) {
	srv, requests, auths := recordingTLSServer(t)
	insecure := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // negative test
	hc := &http.Client{Transport: wrappingRoundTripper{inner: insecure}}

	c, err := NewClient(&Config{APIURL: srv.URL, APIKey: testKey, HTTPClient: hc})
	if err == nil {
		_, _ = c.Secrets.List(context.Background(), nil)
		t.Fatal("NewClient accepted a RoundTripper wrapping an insecure transport")
	}
	if requests.Load() != 0 || auths.Load() != 0 {
		t.Fatalf("server saw %d requests (%d with Authorization)", requests.Load(), auths.Load())
	}
}

func TestNewClientRefusesCustomTLSDialer(t *testing.T) {
	tr := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}
	if _, err := NewClient(&Config{APIKey: testKey, HTTPClient: &http.Client{Transport: tr}}); err == nil {
		t.Fatal("NewClient accepted a transport with a custom TLS dialer")
	}
}

// Not parallel: mutates the process-wide http.DefaultTransport.
func TestNewClientRefusesMutatedDefaultTransport(t *testing.T) {
	srv, requests, auths := recordingTLSServer(t)
	saved := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = saved })

	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // negative test
	for _, hc := range []*http.Client{nil, {}} {
		c, err := NewClient(&Config{APIURL: srv.URL, APIKey: testKey, HTTPClient: hc})
		if err == nil {
			_, _ = c.Secrets.List(context.Background(), nil)
			t.Fatalf("NewClient(HTTPClient=%v) accepted an insecure http.DefaultTransport", hc)
		}
	}

	http.DefaultTransport = wrappingRoundTripper{inner: saved}
	if _, err := NewClient(&Config{APIURL: srv.URL, APIKey: testKey, HTTPClient: &http.Client{}}); err == nil {
		t.Fatal("NewClient accepted a wrapped http.DefaultTransport")
	}
	if requests.Load() != 0 || auths.Load() != 0 {
		t.Fatalf("server saw %d requests (%d with Authorization)", requests.Load(), auths.Load())
	}
}

func TestCallerTransportIsClonedAtConstruction(t *testing.T) {
	srv, requests, _ := recordingTLSServer(t)
	tr := &http.Transport{}
	c, err := NewClient(&Config{APIURL: srv.URL, APIKey: testKey, HTTPClient: &http.Client{Transport: tr}})
	if err != nil {
		t.Fatal(err)
	}
	// Disabling verification after construction must not reach the client.
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // negative test
	if _, err := c.Secrets.List(context.Background(), nil); err == nil {
		t.Fatal("request to a self-signed server succeeded")
	}
	if requests.Load() != 0 {
		t.Fatalf("server saw %d requests", requests.Load())
	}
	got := c.httpClient.Transport.(*http.Transport)
	if got == tr || got.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("caller transport not cloned with TLS 1.2 minimum")
	}
}

func TestDefaultClientRejectsUntrustedCertificate(t *testing.T) {
	srv, requests, auths := recordingTLSServer(t)
	c, err := NewClient(&Config{APIURL: srv.URL, APIKey: testKey})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Secrets.List(context.Background(), nil)
	var verr *tls.CertificateVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected a certificate verification failure, got %v", err)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatal("handshake error contains the API key")
	}
	if requests.Load() != 0 || auths.Load() != 0 {
		t.Fatalf("server saw %d requests (%d with Authorization)", requests.Load(), auths.Load())
	}
}

func TestCallerRootCAsTrustPrivateCA(t *testing.T) {
	srv, requests, auths := recordingTLSServer(t)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	c, err := NewClient(&Config{APIURL: srv.URL, APIKey: testKey, HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Secrets.List(context.Background(), nil); err != nil {
		t.Fatalf("request with trusted private CA failed: %v", err)
	}
	if requests.Load() != 1 || auths.Load() != 1 {
		t.Fatalf("server saw %d requests (%d with Authorization), want 1", requests.Load(), auths.Load())
	}
}
