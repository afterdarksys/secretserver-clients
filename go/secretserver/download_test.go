package secretserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
)

func TestOversizeCertificateAndLDAPDownloadsWriteNothing(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("c"), maxDownloadBytes+1))
	})
	var cert countingWriter
	if err := c.Certificates.Download(context.Background(), "cert-1", nil, &cert); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("certificate download: got %v", err)
	}
	if cert.n != 0 {
		t.Fatalf("certificate download wrote %d bytes", cert.n)
	}
	var ldif countingWriter
	if err := c.LDAP.Export(context.Background(), nil, &ldif); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("LDAP export: got %v", err)
	}
	if ldif.n != 0 {
		t.Fatalf("LDAP export wrote %d bytes", ldif.n)
	}
}

func TestCertificateDownloadAtCapSucceeds(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("c"), maxDownloadBytes))
	})
	var buf bytes.Buffer
	if err := c.Certificates.Download(context.Background(), "cert-1", nil, &buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != maxDownloadBytes {
		t.Fatalf("wrote %d bytes, want %d", buf.Len(), maxDownloadBytes)
	}
}

func TestTruncatedDownloadWritesNothing(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Promise more than is sent, then drop the connection.
		w.Header().Set("Content-Length", strconv.Itoa(1024))
		_, _ = w.Write(bytes.Repeat([]byte("c"), 100))
		w.(http.Flusher).Flush()
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	})
	var sink countingWriter
	if err := c.Certificates.Download(context.Background(), "cert-1", nil, &sink); err == nil {
		t.Fatal("truncated download reported success")
	}
	if sink.n != 0 {
		t.Fatalf("truncated download wrote %d bytes", sink.n)
	}
}
