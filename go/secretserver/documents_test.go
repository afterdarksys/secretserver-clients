package secretserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocumentsWireContract(t *testing.T) {
	calls := 0
	ctx := context.Background()
	pdf := []byte{'%', 'P', 'D', 'F', '-', 0, 255}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer test" {
			t.Error("missing auth")
		}
		if r.Method == "POST" && r.URL.Path == "/api/v1/documents" {
			b, _ := io.ReadAll(r.Body)
			if !bytes.Equal(b, pdf) || r.Header.Get("Content-Type") != "application/pdf" || r.URL.Query().Get("name") != "a & b.pdf" {
				t.Error("raw upload contract")
			}
		}
		if strings.Contains(r.URL.Path, "/pages/") {
			if r.URL.Query().Get("purpose") != "print" {
				t.Error("print purpose missing")
			}
			w.Write([]byte{0, 255, 10, 128})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/download") {
			w.Write([]byte{0, 255, 10, 128})
			return
		}
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/grants") {
			var g DocumentGrantRequest
			json.NewDecoder(r.Body).Decode(&g)
			if g.AllowDownload || g.AllowPrint || g.RecipientEmail != "member@example.com" {
				t.Error("grant defaults")
			}
		}
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		io.WriteString(w, `{"id":"doc"}`)
	}))
	defer server.Close()
	c, err := NewClient(&Config{APIURL: server.URL, APIKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Documents.Upload(ctx, "a & b.pdf", pdf); err != nil {
		t.Fatal(err)
	}
	for _, print := range []bool{true} {
		b, e := c.Documents.Preview(ctx, "doc", 2, print)
		if e != nil || !bytes.Equal(b, []byte{0, 255, 10, 128}) {
			t.Fatal("preview", e)
		}
	}
	b, e := c.Documents.Download(ctx, "doc")
	if e != nil || !bytes.Equal(b, []byte{0, 255, 10, 128}) {
		t.Fatal("download", e)
	}
	if _, e = c.Documents.Grant(ctx, "doc", DocumentGrantRequest{RecipientEmail: "member@example.com", ExpiresAt: "2030-01-01T00:00:00Z"}); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Documents.List(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Documents.Get(ctx, "doc"); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Documents.Grants(ctx, "doc"); e != nil {
		t.Fatal(e)
	}
	if e = c.Documents.Revoke(ctx, "doc", "grant"); e != nil {
		t.Fatal(e)
	}
	count := calls
	if _, e = c.Documents.Preview(ctx, "doc", 0, false); e == nil {
		t.Fatal("invalid page")
	}
	if _, e = c.Documents.Upload(ctx, "x", make([]byte, (8<<20)+1)); e == nil {
		t.Fatal("oversize")
	}
	if _, e = c.Documents.Grant(ctx, "doc", DocumentGrantRequest{}); e == nil {
		t.Fatal("missing recipient")
	}
	if calls != count {
		t.Fatal("invalid request sent")
	}
}
