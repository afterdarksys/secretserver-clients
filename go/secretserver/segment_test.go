package secretserver

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestSegRejectsDotAndEmptySegments(t *testing.T) {
	for _, s := range []string{"", ".", ".."} {
		if _, err := seg(s); err == nil {
			t.Errorf("seg(%q) accepted", s)
		}
	}
	for in, want := range map[string]string{"a/b": "a%2Fb", "...": "...", "a?b#c": "a%3Fb%23c", "%2e%2e": "%252e%252e", "x y": "x%20y"} {
		if got, err := seg(in); err != nil || got != want {
			t.Errorf("seg(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestBadPathSegmentsSendNoRequest(t *testing.T) {
	var requests atomic.Int32
	c := newTestClientConfig(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}, Config{PartialUpdates: true})
	ctx := context.Background()
	for _, bad := range []string{"", ".", ".."} {
		calls := map[string]error{}
		_, calls["Secrets.Get"] = c.Secrets.Get(ctx, bad, nil)
		_, calls["Secrets.Update"] = c.Secrets.Update(ctx, bad, &SecretUpdateRequest{Data: map[string]string{"v": "x"}})
		calls["Secrets.Delete"] = c.Secrets.Delete(ctx, bad)
		_, calls["Certificates.Get"] = c.Certificates.Get(ctx, bad)
		_, calls["Certificates.GetWithPEM"] = c.Certificates.GetWithPEM(ctx, bad)
		_, calls["Certificates.Renew"] = c.Certificates.Renew(ctx, bad)
		calls["Certificates.Revoke"] = c.Certificates.Revoke(ctx, bad)
		calls["Certificates.Download"] = c.Certificates.Download(ctx, bad, nil, io.Discard)
		_, calls["SSHKeys.Get"] = c.SSHKeys.Get(ctx, bad)
		_, calls["SSHKeys.Export"] = c.SSHKeys.Export(ctx, bad)
		calls["SSHKeys.Delete"] = c.SSHKeys.Delete(ctx, bad)
		_, calls["LDAP.Search"] = c.LDAP.Search(ctx, bad, &LDAPSearchRequest{Filter: "(cn=*)", BaseDN: "dc=x"})
		_, calls["Integrations.Get"] = c.Integrations.Get(ctx, bad, false)
		_, calls["JKS.Get"] = c.JKS.Get(ctx, bad)
		calls["JKS.Delete"] = c.JKS.Delete(ctx, bad)
		_, calls["JKS.Export"] = c.JKS.Export(ctx, bad)
		_, calls["JKS.Entries"] = c.JKS.Entries(ctx, bad)
		_, calls["JKS.CreateEntry"] = c.JKS.CreateEntry(ctx, bad, &CreateJKSEntryRequest{Alias: "a"})
		calls["JKS.DeleteEntry(id)"] = c.JKS.DeleteEntry(ctx, bad, "alias")
		calls["JKS.DeleteEntry(alias)"] = c.JKS.DeleteEntry(ctx, "store", bad)
		_, calls["AssignVariable"] = c.AssignVariable(ctx, bad, VariableAssignment{})
		_, calls["GetVariable"] = c.GetVariable(ctx, bad)
		calls["DeleteVariable"] = c.DeleteVariable(ctx, bad)
		for name, err := range calls {
			if err == nil {
				t.Errorf("%s(%q) accepted", name, bad)
			}
		}
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("server saw %d requests for invalid path segments", n)
	}
}

func TestPathSegmentsEscapedEverywhere(t *testing.T) {
	var paths []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		_, _ = w.Write([]byte(`{}`))
	})
	ctx := context.Background()
	_ = c.Secrets.Delete(ctx, "a/..")
	_ = c.JKS.DeleteEntry(ctx, "s/1", "../x")
	_, _ = c.GetVariable(ctx, "v?x")
	var buf bytes.Buffer
	_ = c.Certificates.Download(ctx, "c#1", nil, &buf)
	want := []string{
		"/api/v1/secrets/a%2F..",
		"/api/v1/jks-keystores/s%2F1/entries/..%2Fx",
		"/api/v1/variables/v%3Fx",
		"/api/v1/certificates/c%231/download",
	}
	if len(paths) != len(want) {
		t.Fatalf("paths = %q", paths)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("path[%d] = %q, want %q", i, paths[i], want[i])
		}
	}
}
