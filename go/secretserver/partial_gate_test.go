package secretserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// gateClient counts requests and answers every update with 200 and an ETag.
func gateClient(t *testing.T, partial bool, requests *atomic.Int32) *Client {
	t.Helper()
	return newTestClientConfig(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `"new"`)
		_, _ = w.Write([]byte(`{"id":"1","name":"db"}`))
	}, Config{PartialUpdates: partial})
}

// gateUpdates runs Secrets.Update and JKS.Update with ifMatch.
func gateUpdates(c *Client, ifMatch string, version *int) map[string]error {
	notes := "n"
	_, secErr := c.Secrets.Update(context.Background(), "db", &SecretUpdateRequest{Data: map[string]string{"v": "x"}, IfMatch: ifMatch, ExpectedVersion: version})
	_, jksErr := c.JKS.Update(context.Background(), "ks-1", &JKSKeystoreUpdate{Notes: &notes, IfMatch: ifMatch})
	return map[string]error{"Secrets.Update": secErr, "JKS.Update": jksErr}
}

func TestPartialUpdateRefusedWithoutOptInOrETag(t *testing.T) {
	var requests atomic.Int32
	c := gateClient(t, false, &requests)
	three := 3
	for _, tc := range []struct {
		ifMatch string
		version *int
	}{
		{"", nil},
		{"", &three}, // expected_version alone
		{"3", nil},   // bare version number
		{"*", nil},
		{"etag-1", nil}, // unquoted
		{`W/etag-1`, nil},
		{`""`, nil},
		{`"`, nil},
		{`"a"b"`, nil},
		{`"a b"`, nil},
		{`w/"a"`, nil},
		{`"a"` + "\n", nil},
	} {
		for method, err := range gateUpdates(c, tc.ifMatch, tc.version) {
			if !errors.Is(err, ErrPartialUpdatesUnconfirmed) {
				t.Errorf("%s(IfMatch=%q): err = %v, want ErrPartialUpdatesUnconfirmed", method, tc.ifMatch, err)
			}
		}
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("refused updates sent %d requests", n)
	}
	msg := ErrPartialUpdatesUnconfirmed.Error()
	for _, want := range []string{"secretserver.io 3075630 or newer", "pass an ETag from get() as if_match", "enable partial_updates"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}
}

func TestPartialUpdateAllowedWithEntityTag(t *testing.T) {
	var requests atomic.Int32
	c := gateClient(t, false, &requests)
	for _, etag := range []string{`"e-1"`, `W/"e-1"`, `"2026-09-27T10:00:00.123456789Z"`} {
		for method, err := range gateUpdates(c, etag, nil) {
			if err != nil {
				t.Errorf("%s(IfMatch=%q): %v", method, etag, err)
			}
		}
	}
	if n := requests.Load(); n != 6 {
		t.Fatalf("requests = %d, want 6", n)
	}
}

func TestPartialUpdateAllowedWithOptIn(t *testing.T) {
	var requests atomic.Int32
	c := gateClient(t, true, &requests)
	for _, ifMatch := range []string{"", "3", "*"} {
		for method, err := range gateUpdates(c, ifMatch, nil) {
			if err != nil {
				t.Errorf("%s(IfMatch=%q) with PartialUpdates: %v", method, ifMatch, err)
			}
		}
	}
	if n := requests.Load(); n != 6 {
		t.Fatalf("requests = %d, want 6", n)
	}
}
