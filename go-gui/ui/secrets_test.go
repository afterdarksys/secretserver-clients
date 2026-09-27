package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/afterdarksys/secretserver-go/secretserver"
)

func TestEditUpdateRequest(t *testing.T) {
	sec := &secretserver.Secret{Name: "db", Description: "old", Data: map[string]string{"v": "1"}, ETag: `"e-1"`}

	if req := editUpdateRequest(sec, "old", map[string]string{"v": "1"}); req != nil {
		t.Fatalf("unchanged form produced an update: %#v", req)
	}

	req := editUpdateRequest(sec, "", map[string]string{"v": "1"})
	if req == nil || !reflect.DeepEqual(req.Clear, []string{"description"}) || req.Description != nil || req.Data != nil {
		t.Fatalf("emptied description must clear it and send nothing else: %#v", req)
	}
	if req.IfMatch != `"e-1"` {
		t.Fatalf("IfMatch = %q", req.IfMatch)
	}

	req = editUpdateRequest(sec, "new", map[string]string{"v": "2"})
	if req == nil || req.Description == nil || *req.Description != "new" || req.Data["v"] != "2" || req.Clear != nil {
		t.Fatalf("changed description and data not sent: %#v", req)
	}

	req = editUpdateRequest(sec, "old", map[string]string{"v": "2"})
	if req == nil || req.Description != nil || req.Clear != nil || req.Data["v"] != "2" {
		t.Fatalf("data-only change sent metadata: %#v", req)
	}
}

// TestEditWithoutETagIsRefused checks that a secret loaded without an ETag
// (an old server) is never sent as a partial update, and that the form
// explains why.
func TestEditWithoutETagIsRefused(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `"e-2"`)
		_, _ = w.Write([]byte(`{"id":"1","name":"db"}`))
	}))
	defer srv.Close()
	c, err := secretserver.NewClient(&secretserver.Config{APIURL: srv.URL, APIKey: "sk_test"})
	if err != nil {
		t.Fatal(err)
	}

	old := &secretserver.Secret{Name: "db", Description: "old", Data: map[string]string{"v": "1"}}
	_, err = c.Secrets.Update(context.Background(), "db", editUpdateRequest(old, "new", old.Data))
	if !errors.Is(err, secretserver.ErrPartialUpdatesUnconfirmed) {
		t.Fatalf("update without ETag: err = %v", err)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("refused update sent %d requests", n)
	}
	if msg := editUpdateError("db", err).Error(); !strings.Contains(msg, "not saved") || !strings.Contains(msg, "3075630") {
		t.Fatalf("message = %q", msg)
	}

	current := &secretserver.Secret{Name: "db", Description: "old", Data: map[string]string{"v": "1"}, ETag: `"e-1"`}
	if _, err := c.Secrets.Update(context.Background(), "db", editUpdateRequest(current, "new", current.Data)); err != nil {
		t.Fatalf("update with loaded ETag: %v", err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
	if msg := editUpdateError("db", &secretserver.ConflictError{ErrorResponse: &secretserver.ErrorResponse{}}).Error(); !strings.Contains(msg, "changed by someone else") {
		t.Fatalf("conflict message = %q", msg)
	}
}
