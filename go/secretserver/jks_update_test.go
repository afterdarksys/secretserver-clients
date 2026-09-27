package secretserver

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestJKSUpdateSendsOnlyProvidedFields(t *testing.T) {
	var got []capturedRequest
	c := updateServer(t, http.StatusOK, `"j-2"`, &got)
	ctx := context.Background()

	notes := "new notes"
	etag, err := c.JKS.Update(ctx, "ks-1", &JKSKeystoreUpdate{Notes: &notes})
	if err != nil {
		t.Fatal(err)
	}
	if etag != `"j-2"` {
		t.Fatalf("etag = %q", etag)
	}
	if len(got) != 1 || got[0].method != http.MethodPut {
		t.Fatalf("expected a single PUT with no pre-read GET, got %#v", got)
	}
	if b := rawBody(t, got[0].body); !reflect.DeepEqual(b, map[string]string{"notes": `"new notes"`}) {
		t.Fatalf("body = %v", b)
	}

	got = nil
	pw := "rotated"
	if _, err := c.JKS.Update(ctx, "ks-1", &JKSKeystoreUpdate{Password: &pw, Clear: []string{"notes", "tags", "container_id"}, IfMatch: `"j-1"`}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"password": `"rotated"`, "notes": "null", "tags": "null", "container_id": "null"}
	if b := rawBody(t, got[0].body); !reflect.DeepEqual(b, want) {
		t.Fatalf("body = %v, want %v", b, want)
	}
	if got[0].ifMatch != `"j-1"` {
		t.Fatalf("If-Match = %q", got[0].ifMatch)
	}
}

func TestJKSUpdateConflictReturnsConflictError(t *testing.T) {
	var got []capturedRequest
	c := updateServer(t, http.StatusConflict, `"j-current"`, &got)
	name := "renamed"
	_, err := c.JKS.Update(context.Background(), "ks-1", &JKSKeystoreUpdate{Name: &name, IfMatch: `"j-stale"`})
	var conflict *ConflictError
	if !errors.As(err, &conflict) || conflict.ETag != `"j-current"` {
		t.Fatalf("err = %v, want *ConflictError with current ETag", err)
	}
}

func TestJKSGetExposesETag(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"j-1"`)
		_, _ = w.Write([]byte(`{"id":"ks-1","name":"store"}`))
	})
	ks, err := c.JKS.Get(context.Background(), "ks-1")
	if err != nil {
		t.Fatal(err)
	}
	if ks.ETag != `"j-1"` {
		t.Fatalf("ETag = %q", ks.ETag)
	}
}

func TestJKSUpdateRejectsInvalidInputWithoutRequest(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	})
	ctx := context.Background()
	empty, data, notes := "", "AAAA", "n"
	for name, input := range map[string]*JKSKeystoreUpdate{
		"nil":             nil,
		"no fields":       {},
		"empty name":      {Name: &empty},
		"empty container": {ContainerID: &empty},
		"jks without pw":  {JKS: &data},
		"empty password":  {Password: &empty},
		"unknown clear":   {Clear: []string{"name"}},
		"set and clear":   {Notes: &notes, Clear: []string{"notes"}},
	} {
		if _, err := c.JKS.Update(ctx, "ks-1", input); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := c.JKS.Update(ctx, "..", &JKSKeystoreUpdate{Notes: &notes}); err == nil {
		t.Fatal("dot-dot id accepted")
	}
}
