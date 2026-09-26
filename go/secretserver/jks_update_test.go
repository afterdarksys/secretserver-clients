package secretserver

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
)

func jksServer(t *testing.T, current string, put *map[string]interface{}, requests *atomic.Int32) *Client {
	t.Helper()
	return newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.EscapedPath() != "/api/v1/jks-keystores/ks-1" {
			t.Errorf("unexpected path %s", r.URL.EscapedPath())
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(current))
		case http.MethodPut:
			*put = nil
			if err := json.NewDecoder(r.Body).Decode(put); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(`{"message":"updated"}`))
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})
}

func TestJKSUpdateReadMergeWrite(t *testing.T) {
	var put map[string]interface{}
	var requests atomic.Int32
	c := jksServer(t, `{"id":"ks-1","tenant_id":"t","container_id":"c-1","name":"store","notes":"n","tags":["a","b"],"store_type":"managed","entry_count":2}`, &put, &requests)
	ctx := context.Background()

	notes := "new notes"
	if err := c.JKS.Update(ctx, "ks-1", &JKSKeystoreUpdate{Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{"name": "store", "container_id": "c-1", "notes": "new notes", "tags": []interface{}{"a", "b"}}
	if !reflect.DeepEqual(put, want) {
		t.Fatalf("PUT body = %#v, want %#v", put, want)
	}

	name, empty, tags := "renamed", "", []string{}
	if err := c.JKS.Update(ctx, "ks-1", &JKSKeystoreUpdate{Name: &name, ContainerID: &empty, Notes: &empty, Tags: &tags}); err != nil {
		t.Fatal(err)
	}
	want = map[string]interface{}{"name": "renamed", "container_id": nil, "notes": "", "tags": []interface{}{}}
	if !reflect.DeepEqual(put, want) {
		t.Fatalf("PUT body = %#v, want %#v", put, want)
	}
	if n := requests.Load(); n != 4 {
		t.Fatalf("requests = %d, want GET+PUT twice", n)
	}
}

func TestJKSUpdateSendsEmptyTagsNotNull(t *testing.T) {
	var put map[string]interface{}
	var requests atomic.Int32
	c := jksServer(t, `{"id":"ks-1","name":"store"}`, &put, &requests)
	if err := c.JKS.Update(context.Background(), "ks-1", &JKSKeystoreUpdate{}); err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{"name": "store", "container_id": nil, "notes": "", "tags": []interface{}{}}
	if !reflect.DeepEqual(put, want) {
		t.Fatalf("PUT body = %#v, want %#v", put, want)
	}
}

func TestJKSUpdateRejectsInvalidInputWithoutRequest(t *testing.T) {
	var put map[string]interface{}
	var requests atomic.Int32
	c := jksServer(t, `{}`, &put, &requests)
	ctx := context.Background()
	empty := ""
	if err := c.JKS.Update(ctx, "ks-1", nil); err == nil {
		t.Fatal("nil update accepted")
	}
	if err := c.JKS.Update(ctx, "ks-1", &JKSKeystoreUpdate{Name: &empty}); err == nil {
		t.Fatal("empty name accepted")
	}
	if err := c.JKS.Update(ctx, "..", &JKSKeystoreUpdate{}); err == nil {
		t.Fatal("dot-dot id accepted")
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("server saw %d requests", n)
	}
}

func TestJKSUpdateRefusesUnusableCurrentRecord(t *testing.T) {
	var put map[string]interface{}
	var requests atomic.Int32
	c := jksServer(t, `{}`, &put, &requests)
	if err := c.JKS.Update(context.Background(), "ks-1", &JKSKeystoreUpdate{}); err == nil {
		t.Fatal("update proceeded without a current name")
	}
	if put != nil || requests.Load() != 1 {
		t.Fatalf("PUT sent after an unusable GET: %#v", put)
	}
}
