package ui

import (
	"reflect"
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
