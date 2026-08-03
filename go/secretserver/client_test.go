package secretserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientMatchesBackendContract(t *testing.T) {
	var updateBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk_test" {
			t.Errorf("Authorization = %q", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/proxy/api/v1/secrets":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"secrets":[{"id":"1","name":"prod/db"}],"total":1}`))
		case r.Method == http.MethodPut && r.URL.EscapedPath() == "/proxy/api/v1/secrets/prod%2Fdb":
			if err := json.NewDecoder(r.Body).Decode(&updateBody); err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","name":"prod/db"}`))
		case r.Method == http.MethodDelete && r.URL.EscapedPath() == "/proxy/api/v1/jks-keystores/store/entries/release%2Fkey":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, r.Method+" "+r.URL.EscapedPath(), http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewClient(&Config{APIURL: server.URL + "/proxy/api/v1", APIKey: "sk_test"})
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := client.Secrets.List(context.Background(), nil)
	if err != nil || len(secrets) != 1 || secrets[0].Name != "prod/db" {
		t.Fatalf("Secrets.List() = %#v, %v", secrets, err)
	}
	_, err = client.Secrets.Update(context.Background(), "prod/db", &SecretUpdateRequest{Data: map[string]string{"value": "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if updateBody["name"] != "prod/db" {
		t.Fatalf("update body did not include required name: %#v", updateBody)
	}
	if err := client.JKS.DeleteEntry(context.Background(), "store", "release/key"); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientRequiresAPIKey(t *testing.T) {
	if _, err := NewClient(nil); err == nil {
		t.Fatal("NewClient(nil) accepted an empty API key")
	}
}
