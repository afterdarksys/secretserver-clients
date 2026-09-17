package main

import (
	"context"
	"encoding/json"
	"fmt"
	ss "github.com/afterdarksys/secretserver-go/secretserver"
	"os"
)

func main() {
	c, e := ss.NewClient(&ss.Config{APIURL: os.Getenv("SS_LIVE_URL"), APIKey: os.Getenv("SS_LIVE_KEY")})
	must(e)
	ctx := context.Background()
	name := "go-live"
	container := os.Getenv("SS_LIVE_CONTAINER")
	_, e = c.Secrets.Create(ctx, &ss.SecretCreateRequest{Name: name, Data: map[string]string{"value": "first"}, ContainerID: &container})
	must(e)
	v, e := c.Secrets.Get(ctx, name, nil)
	must(e)
	if v.Data["value"] != "first" {
		panic("read mismatch")
	}
	var envelope struct {
		Data map[string]string `json:"data"`
	}
	_, e = c.Call(ctx, "GET", "/s/prod/"+name, nil, &envelope)
	must(e)
	if envelope.Data["value"] != "first" {
		panic("path mismatch")
	}
	_, e = c.Secrets.Update(ctx, name, &ss.SecretUpdateRequest{Data: map[string]string{"value": "second"}, ContainerID: &container})
	must(e)
	v, e = c.Secrets.Get(ctx, name, nil)
	must(e)
	if v.Data["value"] != "second" {
		panic("update mismatch")
	}
	_, e = c.AssignVariable(ctx, "GO_LIVE", ss.VariableAssignment{SecretType: "secret", SecretID: v.ID, Field: "value"})
	must(e)
	rendered, e := c.Render(ctx, "x=%%GO_LIVE%%")
	must(e)
	if rendered != "x=second" {
		panic("render mismatch")
	}
	document, e := c.ResolveDocument(ctx, json.RawMessage(`{"password":"%%GO_LIVE%%","count":2}`))
	must(e)
	var doc map[string]interface{}
	must(json.Unmarshal(document, &doc))
	if doc["password"] != "second" || doc["count"] != float64(2) {
		panic("document mismatch")
	}
	_, e = c.GetVariable(ctx, "GO_LIVE")
	must(e)
	_, e = c.ListVariables(ctx)
	must(e)
	must(c.DeleteVariable(ctx, "GO_LIVE"))
	must(c.Secrets.Delete(ctx, name))
	fmt.Println("Go live contract PASS")
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
