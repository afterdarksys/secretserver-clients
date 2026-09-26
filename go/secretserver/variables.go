package secretserver

import (
	"context"
	"encoding/json"
	"errors"
)

// Variable is a field assignment; it contains no secret value.
type Variable struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SecretType string `json:"secret_type"`
	SecretID   string `json:"secret_id"`
	Field      string `json:"field"`
}
type VariableAssignment struct {
	SecretType string `json:"secret_type"`
	SecretID   string `json:"secret_id"`
	Field      string `json:"field"`
}

func (c *Client) variablesCall(ctx context.Context, method, path string, body, out any) error {
	_, err := c.Call(ctx, method, path, body, out)
	return err
}
func (c *Client) AssignVariable(ctx context.Context, name string, assignment VariableAssignment) (*Variable, error) {
	p, err := seg(name)
	if err != nil {
		return nil, err
	}
	var v Variable
	err = c.variablesCall(ctx, "PUT", "/variables/"+p, assignment, &v)
	return &v, err
}
func (c *Client) GetVariable(ctx context.Context, name string) (*Variable, error) {
	p, err := seg(name)
	if err != nil {
		return nil, err
	}
	var v Variable
	err = c.variablesCall(ctx, "GET", "/variables/"+p, nil, &v)
	return &v, err
}
func (c *Client) ListVariables(ctx context.Context) ([]Variable, error) {
	var out struct {
		Variables []Variable `json:"variables"`
	}
	err := c.variablesCall(ctx, "GET", "/variables", nil, &out)
	return out.Variables, err
}
func (c *Client) DeleteVariable(ctx context.Context, name string) error {
	p, err := seg(name)
	if err != nil {
		return err
	}
	return c.variablesCall(ctx, "DELETE", "/variables/"+p, nil, nil)
}
func (c *Client) Render(ctx context.Context, template string) (string, error) {
	var out struct {
		Rendered *string `json:"rendered"`
	}
	if err := c.variablesCall(ctx, "POST", "/variables/resolve", map[string]string{"template": template}, &out); err != nil {
		return "", err
	}
	if out.Rendered == nil {
		return "", errors.New("invalid rendered response")
	}
	return *out.Rendered, nil
}
func (c *Client) ResolveDocument(ctx context.Context, document json.RawMessage) (json.RawMessage, error) {
	var out struct {
		Document json.RawMessage `json:"document"`
	}
	if !json.Valid(document) {
		return nil, errors.New("invalid JSON document")
	}
	if err := c.variablesCall(ctx, "POST", "/variables/resolve", map[string]json.RawMessage{"document": document}, &out); err != nil {
		return nil, err
	}
	if len(out.Document) == 0 {
		return nil, errors.New("invalid document response")
	}
	return out.Document, nil
}
