package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listSigningKeysInput struct {
	Backend string `json:"backend" jsonschema:"Signing backend: pkcs11 or ehsm"`
}

type listSigningKeysOutput struct {
	Keys []SigningKey `json:"keys"`
}

type signInput struct {
	Backend string `json:"backend" jsonschema:"Signing backend: pkcs11 or ehsm"`
	KeyID   string `json:"key_id" jsonschema:"Opaque key identifier returned by list_key_metadata"`
	Message string `json:"message" jsonschema:"Base64-encoded message, at most 1 MiB decoded"`
	Purpose string `json:"purpose" jsonschema:"Human-readable audit purpose for this signing operation"`
}

func main() {
	client, err := NewClient(os.Getenv("SECRETSERVER_URL"), os.Getenv("SECRETSERVER_TOKEN_FILE"))
	if err != nil {
		log.Fatalf("initialize SecretServer MCP bridge: %v", err)
	}
	defer client.Close()

	server := mcp.NewServer(&mcp.Implementation{Name: "secretserver-key-ecosystem", Version: "1.0.0"}, nil)
	closedWorld := false
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_key_metadata",
		Description: "List non-exportable signing-key metadata from a configured HSM or smart card. Returns no private material.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input listSigningKeysInput) (*mcp.CallToolResult, listSigningKeysOutput, error) {
		keys, err := client.ListSigningKeys(ctx, input.Backend)
		if err != nil {
			return toolError(err), listSigningKeysOutput{}, nil
		}
		return nil, listSigningKeysOutput{Keys: keys}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "sign_with_key",
		Description: "Sign a base64 message inside an HSM or smart card. The private key is never exported and the purpose is audited.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: boolPointer(false), IdempotentHint: true, OpenWorldHint: &closedWorld},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input signInput) (*mcp.CallToolResult, SignResult, error) {
		result, err := client.Sign(ctx, input.Backend, input.KeyID, input.Message, input.Purpose)
		if err != nil {
			return toolError(err), SignResult{}, nil
		}
		return nil, *result, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Printf("MCP server stopped: %v", err)
	}
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("operation failed: %v", err)}}}
}

func boolPointer(value bool) *bool { return &value }
