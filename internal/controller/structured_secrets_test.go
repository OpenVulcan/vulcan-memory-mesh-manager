// These controller tests verify that collection editing preserves the credential boundary.
// 这些控制器测试验证集合编辑保持凭据边界。
package controller

import (
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configflow"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestStructuredSecrets checks whole collections, nested nodes, and untouched sibling routes.
// TestStructuredSecrets 检查完整集合、嵌套节点和未修改的同级路由。
func TestStructuredSecrets(t *testing.T) {
	schema := configbridge.Schema{Version: "v1", ConfigType: "Config", Fields: []configbridge.Field{
		{Path: "llm.routes", Type: "array"},
		{Path: "llm.routes[].nodes", Type: "array"},
		{Path: "llm.routes[].api_keys", Type: "array", Sensitive: true},
		{Path: "llm.routes[].nodes[].api_keys", Type: "array", Sensitive: true},
	}}
	for _, test := range []struct {
		name, path, value string
		wantError         bool
	}{
		{"references", "llm.routes", "- api_keys: ['${KEY}']\n  nodes:\n    - api_keys: ['${NODE_KEY}']\n- api_keys: []\n", false},
		{"direct secret", "llm.routes", "- api_keys: [private-value]\n", true},
		{"nested secret", "llm.routes", "- nodes:\n    - api_keys: [private-value]\n", true},
		{"untouched sibling", "llm.routes[0].nodes", "- api_keys: ['${NODE_KEY}']\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			editor, err := configflow.New(schema, []byte("llm:\n  routes:\n    - nodes: []\n    - api_keys: [legacy-value]\n"))
			if err != nil {
				t.Fatal(err)
			}
			err = setEditorField(editor, schema, tui.ConfigField{Path: test.path, Value: test.value})
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected validation result: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "private-value") {
				t.Fatal("error exposed secret")
			}
		})
	}
}
