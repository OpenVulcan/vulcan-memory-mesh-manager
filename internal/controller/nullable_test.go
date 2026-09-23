// These tests verify null intent survives field reloads and remains authorized by the runtime schema.
// 这些控制器测试验证空值意图在字段重载后保留，并始终受运行时 schema 授权约束。
package controller

import (
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configflow"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestNullableFieldMetadataAndAuthority checks null aliases, pending overlays, and forged client metadata.
// TestNullableFieldMetadataAndAuthority 检查空值别名、待定覆盖与伪造客户端元数据，确保权威清单决定合法性。
func TestNullableFieldMetadataAndAuthority(t *testing.T) {
	schema := configbridge.Schema{Version: "v1", ConfigType: "Config", Fields: []configbridge.Field{{Path: "threshold", Type: "number", Nullable: true}, {Path: "required", Type: "integer"}}}
	fields, err := displayFields(schema, []byte("threshold: ~\nrequired: 1\n"), "")
	if err != nil || !fields[0].Nullable || !fields[0].Null || fields[0].Value != "null" {
		t.Fatalf("null metadata lost: %+v %v", fields, err)
	}
	pending := fields[0]
	pending.Changed = true
	fresh, err := displayFields(schema, []byte("threshold: 0.5\nrequired: 1\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	merged := overlayConfigFields(fresh, []tui.ConfigField{pending})
	if !merged[0].Null || !merged[0].Nullable || !merged[0].Changed {
		t.Fatal("pending null lost during editor reload")
	}
	editor, err := configflow.New(schema, []byte("threshold: 0.5\nrequired: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := setEditorField(editor, schema, pending); err != nil {
		t.Fatal(err)
	}
	if err := setEditorField(editor, schema, tui.ConfigField{Path: "required", Nullable: true, Null: true}); err == nil {
		t.Fatal("forged nullable flag bypassed runtime schema")
	}
}
