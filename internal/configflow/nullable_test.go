// These tests verify schema-authorized null writes preserve YAML identity and remain distinct from zero and text.
// 这些配置流程测试验证 schema 授权的空值写入保留 YAML 身份，并与零和文本保持区别。
package configflow

import (
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configedit"
)

// TestNullableScalarRoundTrip checks explicit null, scalar replacement, anchors, comments, and rejected non-nullable writes.
// TestNullableScalarRoundTrip 检查显式空值、标量替换、锚点、注释及拒绝不可为空字段的写入。
func TestNullableScalarRoundTrip(t *testing.T) {
	schema := configbridge.Schema{Version: "v1", ConfigType: "Config", Fields: []configbridge.Field{
		{Path: "threshold", Type: "number", Nullable: true},
		{Path: "required", Type: "integer"},
		{Path: "label", Type: "string"},
	}}
	editor, err := New(schema, []byte("threshold: &threshold 0.5 # keep this\nalias: *threshold\nrequired: 1\nlabel: existing\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := editor.SetNull("required"); err == nil {
		t.Fatal("non-nullable integer accepted null")
	}
	if err := editor.SetNull("threshold"); err != nil {
		t.Fatal(err)
	}
	if err := editor.SetScalar("label", "null"); err != nil {
		t.Fatal(err)
	}
	encoded, err := editor.Render()
	if err != nil || !strings.Contains(string(encoded), "# keep this") || !strings.Contains(string(encoded), "&threshold") {
		t.Fatalf("metadata lost: %s %v", encoded, err)
	}
	draft, err := configedit.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"threshold", "alias"} {
		scalar, err := draft.Get(path)
		if err != nil || scalar.Tag != "!!null" {
			t.Fatalf("null identity lost at %s: %+v %v", path, scalar, err)
		}
	}
	label, err := draft.Get("label")
	if err != nil || label.Tag != "!!str" || label.Value != "null" {
		t.Fatalf("literal null text changed type: %+v %v", label, err)
	}
	if err := editor.SetScalar("threshold", "0"); err != nil {
		t.Fatal(err)
	}
	encoded, err = editor.Render()
	if err != nil {
		t.Fatal(err)
	}
	draft, err = configedit.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	scalar, err := draft.Get("threshold")
	if err != nil || scalar.Tag != "!!float" || scalar.Value != "0" {
		t.Fatalf("zero was not restored: %+v %v", scalar, err)
	}
}
