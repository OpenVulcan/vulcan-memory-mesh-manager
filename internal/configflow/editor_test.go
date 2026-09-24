// editor_test.go verifies schema-checked YAML choices and unchanged unrelated overrides.
// editor_test.go 验证按模式清单编辑 YAML 选择，并保持无关覆盖内容不变。
package configflow

import (
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configedit"
)

// testSchema defines the VMM paths exercised by storage and advanced editing tests.
// testSchema 定义存储选择与高级编辑测试使用的 VMM 字段路径。
func testSchema() configbridge.Schema {
	paths := []configbridge.Field{
		{Path: "storage.mode", Type: "string", Enum: []string{"split", "controller", "native", "combined"}},
		{Path: "storage.local_data_root", Type: "string"},
		{Path: "storage.combined_provider", Type: "string", Enum: []string{"postgres"}},
		{Path: "sqlite.native.path", Type: "string"},
		{Path: "lancedb.native.path", Type: "string"},
		{Path: "postgres.flavor", Type: "string", Enum: []string{"standard", "paradedb"}},
		{Path: "postgres.dsn", Type: "string", Sensitive: true},
		{Path: "llm.routes", Type: "array", ItemType: "object"},
		{Path: "llm.routes[].model", Type: "string"},
		{Path: "llm.routes[].params", Type: "map", ValueType: "any"},
	}
	return configbridge.Schema{Version: "v1", ConfigType: "Config", Fields: paths}
}

// TestStorageMappingChecksRealSchema verifies the five choices use only declared VMM fields.
// TestStorageMappingChecksRealSchema 验证五种选择只使用 VMM 已声明的字段。
func TestStorageMappingChecksRealSchema(t *testing.T) {
	cases := []struct {
		name    string
		options StorageOptions
		want    map[string]string
	}{
		{"native", StorageOptions{Choice: StorageNative, NativeSQLitePath: "/data/m.db", NativeLanceDBPath: "/data/vector"}, map[string]string{"storage.mode": "native", "sqlite.native.path": "/data/m.db", "lancedb.native.path": "/data/vector"}},
		{"split", StorageOptions{Choice: StorageSplit, LocalDataRoot: "/data/local"}, map[string]string{"storage.mode": "split", "storage.local_data_root": "/data/local"}},
		{"controller", StorageOptions{Choice: StorageController, LocalDataRoot: "/data/local"}, map[string]string{"storage.mode": "controller", "storage.local_data_root": "/data/local"}},
		{"postgres", StorageOptions{Choice: StoragePostgres, PostgresDSNVariable: "VMMM_PG_DSN"}, map[string]string{"storage.mode": "combined", "postgres.flavor": "standard", "postgres.dsn": "${VMMM_PG_DSN}"}},
		{"paradedb", StorageOptions{Choice: StorageParadeDB, PostgresDSNVariable: "VMMM_PG_DSN"}, map[string]string{"storage.mode": "combined", "postgres.flavor": "paradedb", "postgres.dsn": "${VMMM_PG_DSN}"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			editor, err := New(testSchema(), []byte("# keep this comment\nx-extra: 3\n"))
			if err != nil {
				t.Fatal(err)
			}
			if err := editor.ApplyStorage(tc.options); err != nil {
				t.Fatal(err)
			}
			rendered, err := editor.Render()
			if err != nil {
				t.Fatal(err)
			}
			text := string(rendered)
			parsed, err := configedit.Parse(rendered)
			if err != nil {
				t.Fatal(err)
			}
			for path, want := range tc.want {
				actual, err := parsed.Get(path)
				if err != nil || actual.Value != want {
					t.Fatalf("%s = %q, err=%v; want %q", path, actual.Value, err, want)
				}
			}
			if !strings.Contains(text, "# keep this comment") || !strings.Contains(text, "x-extra: 3") {
				t.Fatalf("unrelated YAML changed: %s", text)
			}
		})
	}
}

// TestAdvancedFieldsRejectUnknownAndPreserveRoutes checks complete route edits and schema refusal.
// TestAdvancedFieldsRejectUnknownAndPreserveRoutes 检查完整路由编辑以及模式清单对未知字段的拒绝。
func TestAdvancedFieldsRejectUnknownAndPreserveRoutes(t *testing.T) {
	editor, err := New(testSchema(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := editor.SetStructured("llm.routes", []byte("- model: first\n")); err != nil {
		t.Fatal(err)
	}
	if err := editor.SetScalar("llm.routes[0].model", "second"); err != nil {
		t.Fatal(err)
	}
	if err := editor.SetStructured("llm.routes[0].params", []byte("reasoning_effort: none\n")); err != nil {
		t.Fatal(err)
	}
	if err := editor.SetScalar("unknown.path", "x"); err == nil {
		t.Fatal("unknown field accepted")
	}
	if err := editor.SetScalar("storage.mode", "imaginary"); err == nil {
		t.Fatal("invalid enum accepted")
	}
	rendered, err := editor.Render()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := configedit.Parse(rendered)
	if err != nil {
		t.Fatal(err)
	}
	model, err := parsed.Get("llm.routes[0].model")
	if err != nil || model.Value != "second" {
		t.Fatalf("route model = %q, err=%v", model.Value, err)
	}
	param, err := parsed.Get("llm.routes[0].params.reasoning_effort")
	if err != nil || param.Value != "none" {
		t.Fatalf("reasoning parameter = %q, err=%v", param.Value, err)
	}
}

// TestStorageRejectsMissingRuntimeField requires the selected binary to support local data roots.
// TestStorageRejectsMissingRuntimeField 要求所选 VMM 可执行文件真正支持本地数据根目录字段。
func TestStorageRejectsMissingRuntimeField(t *testing.T) {
	schema := testSchema()
	for index, field := range schema.Fields {
		if field.Path == "storage.local_data_root" {
			schema.Fields = append(schema.Fields[:index], schema.Fields[index+1:]...)
			break
		}
	}
	editor, err := New(schema, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := editor.ApplyStorage(StorageOptions{Choice: StorageSplit, LocalDataRoot: "/data/local"}); err == nil {
		t.Fatal("older VMM schema accepted unsupported data root")
	}
	rendered, err := editor.Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rendered), "storage:") {
		t.Fatalf("failed choice left partial fields: %s", rendered)
	}
}
