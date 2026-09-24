// Package configedit tests comment-preserving, schema-directed YAML draft edits.
// configedit 包测试保留注释并按明确路径编辑 YAML 草稿的行为。
package configedit

import (
	"errors"
	"strings"
	"testing"
)

// TestGetStructuredReturnsExistingCollection verifies complete editable YAML is loaded from the draft.
// TestGetStructuredReturnsExistingCollection 验证草稿能够载入现有集合的完整可编辑 YAML。
func TestGetStructuredReturnsExistingCollection(t *testing.T) {
	draft, err := Parse([]byte("llm:\n  routes:\n    - name: first\n      model: chat-1\nembedding:\n  dimensions: 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := draft.GetStructured("llm.routes", StructuredArray)
	if err != nil || !strings.Contains(routes, "name: first") || !strings.Contains(routes, "model: chat-1") {
		t.Fatalf("routes = %q, error = %v", routes, err)
	}
	embedding, err := draft.GetStructured("embedding", StructuredObject)
	if err != nil || !strings.Contains(embedding, "dimensions: 3") {
		t.Fatalf("embedding = %q, error = %v", embedding, err)
	}
	if _, err := draft.GetStructured("llm.routes", StructuredObject); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("mismatched kind error = %v", err)
	}
}

// TestParseSetPreservesCommentsOrderAndAnchors checks edits retain unknown YAML structure and source bytes.
// TestParseSetPreservesCommentsOrderAndAnchors 检查编辑保留未知 YAML 结构和原始字节。
func TestParseSetPreservesCommentsOrderAndAnchors(t *testing.T) {
	source := []byte("# top comment\nfirst: old\nllm:\n  # route comment\n  routes: []\nx-defaults: &defaults\n  timeout: 10s\nx-reference: *defaults\n")
	draft, err := Parse(source)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	original := draft.Original()
	original[0] = 'x'
	if string(draft.Original()) != string(source) {
		t.Fatal("Original() exposed the draft's source buffer")
	}
	if err := draft.Set("llm.provider.name", ScalarString, "openai"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	value, err := draft.Get("llm.provider.name")
	if err != nil || value.Tag != "!!str" || value.Value != "openai" {
		t.Fatalf("Get() = %#v, %v; want string openai", value, err)
	}
	aliasValue, err := draft.Get("x-reference.timeout")
	if err != nil || aliasValue.Value != "10s" {
		t.Fatalf("Get() through alias = %#v, %v; want 10s", aliasValue, err)
	}
	rendered, err := draft.Render()
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	renderedText := string(rendered)
	for _, retained := range []string{"# top comment", "# route comment", "x-defaults: &defaults", "x-reference: *defaults", "timeout: 10s"} {
		if !strings.Contains(renderedText, retained) {
			t.Errorf("Render() lost %q:\n%s", retained, renderedText)
		}
	}
	if strings.Index(renderedText, "first:") > strings.Index(renderedText, "llm:") || strings.Index(renderedText, "llm:") > strings.Index(renderedText, "x-defaults:") {
		t.Errorf("Render() changed existing mapping order:\n%s", renderedText)
	}
	if strings.Index(renderedText, "routes:") > strings.Index(renderedText, "provider:") {
		t.Errorf("Render() did not append new mapping keys after existing keys:\n%s", renderedText)
	}
	if !strings.Contains(renderedText, `name: "openai"`) {
		t.Errorf("Render() lost a newly-created nested mapping value:\n%s", renderedText)
	}
	if _, err := Parse(rendered); err != nil {
		t.Fatalf("Parse(Render()) error = %v\n%s", err, renderedText)
	}
}

// TestConsecutiveMissingScalarSetsRender verifies separate field edits remain in the serialized document.
// TestConsecutiveMissingScalarSetsRender 验证连续字段编辑都会保留在序列化文档中。
func TestConsecutiveMissingScalarSetsRender(t *testing.T) {
	draft, err := Parse([]byte("# keep this comment\nx-extra: 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := draft.Set("storage.mode", ScalarString, "native"); err != nil {
		t.Fatal(err)
	}
	if err := draft.Set("storage.local_data_root", ScalarString, "/var/lib/vmm"); err != nil {
		t.Fatal(err)
	}
	rendered, err := draft.Render()
	if err != nil {
		t.Fatal(err)
	}
	text := string(rendered)
	for _, want := range []string{"# keep this comment", "x-extra: 3", "storage:", `mode: "native"`, `local_data_root: "/var/lib/vmm"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("Render() lost %q after consecutive Set calls:\n%s", want, text)
		}
	}
}

// TestSetStructuredCreatesProviderObjectsAndArrays checks explicit object and array insertion.
// TestSetStructuredCreatesProviderObjectsAndArrays 检查显式创建对象和数组。
func TestSetStructuredCreatesProviderObjectsAndArrays(t *testing.T) {
	draft, err := Parse([]byte("llm: {}\nembedding: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := draft.SetStructured("llm.routes", StructuredArray, []byte("- provider: alpha\n  model: chat-1\n")); err != nil {
		t.Fatalf("SetStructured(llm.routes) error = %v", err)
	}
	if err := draft.SetStructured("embedding", StructuredObject, []byte("provider: local\ndimensions: 3\n")); err != nil {
		t.Fatalf("SetStructured(embedding) error = %v", err)
	}
	if err := draft.SetStructured("rerank.routes", StructuredArray, []byte("- provider: beta\n")); err != nil {
		t.Fatalf("SetStructured(rerank.routes) error = %v", err)
	}
	for path, want := range map[string]string{
		"llm.routes[0].provider":    "alpha",
		"embedding.provider":        "local",
		"rerank.routes[0].provider": "beta",
	} {
		value, err := draft.Get(path)
		if err != nil || value.Value != want {
			t.Errorf("Get(%q) = %#v, %v; want %q", path, value, err, want)
		}
	}
	if _, err := draft.Render(); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if err := draft.SetStructured("embedding", StructuredObject, []byte("- invalid\n")); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("SetStructured() wrong root kind error = %v; want ErrInvalidDocument", err)
	}
}

// TestStructuredEditsExpandEmptyFlowRoots checks newly-created configuration renders as block YAML.
// TestStructuredEditsExpandEmptyFlowRoots 检查新建配置以块状 YAML 输出。
func TestStructuredEditsExpandEmptyFlowRoots(t *testing.T) {
	draft, err := Parse([]byte("{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := draft.SetStructured("llm.routes", StructuredArray, []byte("- model: first\n")); err != nil {
		t.Fatal(err)
	}
	if err := draft.Set("llm.routes[0].model", ScalarString, "second"); err != nil {
		t.Fatal(err)
	}
	rendered, err := draft.Render()
	if err != nil {
		t.Fatal(err)
	}
	text := string(rendered)
	if !strings.Contains(text, "llm:\n  routes:\n    - model: \"second\"") {
		t.Fatalf("Render() did not retain structured edits in readable block YAML:\n%s", text)
	}
	if strings.Contains(text, "{llm:") {
		t.Fatalf("Render() retained an empty-root flow style after adding configuration:\n%s", text)
	}
}

// TestArraySetAndDeleteUsesExistingIndexes checks array edits do not invent indexes and deletion shifts items.
// TestArraySetAndDeleteUsesExistingIndexes 检查数组编辑不会虚构索引且删除后会顺移元素。
func TestArraySetAndDeleteUsesExistingIndexes(t *testing.T) {
	draft, err := Parse([]byte("items:\n  - name: one\n  - name: two\nsection:\n  a: 1\n  b: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := draft.Set("items[1].name", ScalarString, "second"); err != nil {
		t.Fatalf("Set() array item error = %v", err)
	}
	if err := draft.Delete("items[0]"); err != nil {
		t.Fatalf("Delete() array item error = %v", err)
	}
	if err := draft.Delete("section.a"); err != nil {
		t.Fatalf("Delete() mapping item error = %v", err)
	}
	value, err := draft.Get("items[0].name")
	if err != nil || value.Value != "second" {
		t.Fatalf("Get() after sequence deletion = %#v, %v; want second", value, err)
	}
	if _, err := draft.Get("section.a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() deleted mapping item error = %v; want ErrNotFound", err)
	}
	if err := draft.Delete("items[1]"); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("Delete() out-of-range error = %v; want ErrOutOfRange", err)
	}
	if err := draft.Set("items[3].name", ScalarString, "out-of-range"); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("Set() out-of-range error = %v; want ErrOutOfRange", err)
	}
}

// TestInvalidPathsAndMissingArrayPositions checks malformed paths and ambiguous implicit array creation.
// TestInvalidPathsAndMissingArrayPositions 检查非法路径和含糊的隐式数组创建。
func TestInvalidPathsAndMissingArrayPositions(t *testing.T) {
	for _, path := range []string{"", ".a", "a.", "a..b", "a[]", "a[-1]", "a[1x]", "a[0]b", "a.0", "a[999999999999999999999999999999999999]"} {
		if _, err := parsePath(path); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("parsePath(%q) error = %v; want ErrInvalidPath", path, err)
		}
	}
	draft, err := Parse([]byte("root: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := draft.Set("root.missing[0].name", ScalarString, "x"); !errors.Is(err, ErrUnknownPosition) {
		t.Fatalf("Set() missing sequence error = %v; want ErrUnknownPosition", err)
	}
	if err := draft.Set("root.child.name", ScalarString, "x"); err != nil {
		t.Fatalf("Set() missing map chain error = %v", err)
	}
}

// TestDuplicateKeysAndMultipleDocumentsAreRejected checks ambiguity is rejected at parse time.
// TestDuplicateKeysAndMultipleDocumentsAreRejected 检查解析阶段拒绝歧义结构。
func TestDuplicateKeysAndMultipleDocumentsAreRejected(t *testing.T) {
	for _, source := range []string{
		"a: 1\na: 2\n",
		"outer:\n  nested: 1\n  nested: 2\n",
		"a: 1\n---\nb: 2\n",
		"a: 1\n---\n",
	} {
		_, err := Parse([]byte(source))
		if err == nil {
			t.Errorf("Parse(%q) succeeded; want rejection", source)
		}
		if strings.Contains(source, "---") && !errors.Is(err, ErrMultipleDocuments) {
			t.Errorf("Parse(%q) error = %v; want ErrMultipleDocuments", source, err)
		}
	}
	if _, err := Parse([]byte("a: 1\na: 2\n")); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate key error = %v; want ErrDuplicateKey", err)
	}
}

// TestScalarTypesAreExplicitAndValidated checks scalar kinds are never guessed from input text.
// TestScalarTypesAreExplicitAndValidated 检查标量类型始终由调用方指定且严格校验。
func TestScalarTypesAreExplicitAndValidated(t *testing.T) {
	draft, err := Parse([]byte("values: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	valid := []struct {
		path string
		kind ScalarType
		text string
		tag  string
	}{
		{"values.name", ScalarString, "true", "!!str"},
		{"values.enabled", ScalarBool, "true", "!!bool"},
		{"values.count", ScalarInt, "42", "!!int"},
		{"values.ratio", ScalarNumber, "1.25e2", "!!float"},
		{"values.timeout", ScalarDuration, "250ms", "!!str"},
	}
	for _, item := range valid {
		if err := draft.Set(item.path, item.kind, item.text); err != nil {
			t.Errorf("Set(%q) error = %v", item.path, err)
			continue
		}
		value, err := draft.Get(item.path)
		if err != nil || value.Tag != item.tag {
			t.Errorf("Get(%q) = %#v, %v; want tag %s", item.path, value, err, item.tag)
		}
	}
	for _, item := range []struct {
		kind ScalarType
		text string
	}{
		{ScalarBool, "maybe"},
		{ScalarInt, "1.5"},
		{ScalarNumber, "NaN"},
		{ScalarNumber, "0x1p2"},
		{ScalarDuration, "several"},
		{ScalarType("guess"), "1"},
	} {
		if _, err := makeScalar(item.kind, item.text); err == nil {
			t.Errorf("makeScalar(%q, %q) succeeded; want validation error", item.kind, item.text)
		}
	}
	if err := draft.Set("values.name", ScalarInt, "invalid"); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("Set() invalid value error = %v; want ErrInvalidValue", err)
	}
	unchanged, err := draft.Get("values.name")
	if err != nil || unchanged.Value != "true" || unchanged.Tag != "!!str" {
		t.Fatalf("invalid Set() changed prior value: %#v, %v", unchanged, err)
	}
}

// TestDeleteCannotLeaveDanglingAliases checks anchor targets cannot be removed while referenced.
// TestDeleteCannotLeaveDanglingAliases 检查被引用的锚点目标不能被删除。
func TestDeleteCannotLeaveDanglingAliases(t *testing.T) {
	draft, err := Parse([]byte("defaults: &defaults\n  timeout: 5s\ncopy: *defaults\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := draft.Delete("defaults"); !errors.Is(err, ErrAliasReference) {
		t.Fatalf("Delete() anchor target error = %v; want ErrAliasReference", err)
	}
	value, err := draft.Get("copy.timeout")
	if err != nil || value.Value != "5s" {
		t.Fatalf("failed Delete() changed alias target: %#v, %v", value, err)
	}
}
