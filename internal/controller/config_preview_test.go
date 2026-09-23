// These tests verify candidate previews detect real changes while keeping credentials out of UI events.
// 这些控制器测试验证候选预览能够识别真实变化，同时不向界面事件泄露凭据。
package controller

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestConfigPreviewIncludesRemovedRoutesAndRedactsChangedSecrets covers both sides of schema expansion and hidden-value changes.
// TestConfigPreviewIncludesRemovedRoutesAndRedactsChangedSecrets 覆盖两侧 schema 展开及秘密值变化，失败时报告差异。
func TestConfigPreviewIncludesRemovedRoutesAndRedactsChangedSecrets(t *testing.T) {
	schema := configbridge.Schema{Fields: []configbridge.Field{
		{Path: "llm.routes", Type: "array"},
		{Path: "llm.routes[].model", Type: "string"},
		{Path: "llm.routes[].key", Type: "string", Sensitive: true},
		{Path: "grpc.port", Type: "int"},
		{Path: "label", Type: "string"},
	}}
	before := []byte("llm:\n  routes:\n    - model: first\n      key: OLD_SECRET\n    - model: second\n      key: REMOVED_SECRET\ngrpc:\n  port: 1234\n")
	after := []byte("llm:\n  routes:\n    - model: first\n      key: NEW_SECRET\ngrpc:\n  port: 5678\nlabel: ''\n")
	changes, err := previewConfigChanges(schema, before, after)
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string]tui.ConfigChange)
	for _, change := range changes {
		byPath[change.Path] = change
	}
	if len(changes) != 5 || byPath["llm.routes[1].model"].Kind != "removed" || byPath["label"].Kind != "added" || byPath["grpc.port"].Before != "1234" || byPath["grpc.port"].After != "5678" {
		t.Fatalf("unexpected changes: %+v", changes)
	}
	if byPath["llm.routes[0].key"].Before != "<redacted>" || byPath["llm.routes[0].key"].After != "<redacted>" {
		t.Fatal("changed secret was missed or exposed")
	}
	encoded, _ := json.Marshal(changes)
	if strings.Contains(string(encoded), "SECRET") {
		t.Fatal("raw secret reached preview")
	}
	unchanged, err := previewConfigChanges(schema, after, after)
	if err != nil || len(unchanged) != 0 {
		t.Fatalf("unchanged configuration produced changes: %+v %v", unchanged, err)
	}
}

// TestValidatedPreviewIncludesCredentialNamesOnly exercises the actual staged validation event and verifies no configuration commit occurs.
// TestValidatedPreviewIncludesCredentialNamesOnly 执行实际暂存校验事件，仅允许凭据名称出现，并保持候选流程不提交配置。
func TestValidatedPreviewIncludesCredentialNamesOnly(t *testing.T) {
	c, plan, _ := newFixtureController(t)
	defer c.discardStaged()
	plan.Providers.CredentialUpdates = []tui.CredentialUpdate{{EnvironmentName: "VMMM_PREVIEW_KEY", Value: "PREVIEW_SECRET"}}
	plan.ConfigFields = []tui.ConfigField{{Path: "noise_rules/test.json", Value: "{\"private\":\"RULE_SECRET\"}", RuleAsset: true, Editable: true, Changed: true}}
	if terminalKind(collectOperation(t, c, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("stage failed")
	}
	events := collectOperation(t, c, tui.OperationRequest{Kind: tui.OperationValidate, Plan: plan})
	if terminalKind(events) != tui.OperationEventCompleted {
		t.Fatalf("validation failed: %+v", events)
	}
	var preview *tui.ConfigPreview
	for _, event := range events {
		if event.Preview != nil {
			preview = event.Preview
		}
	}
	if preview == nil {
		t.Fatal("successful validation omitted preview")
	}
	encoded, _ := json.Marshal(preview)
	if strings.Contains(string(encoded), "SECRET") || !strings.Contains(string(encoded), "VMMM_PREVIEW_KEY") || !strings.Contains(string(encoded), "sha256:") {
		t.Fatalf("unsafe or incomplete preview: %s", encoded)
	}
	if _, exists := c.loadState(); exists {
		t.Fatal("preview committed an installation")
	}
}

// TestPreviewInheritsSensitiveParent prevents child metadata from exposing a secret-marked object.
// TestPreviewInheritsSensitiveParent 防止子字段元数据遗漏标记时暴露已标为敏感的父对象。
func TestPreviewInheritsSensitiveParent(t *testing.T) {
	schema := configbridge.Schema{Fields: []configbridge.Field{{Path: "secret", Type: "object", Sensitive: true}, {Path: "secret.value", Type: "string"}}}
	changes, err := previewConfigChanges(schema, []byte("secret: {value: old-secret}"), []byte("secret: {value: new-secret}"))
	if err != nil || len(changes) != 1 || changes[0].Before != "<redacted>" || changes[0].After != "<redacted>" {
		t.Fatalf("sensitive parent was not honored: %+v %v", changes, err)
	}
}

// TestPreviewReportsNewOverrideMatchingSystemRule distinguishes a new user-layer write from an unchanged effective rule.
// TestPreviewReportsNewOverrideMatchingSystemRule 区分新增用户覆盖写入与有效规则内容不变的情况。
func TestPreviewReportsNewOverrideMatchingSystemRule(t *testing.T) {
	c, plan, _ := newFixtureController(t)
	packageRoot := t.TempDir()
	rulePath := "noise_rules/test.json"
	content := []byte("{\"rules\":[]}")
	systemRule := filepath.Join(packageRoot, "configs", filepath.FromSlash(rulePath))
	if err := os.MkdirAll(filepath.Dir(systemRule), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(systemRule, content, 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err := c.configurationPreview(context.Background(), filepath.Join(packageRoot, "bin", "vmm-local"), plan, map[string][]byte{defaultConfigFileName: []byte("{}"), rulePath: content})
	if err != nil || len(preview.Changes) != 1 || preview.Changes[0].Path != rulePath || preview.Changes[0].Before != "" || preview.Changes[0].After == "" {
		t.Fatalf("new user override was omitted: %+v %v", preview, err)
	}
}
