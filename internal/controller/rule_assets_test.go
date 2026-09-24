// This file verifies rule namespace boundaries and user-over-system precedence in the editor.
// 本文件验证规则编辑器的命名空间边界及用户优先于系统的覆盖语义。
package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestRuleAssetEditorAndCommit preserves exact text and commits only the selected rule overlay.
// TestRuleAssetEditorAndCommit 保留原始文本，并且只提交用户选中的规则覆盖文件。
func TestRuleAssetEditorAndCommit(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	rule := "prompts/default_cn/precheck_l1_main.md"
	path := filepath.Join(plan.ConfigRoot, filepath.FromSlash(rule))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("stage failed")
	}
	result, err := controller.OpenConfigFields(context.Background(), tui.ConfigFieldsRequest{Prefix: "@rules"})
	if err != nil || len(result.Fields) != 1 || !result.Fields[0].RuleAsset || result.Fields[0].Value != "existing\n" {
		t.Fatalf("rules = %+v, error = %v", result, err)
	}
	result.Fields[0].Value = "  changed\n\n"
	result.Fields[0].Changed = true
	plan.ConfigFields = result.Fields
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("rule commit failed")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "  changed\n\n" {
		t.Fatal("rule content changed or was not committed")
	}
}

// TestRuleAssetPrecedenceAndBoundary verifies user overrides and rejects files outside the three supported namespaces.
// TestRuleAssetPrecedenceAndBoundary 验证用户覆盖，并拒绝三类受支持命名空间以外的文件。
func TestRuleAssetPrecedenceAndBoundary(t *testing.T) {
	system, user := t.TempDir(), t.TempDir()
	for directory, value := range map[string]string{system: "system", user: "user"} {
		if err := os.MkdirAll(filepath.Join(directory, "noise_rules"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "noise_rules", "common.json"), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fields, err := readRuleAssets(system, user)
	if err != nil || len(fields) != 1 || fields[0].Value != "user" {
		t.Fatal("user rule did not override system rule")
	}
	for _, relative := range []string{".env", "config.yaml", "noise_rules/../../.env", "noise_rules/file:stream", "noise_rules\\common.json", "/prompts/file.md"} {
		if validRuleAssetPath(relative) {
			t.Fatalf("unsafe rule path accepted: %s", relative)
		}
	}
}
