// This file checks the controller's candidate flow against an explicitly supplied real VMM validator.
// 本文件使用明确指定的真实 VMM 校验器检查控制器的候选配置流程。
package controller

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestCandidateWithRealVMM uses no network and no existing database; VMMM_TEST_VMM_BINARY selects the standard-layout validator.
// TestCandidateWithRealVMM 不访问网络及既有数据库；VMMM_TEST_VMM_BINARY 指定标准布局中的真实校验器。
func TestCandidateWithRealVMM(t *testing.T) {
	source := os.Getenv("VMMM_TEST_VMM_BINARY")
	if source == "" {
		t.Skip("set VMMM_TEST_VMM_BINARY to test the real candidate validator")
	}
	root := t.TempDir()
	binaryPath := filepath.Join(root, "bin", filepath.Base(source))
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(binaryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy validator: %v, %v", copyErr, closeErr)
	}
	configs := filepath.Join(root, "configs")
	if err := os.CopyFS(configs, os.DirFS(filepath.Join(filepath.Dir(filepath.Dir(source)), "configs"))); err != nil {
		t.Fatal(err)
	}
	// Exclude development overlays from the isolated package, matching the official package input policy.
	// 按正式包输入规则从隔离测试包排除开发覆盖文件。
	for _, name := range []string{"config.yaml", ".env"} {
		if err := os.Remove(filepath.Join(configs, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	controller, plan, _ := newFixtureController(t)
	controller.options.Validate = func(ctx context.Context, _ string, candidate string) (configbridge.ValidationResult, error) {
		client, err := configbridge.New(binaryPath, candidate)
		if err != nil {
			return configbridge.ValidationResult{}, err
		}
		return client.Validate(ctx)
	}
	plan.Providers = tui.ProviderPlan{
		LLMRoutes:         []tui.ProviderRoute{{Name: "test", Provider: "openai", Endpoint: "https://api.openai.com/v1", Model: "test-model", APIKeyEnvironmentNames: []string{"VMMM_TEST_KEY"}}},
		Embedding:         &tui.ProviderRoute{Provider: "openai", Endpoint: "https://api.openai.com/v1", Model: "test-embedding", Dimension: 1024, APIKeyEnvironmentNames: []string{"VMMM_TEST_KEY"}},
		CredentialUpdates: []tui.CredentialUpdate{{EnvironmentName: "VMMM_TEST_KEY", Value: "local-validation-only"}},
		RerankConfigured:  true,
	}
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationValidate, tui.OperationInstall} {
		events := collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})
		if terminalKind(events) != tui.OperationEventCompleted {
			t.Fatalf("real validator failed for %s: %+v", kind, events)
		}
		if kind == tui.OperationValidate {
			invalid := plan
			invalid.ConfigFields = []tui.ConfigField{{Path: "noise_rules/common.json", Value: "{invalid JSON", RuleAsset: true, Editable: true, Changed: true}}
			if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationValidate, Plan: invalid})) != tui.OperationEventFailed {
				t.Fatal("real validator accepted an invalid staged rule file")
			}
			if _, err := os.Stat(filepath.Join(plan.ConfigRoot, "noise_rules", "common.json")); !os.IsNotExist(err) {
				t.Fatal("invalid rule reached the installed configuration")
			}
		}
	}
}
