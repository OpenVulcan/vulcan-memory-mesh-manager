// This file verifies preserved installed configuration and explicit rollback through the controller transaction.
// 本文件通过控制器事务验证已安装配置保留及明确回滚行为。
package controller

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configedit"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configflow"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/install"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestProviderWizardPreservesUnrelatedAdvancedFields keeps throughput and ranking settings when a quick provider choice changes.
// TestProviderWizardPreservesUnrelatedAdvancedFields 验证快速切换供应商时保留无关的吞吐与排序高级设置。
func TestProviderWizardPreservesUnrelatedAdvancedFields(t *testing.T) {
	schema := testSchema()
	schema.Fields = append(schema.Fields,
		configbridge.Field{Path: "embedding.provider", Type: "string"},
		configbridge.Field{Path: "embedding.endpoint", Type: "string"},
		configbridge.Field{Path: "embedding.api_keys", Type: "array", Sensitive: true},
		configbridge.Field{Path: "embedding.model", Type: "string"},
		configbridge.Field{Path: "embedding.dimension", Type: "integer"},
		configbridge.Field{Path: "embedding.rpm", Type: "integer"},
		configbridge.Field{Path: "embedding.max_batch_size", Type: "integer"},
		configbridge.Field{Path: "rerank.enabled", Type: "boolean"},
		configbridge.Field{Path: "rerank.routes", Type: "array"},
		configbridge.Field{Path: "rerank.top_n", Type: "integer"},
	)
	before := []byte("embedding:\n  provider: openai\n  endpoint: https://old.example/v1\n  api_keys: [\"${OLD_KEY}\"]\n  model: old-model\n  dimension: 1024\n  rpm: 37\n  max_batch_size: 7\nrerank:\n  enabled: true\n  top_n: 14\n  routes:\n    - name: existing\n")
	editor, err := configflow.New(schema, before)
	if err != nil {
		t.Fatal(err)
	}
	plan := tui.ProviderPlan{Embedding: &tui.ProviderRoute{Provider: "google_ai_studio", Model: "gemini-embedding-001", Dimension: 768, APIKeyEnvironmentNames: []string{"NEW_KEY"}}, RerankConfigured: true}
	if err := applyProviderPlan(editor, plan); err != nil {
		t.Fatal(err)
	}
	after, err := editor.Render()
	if err != nil {
		t.Fatal(err)
	}
	draft, err := configedit.Parse(after)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"embedding.provider": "google_ai_studio", "embedding.endpoint": "", "embedding.model": "gemini-embedding-001", "embedding.dimension": "768", "embedding.rpm": "37", "embedding.max_batch_size": "7", "rerank.enabled": "false", "rerank.top_n": "14", "rerank.routes[0].name": "existing"} {
		value, err := draft.Get(path)
		if err != nil || value.Value != want {
			t.Fatalf("%s = %+v, %v; want %q", path, value, err, want)
		}
	}
	if !bytes.Contains(after, []byte("${NEW_KEY}")) || bytes.Contains(after, []byte("${OLD_KEY}")) {
		t.Fatal("embedding API key references were not replaced")
	}
}

// TestInstalledConfigurationPreservesCustomPaths ensures reopening the editor does not replace saved paths with defaults.
// TestInstalledConfigurationPreservesCustomPaths 确保重新打开编辑器不会把已保存路径替换为默认值。
func TestInstalledConfigurationPreservesCustomPaths(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatal("fixture installation failed")
		}
	}
	before, err := os.ReadFile(filepath.Join(plan.ConfigRoot, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	plan.StorageSettings = tui.StorageSettings{}
	files, err := controller.buildConfigFiles(context.Background(), plan, plan.ProgramRoot)
	if err != nil {
		t.Fatal(err)
	}
	old, err := configedit.Parse(before)
	if err != nil {
		t.Fatal(err)
	}
	current, err := configedit.Parse(files["config.yaml"])
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"sqlite.native.path", "lancedb.native.path", "logging.directory"} {
		want, oldErr := old.Get(path)
		got, currentErr := current.Get(path)
		if oldErr != nil || currentErr != nil || want != got {
			t.Fatalf("saved %s changed", path)
		}
	}
}

// TestExplicitRollbackReachesTransaction proves that an older verified package requires and retains explicit rollback intent.
// TestExplicitRollbackReachesTransaction 证明旧版校验包必须具有明确回滚意图，并将其传入事务。
func TestExplicitRollbackReachesTransaction(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatal("fixture installation failed")
		}
	}
	installed, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	installed.VMM.Tag = "v9.0.0"
	if err := state.Save(controller.options.StatePath, installed); err != nil {
		t.Fatal(err)
	}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})) != tui.OperationEventFailed {
		t.Fatal("ordinary upgrade accepted a downgrade")
	}
	plan.Rollback = true
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("explicit rollback was rejected")
	}
	if controller.stagedSnapshot().operation != install.OperationRollback {
		t.Fatal("rollback intent was lost")
	}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("rollback commit failed")
	}
}

// TestExplicitRerankDisable produces a patch for a deliberate disabled choice.
// TestExplicitRerankDisable 为明确禁用重排的选择生成实际修改。
func TestExplicitRerankDisable(t *testing.T) {
	configuration, selected := providerConfiguration(tui.ProviderPlan{RerankConfigured: true})
	if !selected || configuration.Rerank == nil || configuration.Rerank.Enabled {
		t.Fatal("explicit rerank disable was discarded")
	}
}

// TestRestagingReleasesPreviousLock covers going back to change source or paths after a successful package download.
// TestRestagingReleasesPreviousLock 覆盖下载成功后返回修改来源或路径时重新暂存的流程。
func TestRestagingReleasesPreviousLock(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	defer controller.discardStaged()
	// Windows CI may spend several seconds authenticating and extracting each real fixture archive.
	// Windows 持续集成对每个真实夹具包进行认证与解包可能需要数秒，保留足够余量检测实际锁死。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for range 2 {
		if err := controller.stagePackage(ctx, plan, make(chan tui.OperationEvent, 32)); err != nil {
			t.Fatalf("restaging reused its own held lock: %v", err)
		}
	}
}

// TestStartupFailureRestoresPreviousConfiguration checks the full controller boundary after candidate process startup fails.
// TestStartupFailureRestoresPreviousConfiguration 在候选进程启动失败后检查完整控制器恢复边界。
func TestStartupFailureRestoresPreviousConfiguration(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatal("fixture installation failed")
		}
	}
	before, err := os.ReadFile(filepath.Join(plan.ConfigRoot, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	previousState, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	process := &fakeProcess{running: true, startErrors: []error{errors.New("candidate startup failed"), nil}}
	controller.process = process
	plan.ConfigFields = []tui.ConfigField{{Path: "logging.directory", Type: "string", Value: filepath.Join(plan.DataRoot, "changed-logs"), Editable: true, Changed: true}}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("upgrade stage failed")
	}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})) != tui.OperationEventFailed {
		t.Fatal("failed startup was reported as success")
	}
	if after, err := os.ReadFile(filepath.Join(plan.ConfigRoot, "config.yaml")); err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed startup retained the candidate configuration")
	}
	if !process.running || len(process.startErrors) != 0 {
		t.Fatal("previous runtime was not restored")
	}
	recovered, err := state.Load(controller.options.StatePath)
	// A failed upgrade restores old files and the last successful check, but keeps the completion marker clear for explicit reinstall.
	// 升级失败后恢复旧文件和上一次通过时间，但完成标记保持未完成，要求显式重新安装。
	if err != nil || recovered.ConfigValidatedAt != previousState.ConfigValidatedAt || recovered.InstallationComplete {
		t.Fatalf("failed upgrade lost check history or claimed completion: %+v, error=%v", recovered, err)
	}
}
