// This file verifies preserved installed configuration and explicit rollback through the controller transaction.
// 本文件通过控制器事务验证已安装配置保留及明确回滚行为。
package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configedit"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/install"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 2 {
		if err := controller.stagePackage(ctx, plan, make(chan tui.OperationEvent, 32)); err != nil {
			t.Fatalf("restaging reused its own held lock: %v", err)
		}
	}
}
