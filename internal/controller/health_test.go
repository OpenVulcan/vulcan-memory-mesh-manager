// These controller tests cover readiness failure after a process has successfully started.
// 这些控制器测试覆盖进程成功启动之后的就绪检查失败。
package controller

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestHealthFailureRestoresUpgrade proves a started but unhealthy candidate cannot commit new configuration.
// TestHealthFailureRestoresUpgrade 证明已启动但不健康的候选实例不能提交新配置。
func TestHealthFailureRestoresUpgrade(t *testing.T) {
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
	process := &fakeProcess{running: true}
	controller.process = process
	controller.options.WaitHealthy = func(context.Context, string, string) error { return errors.New("unreachable") }
	plan.ConfigFields = []tui.ConfigField{{Path: "logging.directory", Type: "string", Value: filepath.Join(plan.DataRoot, "changed-logs"), Editable: true, Changed: true}}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("stage failed")
	}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})) != tui.OperationEventFailed {
		t.Fatal("unhealthy runtime reported success")
	}
	after, err := os.ReadFile(filepath.Join(plan.ConfigRoot, "config.yaml"))
	if err != nil || !bytes.Equal(before, after) || !process.running {
		t.Fatal("original configuration and running state were not restored")
	}
}

// TestLifecycleRejectsUnhealthyProcess checks explicit starts use the same readiness gate.
// TestLifecycleRejectsUnhealthyProcess 检查显式启动也经过相同的就绪门禁。
func TestLifecycleRejectsUnhealthyProcess(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatal("fixture installation failed")
		}
	}
	controller.options.WaitHealthy = func(context.Context, string, string) error { return errors.New("unreachable") }
	events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationService, TargetMode: tui.ServiceModeForeground, ServiceAction: tui.ServiceActionStart})
	if terminalKind(events) != tui.OperationEventFailed {
		t.Fatal("unhealthy explicit start reported success")
	}
}
