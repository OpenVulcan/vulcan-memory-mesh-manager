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

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/service"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestFirstInstallStartsAndChecksHealth verifies success means the selected runtime actually became ready.
// TestFirstInstallStartsAndChecksHealth 验证首次安装成功意味着所选运行方式实际启动并就绪。
func TestFirstInstallStartsAndChecksHealth(t *testing.T) {
	for _, mode := range []tui.ServiceMode{tui.ServiceModeForeground, tui.ServiceModeService} {
		t.Run(string(mode), func(t *testing.T) {
			controller, plan, _ := newFixtureController(t)
			plan.ServiceMode = mode
			process := controller.process.(*fakeProcess)
			adapter := &fakeService{status: service.Status{State: "stopped", AutoStart: "false"}}
			if mode == tui.ServiceModeService {
				plan.ServiceUser = currentServiceUser(t)
				controller.options.ServiceFactory = func(string) (ServiceClient, error) { return adapter, nil }
			}
			checks := 0
			controller.options.WaitHealthy = func(context.Context, string, string) error { checks++; return nil }
			for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
				if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
					t.Fatalf("first install failed at %s", kind)
				}
			}
			snapshot, err := controller.Snapshot(context.Background())
			if err != nil || !snapshot.Installed || snapshot.Incomplete || !snapshot.Running || checks != 1 {
				t.Fatalf("first install did not reach healthy running state: %+v, checks=%d, err=%v", snapshot, checks, err)
			}
			if mode == tui.ServiceModeService && (!adapter.called("install") || !adapter.called("start")) {
				t.Fatalf("service was not registered and started: %v", adapter.calls)
			}
			if mode == tui.ServiceModeForeground && !process.called("start") {
				t.Fatalf("foreground process was not started: %v", process.calls)
			}
		})
	}
}

// TestUnhealthyFirstInstallIsNotReportedComplete verifies readiness failure undoes the first install.
// TestUnhealthyFirstInstallIsNotReportedComplete 验证首次安装就绪失败时撤回安装且不报告完成。
func TestUnhealthyFirstInstallIsNotReportedComplete(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	process := controller.process.(*fakeProcess)
	controller.options.WaitHealthy = func(context.Context, string, string) error { return errors.New("unreachable") }
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("package staging failed")
	}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})) != tui.OperationEventFailed {
		t.Fatal("unhealthy first install reported success")
	}
	snapshot, err := controller.Snapshot(context.Background())
	if err != nil || snapshot.Installed || process.running {
		t.Fatalf("unhealthy first install was retained as running installation: %+v, %v", snapshot, err)
	}
	binaryPath := filepath.Join(plan.ProgramRoot, filepath.FromSlash(controller.identity.VMMExecutablePath))
	if _, err := os.Stat(binaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unhealthy first install left a managed binary: %v", err)
	}
}

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
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationService, TargetMode: tui.ServiceModeForeground, ServiceAction: tui.ServiceActionStop})) != tui.OperationEventCompleted {
		t.Fatal("foreground runtime could not be stopped before explicit start")
	}
	controller.options.WaitHealthy = func(context.Context, string, string) error { return errors.New("unreachable") }
	events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationService, TargetMode: tui.ServiceModeForeground, ServiceAction: tui.ServiceActionStart})
	if terminalKind(events) != tui.OperationEventFailed {
		t.Fatal("unhealthy explicit start reported success")
	}
}
