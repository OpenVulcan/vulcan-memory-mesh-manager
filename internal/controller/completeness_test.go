// These tests distinguish an intact stopped installation from interrupted or damaged files and exercise explicit reinstall.
// 这些测试区分完整但停止的安装与中断或损坏文件，并验证明确重新安装。
package controller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/service"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestIncompleteInstallationCanReinstall checks missing files, changed registered bytes, and an unfinished completion marker.
// TestIncompleteInstallationCanReinstall 检查文件缺失、已登记内容损坏及完成标记未写入三种情况。
func TestIncompleteInstallationCanReinstall(t *testing.T) {
	for _, damage := range []string{"missing", "changed", "unfinished"} {
		t.Run(damage, func(t *testing.T) {
			controller, plan, _ := newFixtureController(t)
			for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
				if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
					t.Fatal("fixture installation failed")
				}
			}
			before, err := controller.Snapshot(context.Background())
			if err != nil || !before.Installed || before.Incomplete || before.Running {
				t.Fatalf("stopped installation misclassified: %+v %v", before, err)
			}
			binaryPath := filepath.Join(plan.ProgramRoot, filepath.FromSlash(controller.identity.VMMExecutablePath))
			switch damage {
			case "missing":
				err = os.Remove(binaryPath)
			case "changed":
				err = os.WriteFile(binaryPath, []byte("damaged"), 0o755)
			case "unfinished":
				var saved state.State
				saved, err = state.Load(controller.options.StatePath)
				if err == nil {
					saved.InstallationComplete = false
					err = state.Save(controller.options.StatePath, saved)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := controller.Snapshot(context.Background())
			if err != nil || snapshot.Installed || !snapshot.Incomplete {
				t.Fatalf("incomplete installation misclassified: %+v %v", snapshot, err)
			}
			if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationService, ServiceAction: tui.ServiceActionStart, TargetMode: tui.ServiceModeForeground})) != tui.OperationEventFailed {
				t.Fatal("incomplete installation was started")
			}
			plan.Repair = true
			for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
				if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
					t.Fatalf("reinstall failed at %s", kind)
				}
			}
			snapshot, err = controller.Snapshot(context.Background())
			if err != nil || !snapshot.Installed || snapshot.Incomplete {
				t.Fatalf("reinstall did not complete: %+v %v", snapshot, err)
			}
		})
	}
}

// TestIncompleteServiceDoesNotExecuteDamagedProgram checks unavailable status and damaged bytes without invoking an untrusted CLI.
// TestIncompleteServiceDoesNotExecuteDamagedProgram 检查服务状态不可查与程序损坏，不调用不可信 CLI。
func TestIncompleteServiceDoesNotExecuteDamagedProgram(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatal("fixture installation failed")
		}
	}
	saved, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	saved.Service.Name = "VulcanMemoryMesh"
	if err := state.Save(controller.options.StatePath, saved); err != nil {
		t.Fatal(err)
	}
	adapter := &fakeService{status: service.Status{State: "stopped"}}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return adapter, nil }
	snapshot, err := controller.Snapshot(context.Background())
	if err != nil || !snapshot.Installed || snapshot.Running {
		t.Fatalf("stopped service misclassified: %+v %v", snapshot, err)
	}
	adapter.statusErr = errors.New("service query denied")
	snapshot, err = controller.Snapshot(context.Background())
	if err != nil || !snapshot.Incomplete || snapshot.Installed || snapshot.IntegrityIssue != "service-unverified" {
		t.Fatalf("unverified service misclassified: %+v %v", snapshot, err)
	}
	if err := os.Remove(filepath.Join(plan.ProgramRoot, filepath.FromSlash(controller.identity.VMMExecutablePath))); err != nil {
		t.Fatal(err)
	}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) {
		t.Fatal("damaged service executable must not be invoked")
		return nil, nil
	}
	snapshot, err = controller.Snapshot(context.Background())
	if err != nil || !snapshot.Incomplete || snapshot.ServiceMode != tui.ServiceModeService || snapshot.IntegrityIssue != "missing-program-files" {
		t.Fatalf("damaged service misclassified: %+v %v", snapshot, err)
	}
	plan.Repair = true
	if _, err := controller.pauseInstalledRuntime(context.Background(), saved, true, plan, nil); !errors.Is(err, ErrDamagedServiceControl) {
		t.Fatalf("repair did not report safe service boundary: %v", err)
	}
}

// TestFailedReinstallRefreshesOpenUI reports the pending marker after a failure occurring before file promotion.
// TestFailedReinstallRefreshesOpenUI 验证文件推广前的失败也会将未完成标记刷新到已经打开的界面。
func TestFailedReinstallRefreshesOpenUI(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatal("fixture installation failed")
		}
	}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})) != tui.OperationEventCompleted {
		t.Fatal("second package staging failed")
	}
	controller.process = &fakeProcess{statusErr: errors.New("cannot verify running process")}
	events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})
	if terminalKind(events) != tui.OperationEventFailed {
		t.Fatal("failed runtime check reported success")
	}
	var snapshot *tui.InstallationSnapshot
	for _, event := range events {
		if event.Snapshot != nil {
			snapshot = event.Snapshot
		}
	}
	if snapshot == nil || snapshot.Installed || !snapshot.Incomplete {
		t.Fatalf("open UI did not receive failed-install snapshot: %+v", snapshot)
	}
}

// TestMissingServiceCanBeReinstalled exercises an interrupted registration and both requested execution modes.
// TestMissingServiceCanBeReinstalled 验证服务注册中断后可重装为服务或命令行模式。
func TestMissingServiceCanBeReinstalled(t *testing.T) {
	for _, mode := range []tui.ServiceMode{tui.ServiceModeService, tui.ServiceModeForeground} {
		t.Run(string(mode), func(t *testing.T) {
			controller, plan, _ := newFixtureController(t)
			for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
				if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
					t.Fatal("fixture install failed")
				}
			}
			saved, err := state.Load(controller.options.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			saved.Service.Name = "VulcanMemoryMesh"
			saved.Service.User = serviceUserForState(currentServiceUser(t))
			saved.InstallationComplete = false
			if err := state.Save(controller.options.StatePath, saved); err != nil {
				t.Fatal(err)
			}
			adapter := &fakeService{status: service.Status{State: "not-installed", AutoStart: "false"}}
			controller.options.ServiceFactory = func(string) (ServiceClient, error) { return adapter, nil }
			snapshot, err := controller.Snapshot(context.Background())
			if err != nil || snapshot.Installed || snapshot.IntegrityIssue != "service-missing" {
				t.Fatalf("missing service misclassified: %+v %v", snapshot, err)
			}
			plan.Repair, plan.ServiceMode = true, mode
			plan.ServiceUser = currentServiceUser(t)
			for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
				if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
					t.Fatalf("repair failed at %s: %v", kind, adapter.calls)
				}
			}
			snapshot, err = controller.Snapshot(context.Background())
			if err != nil || !snapshot.Installed || snapshot.Incomplete || snapshot.ServiceMode != mode {
				t.Fatalf("repair did not restore requested mode: %+v %v", snapshot, err)
			}
			if adapter.called("stop") {
				t.Fatal("attempted to stop a service proven absent")
			}
		})
	}
}

// TestInterruptedServiceCopyCanBeReinstalled verifies missing executable bytes do not block repair when no native service exists.
// TestInterruptedServiceCopyCanBeReinstalled 验证程序复制中断且系统服务不存在时，可通过已验证暂存程序检查后重装。
func TestInterruptedServiceCopyCanBeReinstalled(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatal("fixture install failed")
		}
	}
	saved, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	saved.Service.Name, saved.InstallationComplete = "VulcanMemoryMesh", false
	saved.Service.User = serviceUserForState(currentServiceUser(t))
	if err := state.Save(controller.options.StatePath, saved); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(plan.ProgramRoot, filepath.FromSlash(controller.identity.VMMExecutablePath))
	if err := os.Remove(binaryPath); err != nil {
		t.Fatal(err)
	}
	adapter := &fakeService{status: service.Status{State: "not-installed", AutoStart: "false"}}
	inspectedVerifiedStage := false
	controller.options.ServiceFactory = func(binary string) (ServiceClient, error) {
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			if binary == binaryPath {
				t.Fatal("attempted to inspect service with the missing executable")
			}
			if _, err := os.Stat(binary); err != nil {
				t.Fatal("verified staged CLI missing")
			}
			inspectedVerifiedStage = true
		}
		return adapter, nil
	}
	plan.Repair, plan.ServiceMode, plan.ServiceUser = true, tui.ServiceModeService, currentServiceUser(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatalf("interrupted copy repair failed at %s", kind)
		}
	}
	snapshot, err := controller.Snapshot(context.Background())
	if err != nil || !snapshot.Installed || !inspectedVerifiedStage || adapter.called("stop") {
		t.Fatalf("interrupted copy was not safely repaired: %+v %v %v", snapshot, adapter.calls, err)
	}
}
