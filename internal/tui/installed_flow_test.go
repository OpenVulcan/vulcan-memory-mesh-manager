// This file tests installed TUI routes through the same asynchronous command chain as Bubble Tea.
// 本文件使用与 Bubble Tea 相同的异步命令链测试已安装界面的路由。
package tui

import (
	"strings"
	"testing"

	"charm.land/bubbletea/v2"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
)

// TestIncompleteHomeOffersReinstall keeps damaged installations out of lifecycle actions and preserves the repair choice through download.
// TestIncompleteHomeOffersReinstall 阻止损坏安装执行生命周期动作，并将重新安装选择保留到下载阶段。
func TestIncompleteHomeOffersReinstall(t *testing.T) {
	controller := &testController{}
	model := NewModel(ModelConfig{Controller: controller, Language: LanguageChinese, Initial: InstallationSnapshot{Incomplete: true, VMMVersion: "v1.2.3", Storage: StorageNative}})
	if model.Screen() != ScreenHome || !strings.Contains(model.View().Content, "安装未完成") {
		t.Fatal("incomplete installation was hidden")
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if len(controller.requests) != 0 {
		t.Fatal("incomplete installation reached lifecycle control")
	}
	model.cursor = 11
	model = update(t, model, press(tea.KeyEnter, ""))
	model = update(t, model, press(tea.KeyEnter, ""))
	if !model.plan.Repair || model.Screen() != ScreenProviders || len(controller.requests) != 2 || !controller.requests[1].Plan.Repair {
		t.Fatal("repair intent was lost")
	}
}

// TestInstalledConfigureStagesCurrentVersion checks that editing acquires a verified package before configuration.
// TestInstalledConfigureStagesCurrentVersion 检查编辑已安装配置前会取得当前版本的校验包。
func TestInstalledConfigureStagesCurrentVersion(t *testing.T) {
	controller := &testController{}
	model := NewModel(ModelConfig{Controller: controller, Initial: InstallationSnapshot{Installed: true, VMMVersion: "v1.2.3", Storage: StorageNative}})
	model.cursor = 7
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenSource {
		t.Fatalf("configure screen = %v", model.Screen())
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenProviders || !model.plan.Package.Verified {
		t.Fatalf("configuration reached without verified package: screen=%v", model.Screen())
	}
	if len(controller.requests) != 2 || controller.requests[1].Kind != OperationStagePackage || controller.requests[1].Plan.Version.Tag != "v1.2.3" {
		t.Fatalf("configuration staging requests = %+v", controller.requests)
	}
}

// TestInstalledServiceRegistrationUsesServiceMode verifies account confirmation and explicit service dispatch.
// TestInstalledServiceRegistrationUsesServiceMode 验证账户确认与明确的服务模式请求。
func TestInstalledServiceRegistrationUsesServiceMode(t *testing.T) {
	for _, platform := range []string{"windows", "linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			controller := &testController{}
			model := NewModel(ModelConfig{Controller: controller, PlatformOS: platform, Initial: InstallationSnapshot{Installed: true, ServiceMode: ServiceModeForeground}})
			model.cursor = 3
			model = update(t, model, press(tea.KeyEnter, ""))
			if platform != "windows" {
				if model.Screen() != ScreenServiceUser || len(controller.requests) != 0 {
					t.Fatal("service registered without confirming its account")
				}
				model.input = "vmm"
				model = update(t, model, press(tea.KeyEnter, ""))
			}
			if len(controller.requests) != 1 || controller.requests[0].TargetMode != ServiceModeService || controller.requests[0].ServiceAction != ServiceActionInstall {
				t.Fatalf("registration request = %+v", controller.requests)
			}
			if platform != "windows" && controller.requests[0].Plan.ServiceUser != "vmm" {
				t.Fatal("selected service account was lost")
			}
		})
	}
}

// TestExplicitInteractiveEntries preserves CLI actions and the user's saved proxy.
// TestExplicitInteractiveEntries 保留命令行操作及用户保存的代理源。
func TestExplicitInteractiveEntries(t *testing.T) {
	source, err := download.NewCustomProxy("https://mirror.example/")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"edit", "upgrade", "rollback"} {
		model := NewModel(ModelConfig{EntryAction: action, Initial: InstallationSnapshot{Installed: true, VMMVersion: "v1.2.3", SourceID: string(source.ID), SourcePrefix: "https://mirror.example/"}})
		if model.Screen() != ScreenSource || model.plan.Rollback != (action == "rollback") || model.editingInstalled != (action == "edit") {
			t.Fatalf("incorrect route for %s", action)
		}
		if model.selectedSource.Source.ID != source.ID || model.sourceAt(model.cursor).Source.ID != source.ID {
			t.Fatal("saved custom proxy was lost")
		}
	}
}
