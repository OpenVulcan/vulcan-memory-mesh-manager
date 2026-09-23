// This file verifies saved-configuration checks against installed identity and the durable success timestamp.
// 本文件验证已保存配置检查使用已安装身份，且只持久化检查通过时间。
package controller

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestValidateInstalledRecordsOnlySuccessfulChecks proves that checks use the registered paths and keep older success on failure.
// TestValidateInstalledRecordsOnlySuccessfulChecks 证明检查使用登记路径，且失败时保留上一次通过时间。
func TestValidateInstalledRecordsOnlySuccessfulChecks(t *testing.T) {
	controller, plan, fixture := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatal("fixture installation failed")
		}
	}
	checkTime := time.Date(2026, time.September, 24, 6, 7, 8, 9, time.UTC)
	controller.options.Clock = func() time.Time { return checkTime }
	previousValidate := controller.options.Validate
	called := 0
	controller.options.Validate = func(ctx context.Context, binaryPath, configRoot string) (configbridge.ValidationResult, error) {
		called++
		wantBinary := filepath.Join(plan.ProgramRoot, filepath.FromSlash(fixture.identity.VMMExecutablePath))
		if binaryPath != wantBinary || configRoot != plan.ConfigRoot {
			t.Fatalf("checked unregistered paths: binary=%q root=%q", binaryPath, configRoot)
		}
		return previousValidate(ctx, binaryPath, configRoot)
	}
	result, err := controller.ValidateInstalled(context.Background())
	if err != nil || !result.Valid || called != 1 {
		t.Fatalf("saved validation = %+v, calls=%d, error=%v", result, called, err)
	}
	installed, err := state.Load(controller.options.StatePath)
	if err != nil || !installed.InstallationComplete || installed.ConfigValidatedAt != checkTime.Format(time.RFC3339Nano) {
		t.Fatalf("saved check state = %+v, error=%v", installed, err)
	}
	controller.options.Clock = func() time.Time { return checkTime.Add(time.Hour) }
	controller.options.Validate = func(context.Context, string, string) (configbridge.ValidationResult, error) {
		return configbridge.ValidationResult{Valid: false}, nil
	}
	result, err = controller.ValidateInstalled(context.Background())
	if err != nil || result.Valid {
		t.Fatalf("invalid configuration was not reported: %+v, error=%v", result, err)
	}
	unchanged, err := state.Load(controller.options.StatePath)
	if err != nil || unchanged.ConfigValidatedAt != installed.ConfigValidatedAt || !unchanged.InstallationComplete {
		t.Fatalf("invalid check changed successful history or installation: %+v, error=%v", unchanged, err)
	}
}

// TestValidateInstalledRejectsIncompleteRegistration prevents a healthy config from claiming an unfinished installation.
// TestValidateInstalledRejectsIncompleteRegistration 防止有效配置让未完成安装获得检查通过记录。
func TestValidateInstalledRejectsIncompleteRegistration(t *testing.T) {
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
	installed.InstallationComplete = false
	installed.ConfigValidatedAt = ""
	if err := state.Save(controller.options.StatePath, installed); err != nil {
		t.Fatal(err)
	}
	controller.options.Validate = func(context.Context, string, string) (configbridge.ValidationResult, error) {
		return configbridge.ValidationResult{}, errors.New("validator must not be called")
	}
	if _, err := controller.ValidateInstalled(context.Background()); err == nil || err.Error() != "VMM installation is incomplete" {
		t.Fatalf("incomplete registration was accepted: %v", err)
	}
	unchanged, err := state.Load(controller.options.StatePath)
	if err != nil || unchanged.ConfigValidatedAt != "" || unchanged.InstallationComplete {
		t.Fatalf("incomplete registration changed: %+v, error=%v", unchanged, err)
	}
}
