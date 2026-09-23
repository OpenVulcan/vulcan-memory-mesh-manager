//go:build windows

// This file verifies the actual HKCU registry backend and environment broadcast on disposable Windows CI runners.
// 本文件在临时 Windows CI 执行器中验证真实 HKCU 注册表后端和环境广播。
package pathctl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNativePATHRoundTrip installs the CI binary into real user PATH, invokes it, and restores the exact original registry value.
// TestNativePATHRoundTrip 将 CI 二进制加入真实用户 PATH 并调用，最后恢复原注册表值，无返回值。
func TestNativePATHRoundTrip(t *testing.T) {
	binary := nativePATHBinary(t)
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "vmmm.exe"), binary, 0o700); err != nil {
		t.Fatal(err)
	}
	controller := New()
	before, err := controller.registry.ReadPath()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := restoreRegistryValue(controller.registry, before); err != nil {
			t.Errorf("restore runner PATH: %v", err)
		}
		if err := controller.broadcaster.Broadcast(); err != nil {
			t.Errorf("broadcast restored runner PATH: %v", err)
		}
	})
	record, err := controller.Install(Options{Method: MethodWindowsUserPath, Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	after, err := controller.registry.ReadPath()
	if err != nil || !strings.Contains(after.Value, directory) {
		t.Fatalf("manager directory missing from real registry: %v", err)
	}
	// Existing processes keep their environment; construct a fresh shell environment from the new user registry value.
	// 已有进程保留原环境；使用新的用户注册表值构造新终端环境。
	t.Setenv("PATH", after.Value+";"+os.Getenv("PATH"))
	verifyNativePATHCommand(t, filepath.Join(directory, "vmmm.exe"))
	if err := controller.Remove(record); err != nil {
		t.Fatal(err)
	}
	restored, err := controller.registry.ReadPath()
	if err != nil || restored.Value != before.Value || (before.Present && restored.Type != before.Type) {
		t.Fatalf("PATH removal did not preserve the original value: %v", err)
	}
}
