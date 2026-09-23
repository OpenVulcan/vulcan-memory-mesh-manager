// Package platform tests exact platform mappings without touching the host system.
// platform 包测试精确的平台映射，不接触宿主系统状态。
// The tests protect the asset-selection contract shared with VMM releases.
// 这些测试保护管理器与 VMM 发行版共享的资产选择契约。
package platform

import (
	"runtime"
	"testing"
)

// TestResolveMapsAllSupportedPlatforms verifies all five release IDs and executable paths.
// TestResolveMapsAllSupportedPlatforms 验证全部五种发行 ID 与可执行文件路径。
func TestResolveMapsAllSupportedPlatforms(t *testing.T) {
	tests := []struct {
		name                  string
		goos                  string
		goarch                string
		platformID            string
		managerExecutableName string
		vmmExecutablePath     string
	}{
		{
			name:                  "windows x64",
			goos:                  "windows",
			goarch:                "amd64",
			platformID:            "windows-x64",
			managerExecutableName: "vmmm.exe",
			vmmExecutablePath:     "bin/vmm-local.exe",
		},
		{
			name:                  "linux x64",
			goos:                  "linux",
			goarch:                "amd64",
			platformID:            "linux-x64",
			managerExecutableName: "vmmm",
			vmmExecutablePath:     "bin/vmm-local",
		},
		{
			name:                  "linux arm64",
			goos:                  "linux",
			goarch:                "arm64",
			platformID:            "linux-arm64",
			managerExecutableName: "vmmm",
			vmmExecutablePath:     "bin/vmm-local",
		},
		{
			name:                  "macos intel",
			goos:                  "darwin",
			goarch:                "amd64",
			platformID:            "macos-intel",
			managerExecutableName: "vmmm",
			vmmExecutablePath:     "bin/vmm-local",
		},
		{
			name:                  "macos arm64",
			goos:                  "darwin",
			goarch:                "arm64",
			platformID:            "macos-arm64",
			managerExecutableName: "vmmm",
			vmmExecutablePath:     "bin/vmm-local",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, err := Resolve(test.goos, test.goarch)
			if err != nil {
				t.Fatalf("Resolve(%q, %q) failed: %v", test.goos, test.goarch, err)
			}
			if identity.PlatformID != test.platformID {
				t.Errorf("PlatformID = %q, want %q", identity.PlatformID, test.platformID)
			}
			if identity.ManagerExecutableName != test.managerExecutableName {
				t.Errorf("ManagerExecutableName = %q, want %q", identity.ManagerExecutableName, test.managerExecutableName)
			}
			if identity.VMMExecutablePath != test.vmmExecutablePath {
				t.Errorf("VMMExecutablePath = %q, want %q", identity.VMMExecutablePath, test.vmmExecutablePath)
			}
		})
	}
}

// TestResolveRejectsUnsupportedPlatforms verifies unsupported OS and architecture pairs fail closed.
// TestResolveRejectsUnsupportedPlatforms 验证不受支持的操作系统与架构组合会明确失败。
func TestResolveRejectsUnsupportedPlatforms(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		goarch string
	}{
		{name: "windows arm64", goos: "windows", goarch: "arm64"},
		{name: "unknown OS", goos: "plan9", goarch: "amd64"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, err := Resolve(test.goos, test.goarch)
			if err == nil {
				t.Fatalf("Resolve(%q, %q) = %#v, want unsupported-platform error", test.goos, test.goarch, identity)
			}
		})
	}
}

// TestCurrentUsesRuntimeIdentity verifies runtime detection delegates to the same exact mapping.
// TestCurrentUsesRuntimeIdentity 验证运行时平台检测复用同一份精确映射。
func TestCurrentUsesRuntimeIdentity(t *testing.T) {
	current, currentErr := Current()
	runtimeIdentity, runtimeErr := Resolve(runtime.GOOS, runtime.GOARCH)
	if (currentErr == nil) != (runtimeErr == nil) {
		t.Fatalf("Current() error = %v, Resolve(runtime) error = %v", currentErr, runtimeErr)
	}
	if currentErr != nil {
		return
	}
	if current != runtimeIdentity {
		t.Fatalf("Current() = %#v, Resolve(runtime) = %#v", current, runtimeIdentity)
	}
}
