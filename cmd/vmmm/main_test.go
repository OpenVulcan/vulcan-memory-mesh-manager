// Package main tests the vmmm command dispatcher without starting a real terminal.
// main 包测试 vmmm 命令分派，不启动真实终端。
package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/platform"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestRunCommandWithoutTTYRejectsImplicitTUI verifies pipes never enter the interactive installer.
// TestRunCommandWithoutTTYRejectsImplicitTUI 验证管道环境不会进入交互式安装器。
func TestRunCommandWithoutTTYRejectsImplicitTUI(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCommand(nil, commandEnvironment{
		stdout: &stdout,
		stderr: &stderr,
		isTerminal: func() bool {
			return false
		},
	})
	if code != 2 {
		t.Fatalf("runCommand() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "requires a terminal") {
		t.Fatalf("stderr = %q, want terminal diagnostic", stderr.String())
	}
}

// TestRunCommandInstallWithoutTTYRejectsInteractiveInstall verifies install has an explicit pipe error.
// TestRunCommandInstallWithoutTTYRejectsInteractiveInstall 验证 install 在管道中明确拒绝交互安装。
func TestRunCommandInstallWithoutTTYRejectsInteractiveInstall(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommand([]string{"install"}, commandEnvironment{
		stderr:     &stderr,
		isTerminal: func() bool { return false },
	})
	if code != 2 {
		t.Fatalf("runCommand() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "install/open requires a terminal") {
		t.Fatalf("stderr = %q, want install terminal diagnostic", stderr.String())
	}
}

// TestRunCommandVersionIsNonInteractive verifies version does not require state or a TTY.
// TestRunCommandVersionIsNonInteractive 验证 version 不要求状态文件或终端。
func TestRunCommandVersionIsNonInteractive(t *testing.T) {
	var stdout bytes.Buffer
	code := runCommand([]string{"--json", "version"}, commandEnvironment{
		stdout:     &stdout,
		isTerminal: func() bool { return false },
	})
	if code != 0 {
		t.Fatalf("runCommand() code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), `"product":"vmmm"`) || !strings.Contains(stdout.String(), `"version":"`) {
		t.Fatalf("stdout = %q, want JSON version document", stdout.String())
	}
}

// TestParseGlobalOptionsPreservesSubcommand verifies global flags stop before the command token.
// TestParseGlobalOptionsPreservesSubcommand 验证全局选项解析会保留子命令及其参数。
func TestParseGlobalOptionsPreservesSubcommand(t *testing.T) {
	options, remaining, help, err := parseGlobalOptions([]string{"--state", "C:/state.json", "--json", "service", "status"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseGlobalOptions() error = %v", err)
	}
	if help {
		t.Fatal("parseGlobalOptions() unexpectedly requested help")
	}
	if options.StatePath != "C:/state.json" || !options.JSON {
		t.Fatalf("options = %#v, want explicit state and JSON", options)
	}
	if got := strings.Join(remaining, " "); got != "service status" {
		t.Fatalf("remaining = %q, want service status", got)
	}
}

// TestSnapshotFromStateMasksSensitiveStorageDetails verifies only durable non-secret fields enter the summary.
// TestSnapshotFromStateMasksSensitiveStorageDetails 验证摘要只包含持久化非秘密字段。
func TestSnapshotFromStateMasksSensitiveStorageDetails(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vmm")
	loaded := state.State{
		ManagerVersion: "vmmm-test",
		VMM:            state.VMMIdentity{Tag: "v0.1.0", Commit: "commit", Platform: "windows-x64"},
		Paths:          state.InstallPaths{ProgramRoot: root, ConfigRoot: filepath.Join(root, "config"), DataRoot: filepath.Join(root, "data")},
		DownloadSource: state.DownloadSource{ID: "github"},
		Service:        state.ServiceState{Name: "VulcanMemoryMesh", AutoStart: true},
		PATH:           state.PATHState{Owner: state.PATHOwnerManager, Scope: state.PATHScopeUser, Entries: []string{filepath.Join(root, "manager")}},
	}
	identity := platform.Identity{VMMExecutablePath: "bin/vmm-local.exe"}
	snapshot := snapshotFromState(loaded, true, identity, filepath.Join(loaded.Paths.DataRoot, "installation.json"))
	if !snapshot.Installed || snapshot.VMMVersion != "v0.1.0" {
		t.Fatalf("snapshot = %#v, want installed VMM version", snapshot)
	}
	if snapshot.ServiceMode != tui.ServiceModeService || !snapshot.AutoStart || !snapshot.PathEnabled {
		t.Fatalf("snapshot = %#v, want service, autostart, and PATH enabled", snapshot)
	}
}

// TestLoadOptionalStateUsesTheStateNotExistContract verifies only os.ErrNotExist means uninstalled.
// TestLoadOptionalStateUsesTheStateNotExistContract 验证只有 os.ErrNotExist 才表示尚未安装。
func TestLoadOptionalStateUsesTheStateNotExistContract(t *testing.T) {
	missing, installed, err := loadOptionalState(filepath.Join(t.TempDir(), "installation.json"))
	if err != nil || installed || missing.ProtocolVersion != 0 || missing.ManagerVersion != "" {
		t.Fatalf("loadOptionalState(missing) = %#v, %t, %v; want empty, false, nil", missing, installed, err)
	}
	malformedPath := filepath.Join(t.TempDir(), "installation.json")
	if err := os.WriteFile(malformedPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write malformed state: %v", err)
	}
	_, installed, err = loadOptionalState(malformedPath)
	if err == nil || installed {
		t.Fatalf("loadOptionalState(malformed) = installed %t, error %v; want error", installed, err)
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loadOptionalState(malformed) error = %v; must not be classified as missing", err)
	}
}

// TestUnixDefaultPathsSeparateControlAndServiceRoots verifies the privileged state boundary.
// TestUnixDefaultPathsSeparateControlAndServiceRoots 验证管理员状态与服务可写目录分离。
func TestUnixDefaultPathsSeparateControlAndServiceRoots(t *testing.T) {
	for _, osName := range []string{"linux", "darwin"} {
		paths, err := platformDefaultPaths(osName)
		if err != nil {
			t.Fatalf("platformDefaultPaths(%q): %v", osName, err)
		}
		for _, serviceRoot := range []string{paths.ConfigRoot, paths.DataRoot} {
			if paths.StatePath == serviceRoot || strings.HasPrefix(paths.StatePath, serviceRoot+"/") ||
				paths.ManagerRoot == serviceRoot || strings.HasPrefix(paths.ManagerRoot, serviceRoot+"/") ||
				paths.CacheRoot == serviceRoot || strings.HasPrefix(paths.CacheRoot, serviceRoot+"/") {
				t.Fatalf("%s control paths overlap service-owned root %q: %#v", osName, serviceRoot, paths)
			}
		}
		if !strings.HasPrefix(paths.ProgramRoot, "/") || !strings.HasPrefix(paths.StatePath, "/") {
			t.Fatalf("%s default paths are not absolute: %#v", osName, paths)
		}
	}
}

// TestManagerBootstrapSourceHonorsExplicitSourceContract verifies source mapping and custom HTTPS validation.
// TestManagerBootstrapSourceHonorsExplicitSourceContract 验证来源映射以及自定义 HTTPS 校验。
func TestManagerBootstrapSourceHonorsExplicitSourceContract(t *testing.T) {
	t.Setenv("VMMM_BOOTSTRAP_SOURCE", "ghproxy-net")
	t.Setenv("VMMM_BOOTSTRAP_PROXY_PREFIX", "")
	source, err := managerBootstrapSource()
	if err != nil || source.ID != "github-proxy-ghproxy-net" {
		t.Fatalf("managerBootstrapSource() = %#v, %v; want ghproxy.net", source, err)
	}
	t.Setenv("VMMM_BOOTSTRAP_SOURCE", "custom")
	t.Setenv("VMMM_BOOTSTRAP_PROXY_PREFIX", "https://mirror.example/")
	source, err = managerBootstrapSource()
	if err != nil || source.Kind != "github-proxy" || source.Prefix != "https://mirror.example/" {
		t.Fatalf("managerBootstrapSource(custom) = %#v, %v; want validated custom source", source, err)
	}
	t.Setenv("VMMM_BOOTSTRAP_PROXY_PREFIX", "http://mirror.example/")
	if _, err := managerBootstrapSource(); err == nil {
		t.Fatal("managerBootstrapSource() accepted a non-HTTPS custom source")
	}
}

// TestCompareManagerReleaseTagsRejectsDowngrades verifies the ordering used before self-install upgrades.
// TestCompareManagerReleaseTagsRejectsDowngrades 验证自安装升级前使用的版本排序。
func TestCompareManagerReleaseTagsRejectsDowngrades(t *testing.T) {
	comparison, err := compareManagerReleaseTags("v1.2.0", "v1.1.9")
	if err != nil || comparison <= 0 {
		t.Fatalf("compareManagerReleaseTags(newer) = %d, %v; want positive", comparison, err)
	}
	comparison, err = compareManagerReleaseTags("v1.1.9", "v1.2.0")
	if err != nil || comparison >= 0 {
		t.Fatalf("compareManagerReleaseTags(older) = %d, %v; want negative", comparison, err)
	}
	if _, err := compareManagerReleaseTags("latest", "v1.2.0"); err == nil {
		t.Fatal("compareManagerReleaseTags() accepted an ambiguous candidate tag")
	}
}
