//go:build !windows

// These tests check the macOS paths.d input and ownership receipt contracts without changing the host environment.
// 这些测试检查 macOS paths.d 输入及所有权收据契约，不修改宿主环境。
package pathctl

import (
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// TestDarwinPathContentRejectsShellActivePaths keeps path_helper's login-shell output free from active path characters.
// TestDarwinPathContentRejectsShellActivePaths 拒绝能影响 path_helper 登录 shell 输出的活跃路径字符。
func TestDarwinPathContentRejectsShellActivePaths(t *testing.T) {
	for _, value := range []string{"/tmp/a:b", "/tmp/`id`", "/tmp/$HOME", "/tmp/a\nb", "/tmp/a\\", "/tmp/a\"", "/tmp/a'"} {
		if _, err := darwinPathContent(value); err == nil {
			t.Fatalf("unsafe paths.d entry accepted: %q", value)
		}
	}
	const directory = "/Library/Application Support/VMMM/manager"
	content, err := darwinPathContent(directory)
	if err != nil || string(content) != directory+"\n" {
		t.Fatalf("standard directory rejected: %q %v", content, err)
	}
}

// TestDarwinPathRecordRequiresFixedSystemOwnership checks method, path, digest, and scope binding before removal.
// TestDarwinPathRecordRequiresFixedSystemOwnership 检查移除前方法、路径、摘要和范围的绑定。
func TestDarwinPathRecordRequiresFixedSystemOwnership(t *testing.T) {
	const directory = "/Library/Application Support/VMMM/manager"
	record := Record{Version: RecordVersion, Method: MethodDarwinPathsD, Directory: directory, ProfilePath: DarwinPathsFile, AfterSHA256: strings.Repeat("a", 64), Path: state.PATHState{Owner: state.PATHOwnerManager, Scope: state.PATHScopeSystem, Entries: []string{directory}}}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Record){
		func(r *Record) { r.ProfilePath = "/private/etc/paths.d/other" },
		func(r *Record) { r.Path.Scope = state.PATHScopeUser },
		func(r *Record) { r.AfterSHA256 = "" },
		func(r *Record) { r.TargetPath = "/tmp/vmmm" },
	} {
		candidate := record
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatal("invalid macOS path receipt was accepted")
		}
	}
}
