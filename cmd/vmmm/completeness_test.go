// These CLI tests verify incomplete installations are reported without attempting to execute missing programs.
// 这些命令行测试验证未完成安装会被明确报告，且不会尝试执行缺失的程序。
package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/platform"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestStatusAndDoctorReportIncompleteInstall checks a real saved registration and both machine-readable commands.
// TestStatusAndDoctorReportIncompleteInstall 使用真实登记文件验证两个机器可读命令均报告未完成并返回失败码。
func TestStatusAndDoctorReportIncompleteInstall(t *testing.T) {
	root := t.TempDir()
	identity, err := platform.Current()
	if err != nil {
		t.Fatal(err)
	}
	options := commandOptions{JSON: true, ManagerRoot: filepath.Join(root, "manager"), CacheRoot: filepath.Join(root, "cache"), StatePath: filepath.Join(root, "installation.json")}
	saved := state.State{
		ProtocolVersion: state.ProtocolVersion, ManagerVersion: "test",
		VMM:            state.VMMIdentity{Tag: "v0.2.0", Commit: strings.Repeat("a", 40), Platform: identity.PlatformID},
		Paths:          state.InstallPaths{ProgramRoot: filepath.Join(root, "program"), ConfigRoot: filepath.Join(root, "config"), DataRoot: filepath.Join(root, "data")},
		DownloadSource: state.DownloadSource{ID: "github"},
		PATH:           state.PATHState{Owner: state.PATHOwnerNone, Scope: state.PATHScopeNone, Entries: []string{}},
		ManagedFiles:   []state.ManagedFile{{Path: identity.VMMExecutablePath, SHA256: strings.Repeat("0", 64), Size: 1}},
	}
	if err := state.Save(options.StatePath, saved); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"status", "doctor"} {
		t.Run(action, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			environment := normalizeEnvironment(commandEnvironment{stdout: &output, stderr: &diagnostics})
			var code int
			if action == "doctor" {
				code = runDoctor(options, environment)
			} else {
				code = runLifecycleCommand(action, options, environment)
			}
			if code != 1 {
				t.Fatalf("incomplete installation exit=%d, output=%s, diagnostics=%s", code, output.String(), diagnostics.String())
			}
			var result struct{ Snapshot *tui.InstallationSnapshot }
			if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Snapshot == nil {
				t.Fatalf("missing JSON snapshot: %s %v", output.String(), err)
			}
			if result.Snapshot.Installed || !result.Snapshot.Incomplete || result.Snapshot.IntegrityIssue != "missing-program-files" {
				t.Fatalf("wrong completeness: %+v", result.Snapshot)
			}
		})
	}
}
