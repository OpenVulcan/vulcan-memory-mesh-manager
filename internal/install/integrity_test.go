// These tests exercise completeness detection and explicit repair ownership boundaries in the installation layer.
// 这些测试验证安装层的完整性检测与显式修复的文件归属边界。
package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// TestFilesIntactRequiresExecutableAndConfig rejects incomplete manifests and missing user configuration.
// TestFilesIntactRequiresExecutableAndConfig 拒绝缺少主程序的清单与丢失的用户配置。
func TestFilesIntactRequiresExecutableAndConfig(t *testing.T) {
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	result, err := Install(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if issue := FilesIntact(result.State); issue != "" {
		t.Fatalf("intact install rejected: %s", issue)
	}
	withoutBinary := result.State
	withoutBinary.ManagedFiles = nil
	for _, item := range result.State.ManagedFiles {
		if item.Path != "bin/"+vmmExecutableName() {
			withoutBinary.ManagedFiles = append(withoutBinary.ManagedFiles, item)
		}
	}
	if issue := FilesIntact(withoutBinary); issue != "missing-program-files" {
		t.Fatalf("missing executable accepted: %s", issue)
	}
	if err := os.Remove(filepath.Join(paths.ConfigRoot, UserConfigFileName)); err != nil {
		t.Fatal(err)
	}
	if issue := FilesIntact(result.State); issue != "missing-configuration" {
		t.Fatalf("missing config accepted: %s", issue)
	}
}

// TestRepairPreservesUnregisteredFiles ensures an explicit repair is not blanket permission to replace unrelated files.
// TestRepairPreservesUnregisteredFiles 确保显式修复不能覆盖未登记的无关文件。
func TestRepairPreservesUnregisteredFiles(t *testing.T) {
	request, paths, _ := newInstallRequest(t, "")
	request.ValidateConfig = validConfigValidator(t)
	result, err := Install(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	filename := "bin/" + vmmExecutableName()
	managed := make([]state.ManagedFile, 0)
	for _, item := range result.State.ManagedFiles {
		if item.Path != filename {
			managed = append(managed, item)
		}
	}
	result.State.ManagedFiles = managed
	if err := state.Save(request.StatePath, result.State); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(paths.ProgramRoot, filepath.FromSlash(filename))
	if err := os.WriteFile(binary, []byte("unrelated user file"), 0o700); err != nil {
		t.Fatal(err)
	}
	request.Operation, request.Repair = OperationUpgrade, true
	if _, err := Apply(context.Background(), request); err == nil {
		t.Fatal("repair overwrote an unregistered file")
	}
	if data, err := os.ReadFile(binary); err != nil || string(data) != "unrelated user file" {
		t.Fatal("unregistered file changed")
	}
}

// TestProgramRemnants distinguishes a clean target from interrupted installation files.
// TestProgramRemnants 区分干净目标目录与安装中断遗留文件。
func TestProgramRemnants(t *testing.T) {
	root := filepath.Join(t.TempDir(), "program")
	if HasProgramRemnants(root) {
		t.Fatal("missing directory reported remnants")
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if HasProgramRemnants(root) {
		t.Fatal("empty directory reported remnants")
	}
	if err := os.WriteFile(filepath.Join(root, "partial"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !HasProgramRemnants(root) {
		t.Fatal("interrupted files were not detected")
	}
}
