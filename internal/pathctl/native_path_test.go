// These helpers gate real PATH integration tests to explicitly opted-in disposable GitHub runners.
// 这些辅助函数仅在明确启用的临时 GitHub 执行器中开放真实 PATH 集成测试。
package pathctl

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// nativePATHBinary reads the exact manager built by CI; ordinary local tests skip all machine integration changes.
// nativePATHBinary 读取 CI 刚构建的管理器；普通本地测试跳过机器集成改动，返回二进制内容。
func nativePATHBinary(t *testing.T) []byte {
	t.Helper()
	if os.Getenv("VMMM_TEST_NATIVE_PATH") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("native PATH verification requires an explicitly opted-in disposable CI runner")
	}
	path := os.Getenv("VMMM_TEST_MANAGER_BINARY")
	if !filepath.IsAbs(path) {
		t.Fatal("native PATH test requires an absolute built-manager path")
	}
	binary, err := os.ReadFile(path)
	if err != nil || len(binary) == 0 {
		t.Fatal("built manager is unavailable")
	}
	return binary
}

// verifyNativePATHCommand requires PATH to select expected before checking its real non-interactive product response.
// verifyNativePATHCommand 要求 PATH 选中 expected 指定文件，再检查真实非交互产品响应，无返回值。
func verifyNativePATHCommand(t *testing.T, expected string) {
	t.Helper()
	resolved, err := exec.LookPath("vmmm")
	if err != nil {
		t.Fatal(err)
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil {
		t.Fatal(err)
	}
	expectedInfo, err := os.Stat(expected)
	if err != nil || !os.SameFile(resolvedInfo, expectedInfo) {
		t.Fatal("PATH selected a different executable")
	}
	output, err := exec.Command("vmmm", "--json", "version").Output()
	if err != nil {
		t.Fatalf("manager command could not run through PATH: %v", err)
	}
	var version struct {
		Product string `json:"product"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(output, &version); err != nil || version.Product != "vmmm" || version.Version == "" {
		t.Fatalf("unexpected manager version response: %s %v", output, err)
	}
}
