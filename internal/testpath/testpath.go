// This file canonicalizes test fixtures before strict path ownership checks run.
// 本文件在严格路径归属检查前规范化测试夹具的真实位置。
package testpath

import (
	"os"
	"path/filepath"
	"testing"
)

// CanonicalTempDir returns a test-owned temporary directory without host OS alias links.
// CanonicalTempDir 返回测试持有且不经过宿主系统别名链接的临时目录。
func CanonicalTempDir(t testing.TB) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// CanonicalExecutable returns the current test binary through its resolved filesystem path.
// CanonicalExecutable 返回当前测试程序经过文件系统解析后的真实路径。
func CanonicalExecutable(t testing.TB) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
