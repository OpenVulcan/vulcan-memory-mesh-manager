// This file checks configuration transactions against directory replacement and concurrent edits.
// 本文件验证配置事务在目录替换和并发编辑情况下仍限制访问范围并保留用户数据。
package install

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/testpath"
)

// TestConfigRollbackUsesPinnedParent restores the original directory after its public name is redirected.
// TestConfigRollbackUsesPinnedParent 验证公开目录名称被重定向后，回滚仍只恢复原始目录。
func TestConfigRollbackUsesPinnedParent(t *testing.T) {
	transaction, root, source := configTransactionFixture(t)
	if err := transaction.replaceConfigFile(source, root, "nested/rules.yaml", 0o600); err != nil {
		t.Fatal(err)
	}
	moved, external := redirectConfigParent(t, root)
	if err := transaction.rollback(); err != nil {
		t.Fatal(err)
	}
	assertConfigContents(t, filepath.Join(moved, "rules.yaml"), "original")
	assertConfigContents(t, filepath.Join(external, "rules.yaml"), "external")
	if err := transaction.cleanup(); err != nil {
		t.Fatal(err)
	}
}

// TestConfigCommitCleanupUsesPinnedParent removes backups without following a replaced directory name.
// TestConfigCommitCleanupUsesPinnedParent 验证提交后的备份清理不会跟随被替换的目录名称。
func TestConfigCommitCleanupUsesPinnedParent(t *testing.T) {
	transaction, root, source := configTransactionFixture(t)
	if err := transaction.replaceConfigFile(source, root, "nested/rules.yaml", 0o600); err != nil {
		t.Fatal(err)
	}
	moved, external := redirectConfigParent(t, root)
	transaction.commit()
	if err := transaction.cleanup(); err != nil {
		t.Fatal(err)
	}
	assertConfigContents(t, filepath.Join(moved, "rules.yaml"), "candidate")
	assertConfigContents(t, filepath.Join(external, "rules.yaml"), "external")
	entries, err := os.ReadDir(moved)
	if err != nil || len(entries) != 1 || entries[0].Name() != "rules.yaml" {
		t.Fatalf("unexpected entries after cleanup: %v, error: %v", entries, err)
	}
}

// TestConfigRollbackPreservesConcurrentEdit retains changed configuration and its original recovery backup.
// TestConfigRollbackPreservesConcurrentEdit 验证并发修改的配置与原始恢复备份都会保留。
func TestConfigRollbackPreservesConcurrentEdit(t *testing.T) {
	transaction, root, source := configTransactionFixture(t)
	if err := transaction.replaceConfigFile(source, root, "nested/rules.yaml", 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "nested", "rules.yaml")
	if err := os.WriteFile(target, []byte("user edit"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := transaction.rollback(); err == nil {
		t.Fatal("rollback accepted a concurrent edit")
	}
	assertConfigContents(t, target, "user edit")
	backup, err := transaction.configChanges[0].backup.ReadFile("original")
	if err != nil || string(backup) != "original" {
		t.Fatalf("original recovery backup = %q, error: %v", backup, err)
	}
}

// configTransactionFixture returns a private transaction, configuration root, and candidate file.
// configTransactionFixture 返回私有事务、配置根与候选文件，测试结束时统一释放句柄。
func configTransactionFixture(t *testing.T) (*fileTransaction, string, string) {
	t.Helper()
	base := testpath.CanonicalTempDir(t)
	root := filepath.Join(base, "config")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "candidate.yaml")
	if err := os.WriteFile(source, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "rules.yaml"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	transaction := newTransaction(filepath.Join(base, "transaction"))
	t.Cleanup(func() { _ = transaction.cleanup() })
	return transaction, root, source
}

// redirectConfigParent moves the original parent and redirects its former name to a separate fixture.
// redirectConfigParent 移动原始父目录，并将旧名称指向独立测试目录，返回原目录的新位置和外部目录。
func redirectConfigParent(t *testing.T, root string) (string, string) {
	t.Helper()
	external := testpath.CanonicalTempDir(t)
	if err := os.WriteFile(filepath.Join(external, "rules.yaml"), []byte("external"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "nested")
	moved := filepath.Join(root, "original-parent")
	if err := os.Rename(parent, moved); err != nil {
		// Windows pins the open directory against renames; this is an equivalent prevention boundary.
		// Windows 会阻止重命名已打开的目录；该拒绝本身即构成等效的防护边界。
		if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
			t.Log("Windows rejected replacement of the pinned directory")
			return parent, external
		}
		t.Fatalf("move configuration parent: %v", err)
	}
	if err := os.Symlink(external, parent); err != nil {
		if restoreErr := os.Rename(moved, parent); restoreErr != nil {
			t.Fatalf("restore parent after unavailable symlink: %v", restoreErr)
		}
		t.Skipf("symbolic links unavailable: %v", err)
	}
	return moved, external
}

// assertConfigContents verifies an exact fixture value without exposing real credentials.
// assertConfigContents 验证测试夹具的精确内容，不输出真实凭据。
func assertConfigContents(t *testing.T, path, expected string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != expected {
		t.Fatalf("fixture content = %q, want %q, error: %v", contents, expected, err)
	}
}
