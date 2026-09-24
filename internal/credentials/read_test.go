// This file verifies credential reads and recovery stay inside the selected directory.
// 本文件验证凭据读取与恢复始终限制在所选目录内，覆盖目录和文件链接替换。
package credentials

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/testpath"
)

// TestSnapshotUsesPinnedDirectory reads the original inode after an attempted parent redirection.
// TestSnapshotUsesPinnedDirectory 验证父目录被尝试重定向后仍读取原始目录中的文件。
func TestSnapshotUsesPinnedDirectory(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "config")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, ".env"), []byte("KEY=original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	moved := filepath.Join(base, "moved")
	if err := os.Rename(parent, moved); err != nil {
		if !testpath.PinnedDirectoryRenameBlocked(err) {
			t.Fatal(err)
		}
		t.Log("Windows rejected replacement of the pinned credential directory")
	} else {
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(parent, ".env"), []byte("KEY=external\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data, found, _, err := readSnapshot(root)
	if err != nil || !found || string(data) != "KEY=original\n" {
		t.Fatalf("pinned credential snapshot changed: found=%v error=%v", found, err)
	}
}

// TestSnapshotRejectsExternalFileLink refuses to read credentials through a link outside the selected parent.
// TestSnapshotRejectsExternalFileLink 验证凭据快照拒绝读取指向所选父目录之外的文件链接。
func TestSnapshotRejectsExternalFileLink(t *testing.T) {
	parent := t.TempDir()
	external := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(external, []byte("KEY=external\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, ".env")
	if err := os.Symlink(external, path); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if data, _, _, err := ReadSnapshot(path); err == nil || len(data) != 0 {
		t.Fatal("snapshot accepted an external file link")
	}
	if err := Restore(path, []byte("KEY=restored\n")); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(external)
	if err != nil || string(contents) != "KEY=external\n" {
		t.Fatal("credential recovery modified the external file")
	}
}
