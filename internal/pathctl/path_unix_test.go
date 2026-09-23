//go:build !windows

// These tests use temporary POSIX files to verify marked profiles and safe command links.
// 这些测试使用临时 POSIX 文件验证带标记 profile 与安全命令链接。
package pathctl

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// TestProfileRoundTripPreservesSurroundingEdits verifies exact block ownership and reversal.
// TestProfileRoundTripPreservesSurroundingEdits 验证片段所有权与周围内容的精确保留。
func TestProfileRoundTripPreservesSurroundingEdits(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "manager")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create manager directory: %v", err)
	}
	profile := filepath.Join(root, ".profile")
	before := []byte("# user setting\nexport EDITOR=vi\n")
	if err := os.WriteFile(profile, before, 0o640); err != nil {
		t.Fatalf("write profile fixture: %v", err)
	}
	controller := New()
	record, err := controller.Install(Options{Method: MethodUnixProfile, Directory: directory, ProfilePath: profile})
	if err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	if record.Path.Owner != state.PATHOwnerManager || record.Path.Scope != state.PATHScopeUser {
		t.Fatalf("record ownership = %#v, want manager/user", record.Path)
	}
	installed, err := os.ReadFile(profile)
	if err != nil {
		t.Fatalf("read installed profile: %v", err)
	}
	if !strings.Contains(string(installed), profileStart) || !strings.Contains(string(installed), shellQuote(directory)) {
		t.Fatalf("installed profile does not contain the expected managed block: %q", installed)
	}

	// The user edits content outside the marked block; removal must retain that edit.
	// 用户编辑带标记片段之外的内容；撤销必须保留该编辑。
	changedOutside := append([]byte("# user setting\nexport EDITOR=nvim\n"), installed[len(before):]...)
	if err := os.WriteFile(profile, changedOutside, 0o640); err != nil {
		t.Fatalf("apply user edit: %v", err)
	}
	if err := controller.Remove(record); err != nil {
		t.Fatalf("Remove() failed: %v", err)
	}
	removed, err := os.ReadFile(profile)
	if err != nil {
		t.Fatalf("read removed profile: %v", err)
	}
	if string(removed) != "# user setting\nexport EDITOR=nvim\n" {
		t.Fatalf("profile after removal = %q", removed)
	}
}

// TestProfileRemovalRejectsEditedManagedBlock prevents deletion after block tampering.
// TestProfileRemovalRejectsEditedManagedBlock 防止片段被篡改后继续删除。
func TestProfileRemovalRejectsEditedManagedBlock(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "manager")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create manager directory: %v", err)
	}
	profile := filepath.Join(root, ".profile")
	if err := os.WriteFile(profile, []byte("# user\n"), 0o600); err != nil {
		t.Fatalf("write profile fixture: %v", err)
	}
	controller := New()
	record, err := controller.Install(Options{Method: MethodUnixProfile, Directory: directory, ProfilePath: profile})
	if err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	body, err := os.ReadFile(profile)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	body = []byte(strings.Replace(string(body), `"$PATH"`, `"$PATH:/user-edit"`, 1))
	if err := os.WriteFile(profile, body, 0o600); err != nil {
		t.Fatalf("tamper profile: %v", err)
	}
	if err := controller.Remove(record); !errors.Is(err, ErrChanged) {
		t.Fatalf("Remove() error = %v, want ErrChanged", err)
	}
	untouched, err := os.ReadFile(profile)
	if err != nil {
		t.Fatalf("read tampered profile: %v", err)
	}
	if !strings.Contains(string(untouched), "/user-edit") {
		t.Fatal("tampered profile was changed")
	}
}

// TestProfileInstallRejectsExistingDirectoryMention verifies conflict detection outside managed blocks.
// TestProfileInstallRejectsExistingDirectoryMention 验证受管片段外的目录冲突检测。
func TestProfileInstallRejectsExistingDirectoryMention(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "manager")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create manager directory: %v", err)
	}
	profile := filepath.Join(root, ".profile")
	if err := os.WriteFile(profile, []byte("export PATH='"+directory+"':\"$PATH\"\n"), 0o600); err != nil {
		t.Fatalf("write profile fixture: %v", err)
	}
	if _, err := New().Install(Options{Method: MethodUnixProfile, Directory: directory, ProfilePath: profile}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Install() error = %v, want ErrConflict", err)
	}
}

// TestLocalBinRoundTripVerifiesTarget verifies link creation and identity-checked removal.
// TestLocalBinRoundTripVerifiesTarget 验证链接创建与身份检查后的撤销。
func TestLocalBinRoundTripVerifiesTarget(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "manager")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create manager directory: %v", err)
	}
	target := filepath.Join(directory, "vmmm")
	if err := os.WriteFile(target, []byte("binary"), 0o700); err != nil {
		t.Fatalf("write target: %v", err)
	}
	linkPath := filepath.Join(root, ".local", "bin", "vmmm")
	controller := New()
	record, err := controller.Install(Options{Method: MethodUnixLocalBin, Directory: directory, LinkPath: linkPath, TargetPath: target})
	if err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	linkTarget, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink() failed: %v", err)
	}
	if filepath.Clean(linkTarget) != filepath.Clean(target) {
		t.Fatalf("link target = %q, want %q", linkTarget, target)
	}
	if err := controller.Remove(record); err != nil {
		t.Fatalf("Remove() failed: %v", err)
	}
	if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("link after removal error = %v, want not-exist", err)
	}
}

// TestLocalBinRemovalRejectsReplacement preserves a user replacement at the same link path.
// TestLocalBinRemovalRejectsReplacement 保护用户在同一路径替换的链接。
func TestLocalBinRemovalRejectsReplacement(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "manager")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create manager directory: %v", err)
	}
	target := filepath.Join(directory, "vmmm")
	other := filepath.Join(root, "other")
	for _, path := range []string{target, other} {
		if err := os.WriteFile(path, []byte("binary"), 0o700); err != nil {
			t.Fatalf("write target %s: %v", path, err)
		}
	}
	linkPath := filepath.Join(root, "bin", "vmmm")
	controller := New()
	record, err := controller.Install(Options{Method: MethodUnixLocalBin, Directory: directory, LinkPath: linkPath, TargetPath: target})
	if err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	if err := os.Remove(linkPath); err != nil {
		t.Fatalf("remove original link: %v", err)
	}
	if err := os.Symlink(other, linkPath); err != nil {
		t.Fatalf("create replacement link: %v", err)
	}
	if err := controller.Remove(record); !errors.Is(err, ErrChanged) {
		t.Fatalf("Remove() error = %v, want ErrChanged", err)
	}
	if _, err := os.Lstat(linkPath); err != nil {
		t.Fatalf("replacement link was removed: %v", err)
	}
}

// TestProfileSymlinkIsRejected verifies that a selected profile symlink is never followed for writes.
// TestProfileSymlinkIsRejected 验证不会跟随被选择 profile 的符号链接写入。
func TestProfileSymlinkIsRejected(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "manager")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create manager directory: %v", err)
	}
	target := filepath.Join(root, "real-profile")
	profile := filepath.Join(root, ".profile")
	if err := os.WriteFile(target, []byte("# user\n"), 0o600); err != nil {
		t.Fatalf("write real profile: %v", err)
	}
	if err := os.Symlink(target, profile); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := New().Install(Options{Method: MethodUnixProfile, Directory: directory, ProfilePath: profile}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Install() error = %v, want ErrConflict", err)
	}
}
