// These tests verify strict path-record persistence without touching the real manager state.
// 这些测试验证严格路径记录持久化，不触碰真实管理器状态。
package pathctl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/testpath"
)

// TestRecordRoundTrip verifies complete platform metadata survives persistence.
// TestRecordRoundTrip 验证完整平台元数据可以持久化并恢复。
func TestRecordRoundTrip(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	filePath := filepath.Join(root, "path-record.json")
	want := validPathRecord(root)
	if err := SaveRecord(filePath, want); err != nil {
		t.Fatalf("SaveRecord() failed: %v", err)
	}
	got, err := LoadRecord(filePath)
	if err != nil {
		t.Fatalf("LoadRecord() failed: %v", err)
	}
	if got.Version != want.Version || !reflect.DeepEqual(got.Path, want.Path) || got.Method != want.Method || got.Directory != want.Directory || got.ProfilePath != want.ProfilePath || got.LinkPath != want.LinkPath || got.TargetPath != want.TargetPath || got.AfterSHA256 != want.AfterSHA256 || got.AfterType != want.AfterType || got.BlockSHA256 != want.BlockSHA256 {
		t.Fatalf("LoadRecord() = %#v, want %#v", got, want)
	}
}

// TestRecordPersistenceRejectsMalformedJSON protects strict JSON boundaries.
// TestRecordPersistenceRejectsMalformedJSON 保护严格 JSON 边界。
func TestRecordPersistenceRejectsMalformedJSON(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	valid, err := json.Marshal(validPathRecord(root))
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	cases := map[string][]byte{
		"duplicate": []byte(`{"version":1,"version":1}`),
		"unknown":   []byte(`{"version":1,"unknown":true}`),
		"trailing":  append(append([]byte(nil), valid...), []byte(" null")...),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			filePath := filepath.Join(root, name+".json")
			if err := os.WriteFile(filePath, body, 0o600); err != nil {
				t.Fatalf("write malformed fixture: %v", err)
			}
			if _, err := LoadRecord(filePath); err == nil {
				t.Fatalf("LoadRecord() accepted %s JSON", name)
			}
		})
	}
}

// TestRecordPersistenceRejectsOversize verifies the bounded reader before JSON decoding.
// TestRecordPersistenceRejectsOversize 验证 JSON 解码前的大小限制。
func TestRecordPersistenceRejectsOversize(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	filePath := filepath.Join(root, "oversize.json")
	if err := os.WriteFile(filePath, []byte(strings.Repeat("x", int(maxRecordBytes)+1)), 0o600); err != nil {
		t.Fatalf("write oversize fixture: %v", err)
	}
	if _, err := LoadRecord(filePath); err == nil {
		t.Fatal("LoadRecord() accepted an oversized record")
	}
}

// TestRecordPersistenceRejectsLinks prevents a record path from following links at rest.
// TestRecordPersistenceRejectsLinks 防止持久化记录路径跟随符号链接。
func TestRecordPersistenceRejectsLinks(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	realFile := filepath.Join(root, "real.json")
	if err := SaveRecord(realFile, validPathRecord(root)); err != nil {
		t.Fatalf("SaveRecord() failed: %v", err)
	}
	linkFile := filepath.Join(root, "link.json")
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := SaveRecord(linkFile, validPathRecord(root)); err == nil {
		t.Fatal("SaveRecord() accepted a symlink record file")
	}
	if _, err := LoadRecord(linkFile); err == nil {
		t.Fatal("LoadRecord() accepted a symlink record file")
	}
}

// TestRecordPersistenceRejectsSymlinkParent prevents records from escaping a selected root.
// TestRecordPersistenceRejectsSymlinkParent 防止记录通过符号链接逃出选定根目录。
func TestRecordPersistenceRejectsSymlinkParent(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatalf("create real directory: %v", err)
	}
	linkDirectory := filepath.Join(root, "link-dir")
	if err := os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	filePath := filepath.Join(linkDirectory, "path-record.json")
	if err := SaveRecord(filePath, validPathRecord(root)); err == nil {
		t.Fatal("SaveRecord() accepted a symlink parent directory")
	}
}

// TestRecordPersistenceRejectsRelativePath verifies callers must select an absolute record location.
// TestRecordPersistenceRejectsRelativePath 验证调用方必须选择绝对记录路径。
func TestRecordPersistenceRejectsRelativePath(t *testing.T) {
	if err := SaveRecord("path-record.json", validPathRecord(testpath.CanonicalTempDir(t))); err == nil {
		t.Fatal("SaveRecord() accepted a relative record path")
	}
}

// TestRecordPersistenceRejectsBroadPOSIXPermissions protects a record from shared-user edits.
// TestRecordPersistenceRejectsBroadPOSIXPermissions 防止共享用户修改路径记录。
func TestRecordPersistenceRejectsBroadPOSIXPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses ACLs rather than POSIX mode bits")
	}
	root := testpath.CanonicalTempDir(t)
	filePath := filepath.Join(root, "path-record.json")
	if err := SaveRecord(filePath, validPathRecord(root)); err != nil {
		t.Fatalf("SaveRecord() failed: %v", err)
	}
	if err := os.Chmod(filePath, 0o640); err != nil {
		t.Fatalf("chmod fixture: %v", err)
	}
	if _, err := LoadRecord(filePath); err == nil {
		t.Fatal("LoadRecord() accepted a group-readable path record")
	}
}

// validPathRecord creates a complete platform-specific non-secret record fixture.
// validPathRecord 创建完整的平台相关非敏感记录 fixture。
func validPathRecord(root string) Record {
	directory := filepath.Join(root, "manager")
	_ = os.Mkdir(directory, 0o700)
	if runtime.GOOS == "windows" {
		return Record{
			Version:     RecordVersion,
			Path:        state.PATHState{Owner: state.PATHOwnerManager, Scope: state.PATHScopeUser, Entries: []string{directory}},
			Method:      MethodWindowsUserPath,
			Directory:   directory,
			AfterSHA256: strings.Repeat("a", 64),
			AfterType:   2,
		}
	}
	profilePath := filepath.Join(root, ".profile")
	block := []byte("managed-profile-fixture")
	return Record{
		Version:     RecordVersion,
		Path:        state.PATHState{Owner: state.PATHOwnerManager, Scope: state.PATHScopeUser, Entries: []string{directory}},
		Method:      MethodUnixProfile,
		Directory:   directory,
		ProfilePath: profilePath,
		BlockSHA256: digest(block),
	}
}
