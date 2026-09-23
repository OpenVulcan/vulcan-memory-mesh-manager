//go:build windows

// These tests exercise Windows PATH decisions with injected registry and broadcast boundaries.
// 这些测试通过注入注册表和广播边界验证 Windows PATH 决策。
package pathctl

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

// fakeRegistry stores one in-memory HKCU PATH value for deterministic tests.
// fakeRegistry 为确定性测试保存一个内存中的 HKCU PATH 值。
type fakeRegistry struct {
	// value is the current simulated registry value.
	// value 是当前模拟的注册表值。
	value registryValue

	// setCalls counts writes to verify no-op and rollback behavior.
	// setCalls 统计写入次数，用于验证无操作和回滚行为。
	setCalls int
}

// ReadPath returns the simulated current-user PATH value.
// ReadPath 返回模拟的当前用户 PATH 值。
func (f *fakeRegistry) ReadPath() (registryValue, error) { return f.value, nil }

// SetPath updates the simulated registry value.
// SetPath 更新模拟的注册表值。
func (f *fakeRegistry) SetPath(value string, valueType uint32) error {
	f.value = registryValue{Value: value, Type: valueType, Present: true}
	f.setCalls++
	return nil
}

// DeletePath removes the simulated registry value.
// DeletePath 删除模拟的注册表值。
func (f *fakeRegistry) DeletePath() error {
	f.value = registryValue{}
	return nil
}

// fakeBroadcaster records notifications and can inject a delivery failure.
// fakeBroadcaster 记录通知并可注入发送失败。
type fakeBroadcaster struct {
	// calls records how many broadcasts were requested.
	// calls 记录请求广播的次数。
	calls int

	// err is returned to simulate a Windows notification failure.
	// err 用于模拟 Windows 通知失败。
	err error
}

// Broadcast records one notification request.
// Broadcast 记录一次通知请求。
func (f *fakeBroadcaster) Broadcast() error {
	f.calls++
	return f.err
}

// TestWindowsInstallAndRemoveRoundTrip verifies user PATH append and exact reversal.
// TestWindowsInstallAndRemoveRoundTrip 验证用户 PATH 追加与精确撤销。
func TestWindowsInstallAndRemoveRoundTrip(t *testing.T) {
	directory := t.TempDir()
	registry := &fakeRegistry{value: registryValue{Value: `C:\Tools;C:\Bin`, Type: registryValueExpandString, Present: true}}
	broadcaster := &fakeBroadcaster{}
	controller := newController(registry, broadcaster)

	record, err := controller.Install(Options{Method: MethodWindowsUserPath, Directory: directory})
	if err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	if record.Path.Owner != state.PATHOwnerManager || record.Path.Scope != state.PATHScopeUser {
		t.Fatalf("record ownership = %#v, want manager/user", record.Path)
	}
	if registry.value.Value != `C:\Tools;C:\Bin;`+directory {
		t.Fatalf("registry PATH = %q", registry.value.Value)
	}
	if broadcaster.calls != 1 {
		t.Fatalf("broadcast calls = %d, want 1", broadcaster.calls)
	}

	if err := controller.Remove(record); err != nil {
		t.Fatalf("Remove() failed: %v", err)
	}
	if registry.value.Value != `C:\Tools;C:\Bin` {
		t.Fatalf("registry PATH after removal = %q", registry.value.Value)
	}
	if broadcaster.calls != 2 {
		t.Fatalf("broadcast calls after removal = %d, want 2", broadcaster.calls)
	}
}

// TestWindowsInstallRejectsDuplicateDirectory protects against ambiguous removal ownership.
// TestWindowsInstallRejectsDuplicateDirectory 防止重复目录导致撤销所有权歧义。
func TestWindowsInstallRejectsDuplicateDirectory(t *testing.T) {
	directory := t.TempDir()
	registry := &fakeRegistry{value: registryValue{Value: directory + `;` + directory, Type: registryValueExpandString, Present: true}}
	controller := newController(registry, &fakeBroadcaster{})
	if _, err := controller.Install(Options{Method: MethodWindowsUserPath, Directory: directory}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Install() error = %v, want ErrConflict", err)
	}
	if registry.setCalls != 0 {
		t.Fatalf("duplicate detection wrote registry %d times", registry.setCalls)
	}
}

// TestWindowsInstallRejectsPathLimit verifies UTF-16 length checking before registry mutation.
// TestWindowsInstallRejectsPathLimit 验证注册表变更前的 UTF-16 长度检查。
func TestWindowsInstallRejectsPathLimit(t *testing.T) {
	directory := t.TempDir()
	registry := &fakeRegistry{value: registryValue{Value: strings.Repeat("a", windowsPathMaxUTF16Units), Type: registryValueExpandString, Present: true}}
	controller := newController(registry, &fakeBroadcaster{})
	if _, err := controller.Install(Options{Method: MethodWindowsUserPath, Directory: directory}); err == nil {
		t.Fatal("Install() accepted an overlong PATH")
	}
	if registry.setCalls != 0 {
		t.Fatalf("overlong PATH wrote registry %d times", registry.setCalls)
	}
}

// TestWindowsInstallRollsBackWhenBroadcastFails keeps registry state unchanged on notification failure.
// TestWindowsInstallRollsBackWhenBroadcastFails 验证通知失败时注册表状态回滚。
func TestWindowsInstallRollsBackWhenBroadcastFails(t *testing.T) {
	directory := t.TempDir()
	original := registryValue{Value: `C:\Tools`, Type: registryValueExpandString, Present: true}
	registry := &fakeRegistry{value: original}
	broadcaster := &fakeBroadcaster{err: errors.New("notification failed")}
	controller := newController(registry, broadcaster)
	if _, err := controller.Install(Options{Method: MethodWindowsUserPath, Directory: directory}); err == nil {
		t.Fatal("Install() succeeded despite broadcast failure")
	}
	if registry.value != original {
		t.Fatalf("registry value after rollback = %#v, want %#v", registry.value, original)
	}
}

// TestWindowsRemoveRefusesEditedPath preserves user edits made after installation.
// TestWindowsRemoveRefusesEditedPath 保护安装后用户对 PATH 的编辑。
func TestWindowsRemoveRefusesEditedPath(t *testing.T) {
	directory := t.TempDir()
	registry := &fakeRegistry{value: registryValue{Value: `C:\Tools`, Type: registryValueExpandString, Present: true}}
	controller := newController(registry, &fakeBroadcaster{})
	record, err := controller.Install(Options{Method: MethodWindowsUserPath, Directory: directory})
	if err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	registry.value.Value += `;C:\UserChange`
	beforeCalls := registry.setCalls
	if err := controller.Remove(record); !errors.Is(err, ErrChanged) {
		t.Fatalf("Remove() error = %v, want ErrChanged", err)
	}
	if registry.setCalls != beforeCalls {
		t.Fatalf("edited PATH removal wrote registry %d additional times", registry.setCalls-beforeCalls)
	}
}

// TestWindowsExistingDirectoryIsExternal verifies that pre-existing user PATH entries are never owned.
// TestWindowsExistingDirectoryIsExternal 验证安装前已有的用户 PATH 条目不会被取得所有权。
func TestWindowsExistingDirectoryIsExternal(t *testing.T) {
	directory := filepath.Clean(t.TempDir())
	registry := &fakeRegistry{value: registryValue{Value: directory, Type: registryValueExpandString, Present: true}}
	broadcaster := &fakeBroadcaster{}
	controller := newController(registry, broadcaster)
	record, err := controller.Install(Options{Method: MethodWindowsUserPath, Directory: directory})
	if err != nil {
		t.Fatalf("Install() failed: %v", err)
	}
	if record.Path.Owner != state.PATHOwnerExternal {
		t.Fatalf("record owner = %q, want external", record.Path.Owner)
	}
	if broadcaster.calls != 0 || registry.setCalls != 0 {
		t.Fatalf("pre-existing PATH was modified: broadcasts=%d writes=%d", broadcaster.calls, registry.setCalls)
	}
	if err := controller.Remove(record); err != nil {
		t.Fatalf("Remove() for external record failed: %v", err)
	}
}
