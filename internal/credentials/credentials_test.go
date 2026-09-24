// This file verifies parsing, secret-safe plans, permissions, ACL arguments, and atomic failure behavior.
// 本文件验证解析、无密钥计划、权限、ACL 参数和原子失败行为。
package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// TestParsePreservesLayoutAndEditsOnlyRequestedAssignments verifies comments, order, and inline comments survive updates.
// TestParsePreservesLayoutAndEditsOnlyRequestedAssignments 验证更新后注释、顺序和内联注释仍被保留。
func TestParsePreservesLayoutAndEditsOnlyRequestedAssignments(t *testing.T) {
	input := "# top\r\nexport FIRST = old # keep this\r\nUNKNOWN=raw#fragment\r\nSECOND=two\r\n"
	document, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if err := document.Set("FIRST", "new#value"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := document.Delete("SECOND"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	want := "# top\r\nexport FIRST='new#value' # keep this\r\nUNKNOWN=raw#fragment\r\n"
	if got := string(document.Render()); got != want {
		t.Fatalf("Render() = %q, want %q", got, want)
	}
	if names := document.Names(); !reflect.DeepEqual(names, []string{"FIRST", "UNKNOWN"}) {
		t.Fatalf("Names() = %#v", names)
	}
}

// TestApplyStoresMultipleValuesAndReturnsValueFreePlan verifies multi-key writes and dry-run visibility.
// TestApplyStoresMultipleValuesAndReturnsValueFreePlan 验证多密钥写入以及 dry-run 计划不包含值。
func TestApplyStoresMultipleValuesAndReturnsValueFreePlan(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	secret := "sk-secret-value"
	preview, err := DryRun(path, map[string]string{"Z_KEY": secret, "A_KEY": "second"}, nil)
	if err != nil {
		t.Fatalf("DryRun() error = %v", err)
	}
	for _, change := range preview.Changes {
		if strings.Contains(change.Name, secret) {
			t.Fatal("dry-run result contains secret")
		}
	}
	plan, err := Apply(path, map[string]string{"Z_KEY": secret, "A_KEY": "second"}, nil)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(plan.Changes) != 2 || plan.Changes[0].Name != "A_KEY" || plan.Changes[1].Name != "Z_KEY" {
		t.Fatalf("Apply() plan = %#v", plan.Changes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "Z_KEY='sk-secret-value'") {
		t.Fatalf("written .env does not contain quoted secret: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf(".env mode = %o, want 600", info.Mode().Perm())
	}
	document, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	value, ok, err := document.Get("Z_KEY")
	if err != nil || !ok || value != secret {
		t.Fatalf("Get() = (%q, %v, %v)", value, ok, err)
	}
}

// TestRejectsDuplicateInvalidAndInjectedInput ensures malformed files and newline injection fail without echoing secrets.
// TestRejectsDuplicateInvalidAndInjectedInput 确保重复、非法和换行注入输入失败且不回显密钥。
func TestRejectsDuplicateInvalidAndInjectedInput(t *testing.T) {
	if _, err := Parse(append([]byte{0xEF, 0xBB, 0xBF}, []byte("KEY=value\n")...)); !errors.Is(err, ErrInvalidSyntax) {
		t.Fatalf("BOM Parse() error = %v", err)
	}
	if _, err := Parse([]byte("KEY=one\nkey=two\n")); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate Parse() error = %v", err)
	}
	secret := "secret-do-not-echo"
	document, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	err = document.Set("KEY", secret+"\nINJECTED=1")
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("Set() error = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("Set() error echoed secret")
	}
	if _, err := Parse([]byte("not-an-assignment\n")); !errors.Is(err, ErrInvalidSyntax) {
		t.Fatalf("invalid syntax error = %v", err)
	}
	if _, err := DryRun(filepath.Join(t.TempDir(), ".env"), map[string]string{"BAD-NAME": secret}, nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("invalid name error = %v", err)
	}
}

// TestEncodingMatchesGodotenvSafeQuotedForms verifies values containing expansion syntax and quote characters.
// TestEncodingMatchesGodotenvSafeQuotedForms 验证包含展开语法和引号的值使用 godotenv 安全引号形式。
func TestEncodingMatchesGodotenvSafeQuotedForms(t *testing.T) {
	document, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	values := map[string]string{
		"PLAIN":    "alpha$BETA\\gamma#delta",
		"QUOTED":   "a'b\"c$D\\e",
		"SPACED":   " leading and trailing ",
		"FRAGMENT": "https://example.test/api#v1",
	}
	for name, value := range values {
		if err := document.Set(name, value); err != nil {
			t.Fatalf("Set(%q) error = %v", name, err)
		}
	}
	rendered := string(document.Render())
	if !strings.Contains(rendered, "PLAIN='alpha$BETA\\gamma#delta'") {
		t.Fatalf("plain value was not kept in literal single quotes: %q", rendered)
	}
	if !strings.Contains(rendered, `QUOTED="a'b\"c\$D\\e"`) {
		t.Fatalf("quoted value was not escaped for godotenv: %q", rendered)
	}
	parsed, err := Parse([]byte(rendered))
	if err != nil {
		t.Fatalf("round-trip Parse() error = %v", err)
	}
	for name, want := range values {
		got, ok, err := parsed.Get(name)
		if err != nil || !ok || got != want {
			t.Fatalf("round-trip Get(%q) = (%q, %v, %v), want %q", name, got, ok, err, want)
		}
	}
}

// TestDryRunAndApplyRejectConflictingCaseVariants verifies cross-platform duplicate protection.
// TestDryRunAndApplyRejectConflictingCaseVariants 验证跨平台大小写重复保护。
func TestDryRunAndApplyRejectConflictingCaseVariants(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	_, err := DryRun(path, map[string]string{"KEY": "one", "key": "two"}, nil)
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("DryRun() error = %v", err)
	}
	if _, err := Parse([]byte("A=one\nA=two\n")); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("Parse() error = %v", err)
	}
}

// TestAtomicFailureKeepsOriginal verifies replacement failures leave the original file and clean the temporary file.
// TestAtomicFailureKeepsOriginal 验证替换失败时原文件不变且临时文件被清理。
func TestAtomicFailureKeepsOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	original := []byte("KEY='old'\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	err := writeAtomicWith(path, []byte("KEY='new'\n"), func(string) error { return nil }, func(string, string) error {
		return errors.New("injected replacement failure")
	})
	if err == nil {
		t.Fatal("writeAtomicWith() succeeded unexpectedly")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("original changed after failed replacement: got %q want %q", got, original)
	}
	if temporary, globErr := filepath.Glob(filepath.Join(filepath.Dir(path), ".vmmm-env-*")); globErr != nil || len(temporary) != 0 {
		t.Fatalf("temporary files remain: %v", temporary)
	}
}

// TestAtomicWriterSecuresBeforeWritingSecret verifies the ACL hook runs while the temporary file is still empty.
// TestAtomicWriterSecuresBeforeWritingSecret 验证 ACL 钩子在临时文件仍为空时运行。
func TestAtomicWriterSecuresBeforeWritingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	securedBeforeWrite := false
	err := writeAtomicWith(path, []byte("KEY='secret'\n"), func(temporaryPath string) error {
		info, err := os.Stat(temporaryPath)
		if err != nil {
			return err
		}
		securedBeforeWrite = info.Size() == 0
		return nil
	}, func(source string, target string) error {
		return os.Rename(source, target)
	})
	if err != nil {
		t.Fatalf("writeAtomicWith() error = %v", err)
	}
	if !securedBeforeWrite {
		t.Fatal("security hook ran after secret bytes were written")
	}
}

// TestWindowsACLArgsNeverUseShellSyntax verifies the Windows ACL command is an argument vector.
// TestWindowsACLArgsNeverUseShellSyntax 验证 Windows ACL 命令使用参数向量而非 shell 语法。
func TestWindowsACLArgsNeverUseShellSyntax(t *testing.T) {
	args, err := windowsACLCommands(`C:\Users\tester\config\.env`, `CONTOSO\alice`)
	if err != nil {
		t.Fatalf("windowsACLCommands() error = %v", err)
	}
	want := [][]string{
		{`C:\Users\tester\config\.env`, "/reset"},
		{`C:\Users\tester\config\.env`, "/inheritance:r"},
		{`C:\Users\tester\config\.env`, "/grant:r", `CONTOSO\alice:(F)`, "SYSTEM:(F)"},
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("windowsACLCommands() = %#v, want %#v", args, want)
	}
	if _, err := windowsACLCommands(`C:\Users\tester\config\.env`, "bad\nuser"); err == nil {
		t.Fatal("windowsACLCommands() accepted control character")
	}
}

// TestRejectsSymlinkPreventsTargetFollowing verifies existing symlink paths cannot be read or replaced.
// TestRejectsSymlinkPreventsTargetFollowing 验证现有符号链接不能被读取或替换。
func TestRejectsSymlinkPreventsTargetFollowing(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("symlink fixture is platform-dependent")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	path := filepath.Join(directory, ".env")
	if err := os.WriteFile(target, []byte("KEY='target'\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() followed symlink")
	}
	if _, err := Apply(path, map[string]string{"KEY": "new"}, nil); err == nil {
		t.Fatal("Apply() accepted symlink")
	}
}
