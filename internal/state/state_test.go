// Package state tests the strict registration protocol and atomic persistence boundary.
// state 包测试严格登记协议和原子持久化边界。
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestSaveAndLoadRoundTrip verifies that a complete registration survives persistence.
// TestSaveAndLoadRoundTrip 验证完整登记信息能够持久化并恢复。
func TestSaveAndLoadRoundTrip(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "registration.json")
	want := validState(t)
	if err := Save(filePath, want); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	got, err := Load(filePath)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

// TestSaveCanReplaceExistingState verifies repeated saves replace the old registration.
// TestSaveCanReplaceExistingState 验证重复保存可以替换旧登记信息。
func TestSaveCanReplaceExistingState(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "registration.json")
	first := validState(t)
	if err := Save(filePath, first); err != nil {
		t.Fatalf("first Save() failed: %v", err)
	}

	second := first
	second.ManagerVersion = "0.2.0"
	second.Service = ServiceState{Name: "vmmm", AutoStart: true}
	if err := Save(filePath, second); err != nil {
		t.Fatalf("second Save() failed: %v", err)
	}

	got, err := Load(filePath)
	if err != nil {
		t.Fatalf("Load() after replacement failed: %v", err)
	}
	if !reflect.DeepEqual(got, second) {
		t.Fatalf("Load() after replacement = %#v, want %#v", got, second)
	}
}

// TestServiceUserPersistence verifies explicit Unix accounts round-trip while legacy records remain readable.
// TestServiceUserPersistence 验证显式 Unix 账户可往返持久化，同时旧登记仍可读取。
func TestServiceUserPersistence(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "registration.json")
	stateValue := validState(t)
	stateValue.Service = ServiceState{Name: "VulcanMemoryMesh", User: "vmm-service", AutoStart: true}
	if err := Save(filePath, stateValue); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}
	loaded, err := Load(filePath)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if loaded.Service != stateValue.Service {
		t.Fatalf("service round trip = %#v, want %#v", loaded.Service, stateValue.Service)
	}
	stateValue.Service.User = ""
	if err := Save(filePath, stateValue); err != nil {
		t.Fatalf("legacy Save() failed: %v", err)
	}
	if _, err := Load(filePath); err != nil {
		t.Fatalf("legacy Load() failed: %v", err)
	}
}

// TestServiceUserValidation rejects unsafe or orphaned account identities before state persistence.
// TestServiceUserValidation 在状态持久化前拒绝非法或无服务对应的账户标识。
func TestServiceUserValidation(t *testing.T) {
	for _, user := range []string{"-leading", ".leading", "name with space", "name/other", "name=other", strings.Repeat("a", 129)} {
		if err := validateService(ServiceState{Name: "VulcanMemoryMesh", User: user}); err == nil {
			t.Errorf("validateService accepted %q", user)
		}
	}
	if err := validateService(ServiceState{User: "alice"}); err == nil {
		t.Fatal("validateService accepted an account without a service")
	}
}

// TestLoadRejectsTruncatedAndInvalidJSON verifies malformed files never become state.
// TestLoadRejectsTruncatedAndInvalidJSON 验证截断和非法 JSON 不会被接受为状态。
func TestLoadRejectsTruncatedAndInvalidJSON(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "truncated", body: `{"protocol_version":1`},
		{name: "invalid", body: "this is not JSON"},
		{name: "trailing value", body: `{"protocol_version":1} {"protocol_version":1}`},
		{name: "duplicate key", body: `{"protocol_version":1,"protocol_version":1}`},
		{name: "unknown field", body: `{"protocol_version":1,"api_key":"must-not-be-accepted"}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			filePath := filepath.Join(t.TempDir(), "registration.json")
			if err := os.WriteFile(filePath, []byte(testCase.body), 0600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if _, err := Load(filePath); err == nil {
				t.Fatalf("Load() accepted %s JSON", testCase.name)
			}
		})
	}
}

// TestLoadRejectsUnknownVersionAndInvalidPath protects schema and path boundaries.
// TestLoadRejectsUnknownVersionAndInvalidPath 保护协议版本和路径边界。
func TestLoadRejectsUnknownVersionAndInvalidPath(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*State)
	}{
		{name: "unknown version", mutate: func(value *State) { value.ProtocolVersion = ProtocolVersion + 1 }},
		{name: "relative program root", mutate: func(value *State) { value.Paths.ProgramRoot = "relative/program" }},
		{name: "relative config root", mutate: func(value *State) { value.Paths.ConfigRoot = "relative/config" }},
		{name: "relative data root", mutate: func(value *State) { value.Paths.DataRoot = "relative/data" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			filePath := filepath.Join(t.TempDir(), "registration.json")
			value := validState(t)
			testCase.mutate(&value)
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("marshal fixture: %v", err)
			}
			if err := os.WriteFile(filePath, body, 0600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if _, err := Load(filePath); err == nil {
				t.Fatalf("Load() accepted %s", testCase.name)
			}
		})
	}
}

// TestFailedReplacementPreservesOldState verifies a failed replacement leaves the old file readable.
// TestFailedReplacementPreservesOldState 验证替换失败后旧文件仍然可以读取。
func TestFailedReplacementPreservesOldState(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "registration.json")
	oldState := validState(t)
	if err := Save(filePath, oldState); err != nil {
		t.Fatalf("initial Save() failed: %v", err)
	}
	newState := oldState
	newState.ManagerVersion = "new-version-that-must-not-commit"

	replacementErr := errors.New("injected replacement failure")
	err := saveWithReplace(filePath, newState, func(temporaryPath string, destinationPath string) error {
		if temporaryPath == "" || destinationPath == "" {
			t.Fatal("replacement received an empty path")
		}
		return replacementErr
	})
	if err == nil || !strings.Contains(err.Error(), replacementErr.Error()) {
		t.Fatalf("saveWithReplace() error = %v, want injected replacement failure", err)
	}

	got, err := Load(filePath)
	if err != nil {
		t.Fatalf("Load() after failed replacement failed: %v", err)
	}
	if !reflect.DeepEqual(got, oldState) {
		t.Fatalf("state after failed replacement = %#v, want %#v", got, oldState)
	}
}

// TestStateJSONContainsNoSecretFields verifies the persisted schema has no credential fields.
// TestStateJSONContainsNoSecretFields 验证持久化协议不包含凭据字段。
func TestStateJSONContainsNoSecretFields(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "registration.json")
	if err := Save(filePath, validState(t)); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}
	body, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	serialized := strings.ToLower(string(body))
	for _, forbidden := range []string{"api_key", "apikey", "password", "dsn"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("state file contains forbidden field text %q: %s", forbidden, serialized)
		}
	}
}

// TestSaveRejectsCredentialBearingCustomPrefix verifies custom source input cannot carry URL credentials.
// TestSaveRejectsCredentialBearingCustomPrefix 验证自定义源前缀不能携带 URL 凭据。
func TestSaveRejectsCredentialBearingCustomPrefix(t *testing.T) {
	value := validState(t)
	value.DownloadSource = DownloadSource{
		ID:           "github-proxy-custom",
		CustomPrefix: "https://user:password@example.test/",
	}
	if err := Save(filepath.Join(t.TempDir(), "registration.json"), value); err == nil {
		t.Fatal("Save() accepted credential-bearing custom prefix")
	}
}

// validState creates a complete state with deterministic non-secret fixture data.
// validState 创建包含确定性非敏感 fixture 数据的完整状态。
func validState(t *testing.T) State {
	t.Helper()
	root := t.TempDir()
	return State{
		ProtocolVersion: ProtocolVersion,
		ManagerVersion:  "0.1.0",
		VMM: VMMIdentity{
			Tag:      "v0.1.0",
			Commit:   "0123456789abcdef0123456789abcdef01234567",
			Platform: "windows-x64",
		},
		Paths: InstallPaths{
			ProgramRoot: filepath.Join(root, "program"),
			ConfigRoot:  filepath.Join(root, "config"),
			DataRoot:    filepath.Join(root, "data"),
		},
		DownloadSource: DownloadSource{ID: "github-official", CustomPrefix: ""},
		Service:        ServiceState{Name: "", AutoStart: false},
		PATH:           PATHState{Owner: PATHOwnerNone, Scope: PATHScopeNone, Entries: []string{}},
		ManagedFiles: []ManagedFile{{
			Path:   "bin/vmm-local.exe",
			SHA256: strings.Repeat("0", 64),
			Size:   123,
		}},
	}
}
