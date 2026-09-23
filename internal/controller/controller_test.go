// Package controller tests the manager orchestration boundary with real package verification and reversible adapters.
// controller 包使用真实安装包校验与可逆适配器测试管理器编排边界。
package controller

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/archive"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configbridge"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/configedit"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/fetch"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/install"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/manifest"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/pathctl"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/platform"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/release"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/service"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/testpath"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/tui"
)

// TestDisplayFieldsLoadsStructuredValues checks the advanced editor receives existing collections.
// TestDisplayFieldsLoadsStructuredValues 检查高级编辑器能够获得现有集合配置。
func TestDisplayFieldsLoadsStructuredValues(t *testing.T) {
	schema := configbridge.Schema{Fields: []configbridge.Field{
		{Path: "llm.routes", Type: "array"},
		{Path: "llm.routes[].model", Type: "string"},
		{Path: "llm.routes[].api_keys", Type: "array", Sensitive: true},
		{Path: "embedding", Type: "object"},
		{Path: "credential", Type: "string", Sensitive: true},
	}}
	fields, err := displayFields(schema, []byte("llm:\n  routes:\n    - model: chat-1\n      api_keys: [hidden-route-key]\nembedding:\n  dimensions: 3\ncredential: hidden-value\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 || fields[0].Value != "<configured>" || !fields[0].Sensitive || !fields[0].Editable || fields[1].Path != "llm.routes[0].model" || fields[1].Value != "chat-1" || fields[2].Value != "<configured>" || !fields[2].Sensitive || !fields[2].Editable || !strings.Contains(fields[3].Value, "dimensions: 3") {
		t.Fatalf("structured fields were not loaded: %+v", fields)
	}
	if fields[4].Value != "<configured>" || !fields[4].Editable {
		t.Fatalf("sensitive field was exposed: %+v", fields[4])
	}
}

// TestSensitiveFieldRequiresEnvironmentReference prevents writing a raw secret to YAML.
// TestSensitiveFieldRequiresEnvironmentReference 防止将原始秘密写入 YAML。
func TestSensitiveFieldRequiresEnvironmentReference(t *testing.T) {
	for _, value := range []string{"plain-secret", "${BAD-NAME}", "${GOOD}suffix"} {
		if err := validateSensitiveReference("string", value); err == nil {
			t.Errorf("raw or invalid secret reference %q was accepted", value)
		}
	}
	if err := validateSensitiveReference("string", "${MANAGEMENT_TOKEN}"); err != nil {
		t.Fatalf("valid secret reference rejected: %v", err)
	}
	if err := validateSensitiveReference("array", "- ${VMM_KEY_ONE}\n- '${VMM_KEY_TWO}'\n"); err != nil {
		t.Fatalf("valid secret array rejected: %v", err)
	}
	for _, value := range []string{"- raw-secret\n", "- ${VMM_KEY}\n---\n- ${SECOND}\n", "key: ${VMM_KEY}\n"} {
		if err := validateSensitiveReference("array", value); err == nil {
			t.Errorf("invalid sensitive array %q was accepted", value)
		}
	}
}

// TestRollbackServiceActionRestoresNativeRegistration checks state-write compensation paths.
// TestRollbackServiceActionRestoresNativeRegistration 检查状态写入失败后的系统服务补偿路径。
func TestRollbackServiceActionRestoresNativeRegistration(t *testing.T) {
	previous := state.ServiceState{Name: "vmm-local", User: "alice", AutoStart: true}
	tests := []struct {
		action     tui.ServiceAction
		previous   state.ServiceState
		wasRunning bool
		wantCalls  string
	}{
		{action: tui.ServiceActionInstall, wantCalls: "uninstall"},
		{action: tui.ServiceActionUninstall, previous: previous, wasRunning: true, wantCalls: "install,start"},
		{action: tui.ServiceActionEnable, previous: previous, wantCalls: "disable"},
		{action: tui.ServiceActionDisable, previous: previous, wantCalls: "enable"},
	}
	for _, test := range tests {
		adapter := &fakeService{}
		if err := rollbackServiceAction(context.Background(), adapter, "vmm-local", "config", test.previous, test.wasRunning, test.action); err != nil {
			t.Fatalf("rollback %s: %v", test.action, err)
		}
		if got := strings.Join(adapter.calls, ","); got != test.wantCalls {
			t.Errorf("rollback %s calls = %q, want %q", test.action, got, test.wantCalls)
		}
		if test.action == tui.ServiceActionUninstall && adapter.lastUser != previous.User {
			t.Errorf("restored user = %q, want %q", adapter.lastUser, previous.User)
		}
	}
}

// TestExpandSchemaPathUsesExistingIndexes verifies nested template paths map to real YAML entries.
// TestExpandSchemaPathUsesExistingIndexes 验证嵌套模板路径只映射到真实 YAML 元素。
func TestExpandSchemaPathUsesExistingIndexes(t *testing.T) {
	draft, err := configedit.Parse([]byte("llm:\n  routes:\n    - nodes:\n        - name: first\n        - name: second\n    - nodes: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	paths, err := expandSchemaPath(draft, "llm.routes[].nodes[].name")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(paths, ","); got != "llm.routes[0].nodes[0].name,llm.routes[0].nodes[1].name" {
		t.Fatalf("expanded paths = %q", got)
	}
}

// TestNewRejectsEmptyTrustRoot verifies that the controller cannot operate without injected trust.
// TestNewRejectsEmptyTrustRoot 验证 controller 没有注入信任根时不能运行。
func TestNewRejectsEmptyTrustRoot(t *testing.T) {
	identity, err := platform.Current()
	if err != nil {
		t.Fatal(err)
	}
	base := testpath.CanonicalTempDir(t)
	_, err = New(Options{
		ManagerVersion: "vmmm-test",
		ManagerRoot:    filepath.Join(base, "manager"),
		StatePath:      filepath.Join(base, "state.json"),
		CacheRoot:      filepath.Join(base, "cache"),
		Identity:       identity,
	})
	if err == nil {
		t.Fatal("New unexpectedly accepted an empty trust root")
	}
}

// TestProviderWizardAndCredentials verifies typed provider defaults and value-free credential state.
// TestProviderWizardAndCredentials 验证强类型供应商默认值和不含秘密的凭据状态。
func TestProviderWizardAndCredentials(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	credentialPath := filepath.Join(plan.ConfigRoot, ".env")
	if err := os.MkdirAll(filepath.Dir(credentialPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialPath, []byte("TEST_PROVIDER_KEY='configured-secret'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := controller.OpenProviderWizard(context.Background(), tui.ProviderWizardRequest{
		Purpose: tui.ProviderPurposeLLM,
		Draft: tui.ProviderDraft{
			Provider:               "openrouter",
			APIKeyEnvironmentNames: []string{"TEST_PROVIDER_KEY"},
			CredentialPath:         credentialPath,
			APIKeyValue:            "must-not-return",
		},
	})
	if err != nil {
		t.Fatalf("OpenProviderWizard() error = %v", err)
	}
	if !result.Draft.CredentialConfigured || result.Draft.APIKeyValue != "" {
		t.Fatalf("provider draft leaked or missed credential state: %+v", result.Draft)
	}
	if result.Draft.Endpoint != "https://openrouter.ai/api/v1" {
		t.Fatalf("provider default endpoint = %q", result.Draft.Endpoint)
	}
	if len(result.Providers) == 0 {
		t.Fatal("provider catalog is empty")
	}
}

// TestStageValidateCommitAndCredentialApply exercises the complete two-phase controller transaction.
// TestStageValidateCommitAndCredentialApply 覆盖完整的两阶段暂存、校验、提交和凭据写入事务。
func TestStageValidateCommitAndCredentialApply(t *testing.T) {
	controller, plan, fixture := newFixtureController(t)
	// Existing rules and credentials must reach validation without receiving draft changes on disk.
	// 现有规则及凭据必须参与候选校验，同时磁盘上的正式配置不能提前接收草稿变更。
	rulePath := filepath.Join(plan.ConfigRoot, "noise_rules", "custom.yaml")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulePath, []byte("rule: preserved\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalCredential := []byte("UNCHANGED_KEY=existing-value\n")
	if err := os.WriteFile(filepath.Join(plan.ConfigRoot, ".env"), originalCredential, 0o600); err != nil {
		t.Fatal(err)
	}
	validate := controller.options.Validate
	controller.options.Validate = func(ctx context.Context, binaryPath, root string) (configbridge.ValidationResult, error) {
		data, err := os.ReadFile(filepath.Join(root, ".env"))
		if err != nil || !bytes.Contains(data, []byte("provider-secret-value")) || !bytes.Contains(data, []byte("existing-value")) {
			return configbridge.ValidationResult{}, errors.New("candidate credentials are incomplete")
		}
		rule, err := os.ReadFile(filepath.Join(root, "noise_rules", "custom.yaml"))
		if err != nil || string(rule) != "rule: preserved\n" {
			return configbridge.ValidationResult{}, errors.New("candidate rule override is missing")
		}
		return validate(ctx, binaryPath, root)
	}
	plan.Providers = tui.ProviderPlan{
		LLMRoutes: []tui.ProviderRoute{{
			Provider:               "openrouter",
			Model:                  "openai/gpt-4o-mini",
			APIKeyEnvironmentNames: []string{"VMMM_TEST_API_KEY"},
		}},
		CredentialPath: filepath.Join(plan.ConfigRoot, ".env"),
		CredentialUpdates: []tui.CredentialUpdate{{
			EnvironmentName: "VMMM_TEST_API_KEY",
			Value:           "provider-secret-value",
		}},
	}

	stageEvents := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})
	if terminalKind(stageEvents) != tui.OperationEventCompleted {
		t.Fatalf("stage terminal event = %v, events = %#v", terminalKind(stageEvents), stageEvents)
	}
	if !hasVerifiedPackage(stageEvents) {
		t.Fatal("stage operation did not emit verified package metadata")
	}

	fields, err := controller.OpenConfigFields(context.Background(), tui.ConfigFieldsRequest{Prefix: "storage"})
	if err != nil {
		t.Fatalf("OpenConfigFields() error = %v", err)
	}
	if len(fields.Fields) == 0 {
		t.Fatal("schema-backed storage fields are empty")
	}

	validateEvents := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationValidate, Plan: plan})
	if terminalKind(validateEvents) != tui.OperationEventCompleted {
		t.Fatalf("validate terminal event = %v, events = %#v", terminalKind(validateEvents), validateEvents)
	}
	if _, err := os.Stat(plan.ProgramRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("program root after candidate validation = %v, want missing", err)
	}
	if data, err := os.ReadFile(filepath.Join(plan.ConfigRoot, ".env")); err != nil || !bytes.Equal(data, originalCredential) {
		t.Fatal("candidate validation modified installed credentials")
	}

	installEvents := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})
	if terminalKind(installEvents) != tui.OperationEventCompleted {
		t.Fatalf("install terminal event = %v, events = %#v", terminalKind(installEvents), installEvents)
	}
	if _, err := os.Stat(filepath.Join(plan.ProgramRoot, filepath.FromSlash(fixture.identity.VMMExecutablePath))); err != nil {
		t.Fatalf("installed VMM binary is missing: %v", err)
	}
	configBytes, err := os.ReadFile(filepath.Join(plan.ConfigRoot, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(configBytes, []byte("${VMMM_TEST_API_KEY}")) || bytes.Contains(configBytes, []byte("provider-secret-value")) {
		t.Fatalf("provider configuration does not contain a safe reference: %s", configBytes)
	}
	credentialBytes, err := os.ReadFile(filepath.Join(plan.ConfigRoot, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(credentialBytes, []byte("provider-secret-value")) {
		t.Fatal("provider credential was not written to .env")
	}
	installed, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatalf("state.Load() error = %v", err)
	}
	if installed.VMM.Tag != fixture.tag || installed.Paths != (state.InstallPaths{ProgramRoot: plan.ProgramRoot, ConfigRoot: plan.ConfigRoot, DataRoot: plan.DataRoot}) {
		t.Fatalf("unexpected installed state: %+v", installed)
	}
}

// TestFailedCommitRollsBackCredentialFile checks that a failed final transaction removes newly written secrets.
// TestFailedCommitRollsBackCredentialFile 验证最终事务失败时会移除本次新写入的秘密。
func TestFailedCommitRollsBackCredentialFile(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.Providers = tui.ProviderPlan{
		CredentialPath: filepath.Join(plan.ConfigRoot, ".env"),
		CredentialUpdates: []tui.CredentialUpdate{{
			EnvironmentName: "VMMM_TEST_API_KEY",
			Value:           "rollback-secret",
		}},
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("stage terminal event = %v", terminal)
	}
	controller.options.Validate = func(context.Context, string, string) (configbridge.ValidationResult, error) {
		return configbridge.ValidationResult{Valid: false, Errors: []configbridge.ValidationError{{Path: "storage.mode", Message: "invalid mode"}}}, nil
	}
	events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})
	if terminalKind(events) != tui.OperationEventFailed {
		t.Fatalf("install terminal event = %v, events = %#v", terminalKind(events), events)
	}
	if _, err := os.Stat(filepath.Join(plan.ConfigRoot, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential file after failed commit = %v, want missing", err)
	}
}

// TestValidateServiceLoggingConfiguredRequiresExplicitRoot rejects legacy overlays that would write service logs into the package.
// TestValidateServiceLoggingConfiguredRequiresExplicitRoot 拒绝会把服务日志写入程序包的旧覆盖配置。
func TestValidateServiceLoggingConfiguredRequiresExplicitRoot(t *testing.T) {
	root := testpath.CanonicalTempDir(t)
	configPath := filepath.Join(root, defaultConfigFileName)
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateServiceLoggingConfigured(root); err == nil {
		t.Fatal("legacy service logging default unexpectedly accepted")
	}
	config := []byte("logging:\n  directory: " + strconv.Quote(filepath.Join(root, "logs")) + "\n")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateServiceLoggingConfigured(root); err != nil {
		t.Fatalf("explicit service log directory rejected: %v", err)
	}
}

// TestServiceAndPathLifecycleUsesDurableState exercises service status parsing and reversible PATH state.
// TestServiceAndPathLifecycleUsesDurableState 验证服务状态读取和可逆 PATH 状态均来自持久化安装信息。
func TestServiceAndPathLifecycleUsesDurableState(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	// Create the registration through the actual installer so Windows ACLs and Unix control ownership match production.
	// 通过真实安装事务创建登记，使 Windows ACL 和 Unix 控制目录归属与生产一致。
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatal("fixture installation failed")
		}
	}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationService, TargetMode: tui.ServiceModeForeground, ServiceAction: tui.ServiceActionStop})) != tui.OperationEventCompleted {
		t.Fatal("foreground runtime could not be stopped before service registration")
	}
	installed, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	serviceAdapter := &fakeService{status: service.Status{State: "running", AutoStart: "true"}}
	pathAdapter := &fakePath{}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return serviceAdapter, nil }
	controller.options.PathFactory = func() PathClient { return pathAdapter }
	controller.options.ManagerRoot = plan.ProgramRoot
	releaseLock, err := install.LockInstallation(context.Background(), controller.options.StatePath)
	if err != nil {
		t.Fatalf("lock existing fixture: %v", err)
	}
	_ = releaseLock()

	serviceEvents := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationService, TargetMode: tui.ServiceModeService, ServiceAction: tui.ServiceActionInstall, Plan: tui.InstallPlan{AutoStart: true, ServiceUser: currentServiceUser(t)}})
	if terminalKind(serviceEvents) != tui.OperationEventCompleted || !serviceAdapter.called("install") {
		t.Fatalf("service install failed: terminal=%v calls=%v events=%+v", terminalKind(serviceEvents), serviceAdapter.calls, serviceEvents)
	}
	registered, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatalf("state.Load() after service install = %v", err)
	}
	wantServiceUser := ""
	if runtime.GOOS != "windows" {
		wantServiceUser = currentServiceUser(t)
	}
	if registered.Service.User != wantServiceUser {
		t.Fatalf("persisted service user = %q, want %q", registered.Service.User, wantServiceUser)
	}
	serviceEvents = collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationService, TargetMode: tui.ServiceModeService, ServiceAction: tui.ServiceActionStart})
	if terminalKind(serviceEvents) != tui.OperationEventCompleted || !serviceAdapter.called("start") {
		t.Fatalf("service start failed: terminal=%v calls=%v", terminalKind(serviceEvents), serviceAdapter.calls)
	}
	snapshot, err := controller.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if !snapshot.Running || snapshot.ServiceState != "running" || !snapshot.AutoStart {
		t.Fatalf("unexpected service snapshot: %+v", snapshot)
	}

	pathState, err := controller.applyPath(tui.InstallPlan{AddToPath: true, ProgramRoot: plan.ProgramRoot}, installed.Paths, installed.PATH)
	if err != nil {
		t.Fatalf("applyPath() error = %v", err)
	}
	if pathState.Owner != state.PATHOwnerManager || pathAdapter.installs != 1 {
		t.Fatalf("unexpected PATH install: state=%+v installs=%d", pathState, pathAdapter.installs)
	}
	if err := controller.removePathRecord(controller.controlStateRoot()); err != nil {
		t.Fatalf("removePathRecord() error = %v", err)
	}
	if pathAdapter.removes != 1 {
		t.Fatalf("PATH remove calls = %d, want 1", pathAdapter.removes)
	}
}

// TestUpgradeStopsAndRestartsForegroundRuntime verifies the runtime boundary around a successful upgrade.
// TestUpgradeStopsAndRestartsForegroundRuntime 验证成功升级前后会停止并重新启动前台运行实例。
func TestUpgradeStopsAndRestartsForegroundRuntime(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first install terminal event = %v", terminal)
	}
	process := controller.process.(*fakeProcess)
	process.running = true
	process.calls = nil

	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("upgrade stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("upgrade install terminal event = %v, calls=%v", terminal, process.calls)
	}
	if !process.called("stop") || !process.called("start") || !process.running {
		t.Fatalf("foreground runtime was not stopped and restarted: calls=%v running=%v", process.calls, process.running)
	}
}

// TestUpgradeFailureRestoresForegroundRuntime verifies that failed commit validation restarts the old process.
// TestUpgradeFailureRestoresForegroundRuntime 验证提交校验失败时会恢复旧前台进程。
func TestUpgradeFailureRestoresForegroundRuntime(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first install terminal event = %v", terminal)
	}
	process := controller.process.(*fakeProcess)
	process.running = true
	process.calls = nil
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("upgrade stage terminal event = %v", terminal)
	}
	controller.options.Validate = func(context.Context, string, string) (configbridge.ValidationResult, error) {
		return configbridge.ValidationResult{Valid: false, Errors: []configbridge.ValidationError{{Path: "storage.mode", Message: "invalid"}}}, nil
	}
	events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})
	if terminalKind(events) != tui.OperationEventFailed {
		t.Fatalf("failed upgrade terminal event = %v", terminalKind(events))
	}
	if !process.called("stop") || !process.called("start") || !process.running {
		t.Fatalf("old foreground runtime was not restored: calls=%v running=%v", process.calls, process.running)
	}
}

// TestUpgradeRejectsStorageTopologyChange verifies ordinary upgrades cannot switch databases silently.
// TestUpgradeRejectsStorageTopologyChange 验证普通升级不能静默切换数据库拓扑。
func TestUpgradeRejectsStorageTopologyChange(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first install terminal event = %v", terminal)
	}
	installedBefore, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatalf("state.Load() before topology change = %v", err)
	}

	splitPlan := plan
	splitPlan.Storage = tui.StorageOption{Mode: tui.StorageSplit}
	splitPlan.StorageSettings = tui.StorageSettings{LocalDataRoot: plan.DataRoot}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: splitPlan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("split stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: splitPlan})); terminal != tui.OperationEventFailed {
		t.Fatalf("split topology change terminal event = %v, want failed", terminal)
	}

	nativePathPlan := plan
	nativePathPlan.StorageSettings.NativeSQLitePath = filepath.Join(plan.DataRoot, "migrated.sqlite")
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: nativePathPlan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("native path stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: nativePathPlan})); terminal != tui.OperationEventFailed {
		t.Fatalf("native path change terminal event = %v, want failed", terminal)
	}
	installedAfter, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatalf("state.Load() after rejected topology changes = %v", err)
	}
	if installedAfter.VMM != installedBefore.VMM || installedAfter.Paths != installedBefore.Paths {
		t.Fatalf("rejected topology changes modified installation state: before=%+v after=%+v", installedBefore, installedAfter)
	}
}

// TestUpgradeRejectsPostgreSQLCredentialChange verifies DSN changes require a migration transaction.
// TestUpgradeRejectsPostgreSQLCredentialChange 验证 DSN 变化必须经过迁移事务。
func TestUpgradeRejectsPostgreSQLCredentialChange(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.Storage = tui.StorageOption{Mode: tui.StoragePostgreSQL}
	plan.StorageSettings = tui.StorageSettings{
		PostgreSQLDSNVariable:          "VMMM_TEST_DSN",
		PostgreSQLDSNValue:             "postgres://user:one@example.test/db",
		PostgreSQLCredentialPath:       filepath.Join(plan.ConfigRoot, ".env"),
		PostgreSQLCredentialConfigured: false,
		PostgreSQLFlavor:               "standard",
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first PostgreSQL stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first PostgreSQL install terminal event = %v", terminal)
	}
	credentialPath := filepath.Join(plan.ConfigRoot, ".env")
	before, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatalf("ReadFile() before DSN change = %v", err)
	}
	changed := plan
	changed.StorageSettings.PostgreSQLDSNValue = "postgres://user:two@example.test/db"
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: changed})); terminal != tui.OperationEventCompleted {
		t.Fatalf("changed PostgreSQL stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: changed})); terminal != tui.OperationEventFailed {
		t.Fatalf("changed PostgreSQL install terminal event = %v, want failed", terminal)
	}
	after, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatalf("ReadFile() after DSN change = %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("DSN credential changed despite migration guard: before=%q after=%q", before, after)
	}
}

// TestManagedPlanWritesWritableLogDirectory verifies both run modes keep logs out of the package so a later service conversion remains possible.
// TestManagedPlanWritesWritableLogDirectory 验证两种运行方式均将日志放在程序包外，以便日后转换为服务。
func TestManagedPlanWritesWritableLogDirectory(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, mode := range []tui.ServiceMode{tui.ServiceModeForeground, tui.ServiceModeService} {
		plan.ServiceMode = mode
		files, err := controller.buildConfigFiles(context.Background(), plan, plan.ProgramRoot)
		if err != nil {
			t.Fatalf("build %s configuration: %v", mode, err)
		}
		draft, err := configedit.Parse(files[defaultConfigFileName])
		if err != nil {
			t.Fatalf("parse %s configuration: %v", mode, err)
		}
		actual, err := draft.Get("logging.directory")
		if err != nil {
			t.Fatalf("read %s log directory: %v", mode, err)
		}
		if want := filepath.Join(plan.DataRoot, "logs"); actual.Value != want {
			t.Fatalf("%s log directory = %q, want %q", mode, actual.Value, want)
		}
	}
}

// TestUpgradeRebindsAndRestartsRunningService verifies service registration migration around an upgrade.
// TestUpgradeRebindsAndRestartsRunningService 验证升级时会迁移服务注册并恢复原运行状态。
func TestUpgradeRebindsAndRestartsRunningService(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	serviceAdapter := &fakeService{}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return serviceAdapter, nil }
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service install terminal event = %v, calls=%v", terminal, serviceAdapter.calls)
	}
	if runtime.GOOS != "windows" && serviceAdapter.lastUser != plan.ServiceUser {
		t.Fatalf("service user passed to install = %q, want %q", serviceAdapter.lastUser, plan.ServiceUser)
	}
	serviceAdapter.status.State = "running"
	serviceAdapter.status.User = plan.ServiceUser
	serviceAdapter.calls = nil
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("service upgrade stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("service upgrade install terminal event = %v, calls=%v", terminal, serviceAdapter.calls)
	}
	if !serviceAdapter.called("stop") || !serviceAdapter.called("uninstall") || !serviceAdapter.called("install") || !serviceAdapter.called("start") {
		t.Fatalf("service runtime was not migrated and restarted: calls=%v", serviceAdapter.calls)
	}
}

// TestServiceUpgradeFailureRestoresRegistration verifies rollback after a failed service upgrade commit.
// TestServiceUpgradeFailureRestoresRegistration 验证服务升级提交失败后会恢复旧注册和运行状态。
func TestServiceUpgradeFailureRestoresRegistration(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	serviceAdapter := &fakeService{}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return serviceAdapter, nil }
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service install terminal event = %v", terminal)
	}
	serviceAdapter.status.State = "running"
	serviceAdapter.status.User = plan.ServiceUser
	serviceAdapter.calls = nil
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("service upgrade stage terminal event = %v", terminal)
	}
	controller.options.Validate = func(context.Context, string, string) (configbridge.ValidationResult, error) {
		return configbridge.ValidationResult{Valid: false, Errors: []configbridge.ValidationError{{Path: "storage.mode", Message: "invalid"}}}, nil
	}
	events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})
	if terminalKind(events) != tui.OperationEventFailed {
		t.Fatalf("failed service upgrade terminal event = %v", terminalKind(events))
	}
	if !serviceAdapter.called("stop") || !serviceAdapter.called("uninstall") || !serviceAdapter.called("install") || !serviceAdapter.called("start") {
		t.Fatalf("old service registration was not restored: calls=%v", serviceAdapter.calls)
	}
	installed, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatalf("state.Load() after failed service upgrade = %v", err)
	}
	if installed.Service.Name == "" {
		t.Fatalf("service registration disappeared after failed upgrade: %+v", installed.Service)
	}
}

// TestServiceToForegroundSwitchStopsAndRemovesService verifies a mode switch clears the durable service record.
// TestServiceToForegroundSwitchStopsAndRemovesService 验证切换到前台模式会停止并移除持久化服务记录。
func TestServiceToForegroundSwitchStopsAndRemovesService(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	serviceAdapter := &fakeService{}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return serviceAdapter, nil }
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service install terminal event = %v", terminal)
	}
	serviceAdapter.status = service.Status{State: "running", User: plan.ServiceUser, AutoStart: "enabled"}
	serviceAdapter.calls = nil
	foregroundPlan := plan
	foregroundPlan.ServiceMode = tui.ServiceModeForeground
	foregroundPlan.ServiceUser = ""
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: foregroundPlan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("foreground switch stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: foregroundPlan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("foreground switch install terminal event = %v, calls=%v", terminal, serviceAdapter.calls)
	}
	if !serviceAdapter.called("stop") || !serviceAdapter.called("uninstall") || !controller.process.(*fakeProcess).called("start") {
		t.Fatalf("service-to-foreground switch was not reconciled: service=%v process=%v", serviceAdapter.calls, controller.process.(*fakeProcess).calls)
	}
	installed, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatalf("state.Load() after foreground switch = %v", err)
	}
	if installed.Service.Name != "" || installed.Service.User != "" {
		t.Fatalf("service state survived foreground switch: %+v", installed.Service)
	}
}

// TestServicePrivilegePreflightRunsBeforeCommit verifies a denied service mutation cannot create an installation registration.
// TestServicePrivilegePreflightRunsBeforeCommit 验证服务权限不足时不会创建安装登记。
func TestServicePrivilegePreflightRunsBeforeCommit(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	controller.options.ServicePrivilegeCheck = func() error { return errors.New("service privilege denied") }
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("service stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventFailed {
		t.Fatalf("privilege failure terminal event = %v, want failed", terminal)
	}
	if _, err := os.Stat(controller.options.StatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("registration exists after privilege preflight failed: %v", err)
	}
}

// TestServiceInstallFailureRestoresPreviousRegistration verifies post-commit service compensation.
// TestServiceInstallFailureRestoresPreviousRegistration 验证提交后服务注册失败会补偿旧注册。
func TestServiceInstallFailureRestoresPreviousRegistration(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	serviceAdapter := &fakeService{}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return serviceAdapter, nil }
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service install terminal event = %v", terminal)
	}
	serviceAdapter.status = service.Status{State: "running", User: plan.ServiceUser, AutoStart: "enabled"}
	serviceAdapter.calls = nil
	serviceAdapter.installErrors = []error{errors.New("new registration rejected"), nil}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("upgrade stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventFailed {
		t.Fatalf("post-commit service failure terminal event = %v, want failed", terminal)
	}
	if !serviceAdapter.called("stop") || !serviceAdapter.called("uninstall") || len(serviceAdapter.installErrors) != 0 || !serviceAdapter.called("start") {
		t.Fatalf("service compensation calls = %v", serviceAdapter.calls)
	}
	installed, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatalf("state.Load() after service compensation = %v", err)
	}
	if installed.Service.Name == "" || installed.Service.User != serviceUserForState(plan.ServiceUser) {
		t.Fatalf("previous service registration was not persisted: %+v", installed.Service)
	}
}

// TestForegroundSwitchFailureRestoresRunningService verifies failed service removal restarts the old service.
// TestForegroundSwitchFailureRestoresRunningService 验证服务移除失败时会重启原运行服务。
func TestForegroundSwitchFailureRestoresRunningService(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	serviceAdapter := &fakeService{}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return serviceAdapter, nil }
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service install terminal event = %v", terminal)
	}
	serviceAdapter.status = service.Status{State: "running", User: plan.ServiceUser, AutoStart: "enabled"}
	serviceAdapter.uninstallErr = errors.New("service removal rejected")
	serviceAdapter.calls = nil
	foregroundPlan := plan
	foregroundPlan.ServiceMode = tui.ServiceModeForeground
	foregroundPlan.ServiceUser = ""
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: foregroundPlan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("foreground failure stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: foregroundPlan})); terminal != tui.OperationEventFailed {
		t.Fatalf("foreground failure terminal event = %v, want failed", terminal)
	}
	if !serviceAdapter.called("stop") || !serviceAdapter.called("uninstall") || !serviceAdapter.called("start") {
		t.Fatalf("running service was not restored after failed switch: %v", serviceAdapter.calls)
	}
	installed, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatalf("state.Load() after failed foreground switch = %v", err)
	}
	if installed.Service.Name == "" {
		t.Fatalf("service registration disappeared after failed switch: %+v", installed.Service)
	}
}

// TestServiceFactoryFailureRestoresRegistration verifies a post-commit adapter failure uses the old handle.
// TestServiceFactoryFailureRestoresRegistration 验证提交后适配器失败会使用旧服务句柄恢复。
func TestServiceFactoryFailureRestoresRegistration(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	serviceAdapter := &fakeService{}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return serviceAdapter, nil }
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("first service install terminal event = %v", terminal)
	}
	serviceAdapter.status = service.Status{State: "running", User: plan.ServiceUser, AutoStart: "enabled"}
	serviceAdapter.calls = nil
	factoryCalls := 0
	controller.options.ServiceFactory = func(string) (ServiceClient, error) {
		factoryCalls++
		if factoryCalls == 2 {
			return nil, errors.New("new service adapter unavailable")
		}
		return serviceAdapter, nil
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationStagePackage, Plan: plan})); terminal != tui.OperationEventCompleted {
		t.Fatalf("factory failure stage terminal event = %v", terminal)
	}
	if terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: plan})); terminal != tui.OperationEventFailed {
		t.Fatalf("factory failure terminal event = %v, want failed", terminal)
	}
	if !serviceAdapter.called("stop") || !serviceAdapter.called("uninstall") || !serviceAdapter.called("install") || !serviceAdapter.called("start") {
		t.Fatalf("factory failure did not restore service: %v", serviceAdapter.calls)
	}
	installed, err := state.Load(controller.options.StatePath)
	if err != nil {
		t.Fatalf("state.Load() after factory failure = %v", err)
	}
	if installed.Service.Name == "" {
		t.Fatalf("service state was cleared despite successful restoration: %+v", installed.Service)
	}
}

// TestPathRollbackRemovesNewIntegration verifies the compensation path used after durable state failure.
// TestPathRollbackRemovesNewIntegration 验证持久化状态失败后的 PATH 补偿会移除新集成。
func TestPathRollbackRemovesNewIntegration(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	pathAdapter := &fakePath{}
	controller.options.PathFactory = func() PathClient { return pathAdapter }
	previous := emptyPATHState()
	current, err := controller.applyPath(tui.InstallPlan{AddToPath: true, ProgramRoot: plan.ProgramRoot}, state.InstallPaths{DataRoot: plan.DataRoot}, previous)
	if err != nil {
		t.Fatalf("applyPath() error = %v", err)
	}
	controller.rollbackPathChange(state.InstallPaths{DataRoot: plan.DataRoot}, previous, current)
	if pathAdapter.removes != 1 {
		t.Fatalf("PATH compensation remove calls = %d, want 1", pathAdapter.removes)
	}
	if _, err := os.Stat(pathRecordPath(plan.DataRoot)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PATH record after compensation = %v, want missing", err)
	}
}

// TestPathActionRollsBackWhenStateSaveFails proves a standalone PATH action removes its new entry if registration persistence fails.
// TestPathActionRollsBackWhenStateSaveFails 验证单独设置 PATH 后若安装登记保存失败，会撤销刚创建的命令入口。
func TestPathActionRollsBackWhenStateSaveFails(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatalf("fixture install failed at %s", kind)
		}
	}
	var injectedErr error
	pathAdapter := &fakePath{onInstall: func() {
		if injectedErr = os.Remove(controller.options.StatePath); injectedErr == nil {
			injectedErr = os.Mkdir(controller.options.StatePath, 0o700)
		}
	}}
	controller.options.PathFactory = func() PathClient { return pathAdapter }
	terminal := terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationPath, AddToPath: true}))
	if injectedErr != nil {
		t.Fatal(injectedErr)
	}
	if terminal != tui.OperationEventFailed {
		t.Fatal("unpersisted PATH change reported success")
	}
	if pathAdapter.installs != 1 || pathAdapter.removes != 1 {
		t.Fatalf("unpersisted PATH change was not removed: installs=%d removes=%d", pathAdapter.installs, pathAdapter.removes)
	}
	if _, err := os.Stat(pathRecordPath(controller.controlStateRoot())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PATH ownership receipt survived compensation: %v", err)
	}
}

// TestUninstallWaitsForInstallLockBeforeServiceRemoval verifies native service changes cannot precede the program-file lock.
// TestUninstallWaitsForInstallLockBeforeServiceRemoval 验证卸载等待程序文件锁时不会提前注销系统服务。
func TestUninstallWaitsForInstallLockBeforeServiceRemoval(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	adapter := &fakeService{}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return adapter, nil }
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatalf("service fixture install failed at %s", kind)
		}
	}
	releaseLock, err := install.LockInstallation(context.Background(), controller.options.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if releaseLock != nil {
			_ = releaseLock()
		}
	}()
	serviceTouched := make(chan struct{}, 1)
	controller.options.ServiceFactory = func(string) (ServiceClient, error) {
		serviceTouched <- struct{}{}
		return adapter, nil
	}
	events, err := controller.Start(context.Background(), tui.OperationRequest{Kind: tui.OperationUninstall, Uninstall: tui.UninstallOptions{RemoveService: true, KeepConfig: true, KeepData: true}})
	if err != nil {
		t.Fatal(err)
	}
	early := false
	select {
	case <-serviceTouched:
		early = true
	case <-time.After(150 * time.Millisecond):
	}
	if err := releaseLock(); err != nil {
		t.Fatal(err)
	}
	releaseLock = nil
	var terminal tui.OperationEventKind
	for event := range events {
		if event.Kind == tui.OperationEventCompleted || event.Kind == tui.OperationEventFailed || event.Kind == tui.OperationEventCancelled {
			terminal = event.Kind
		}
	}
	if early {
		t.Fatal("service control ran before installation lock was released")
	}
	if terminal != tui.OperationEventCompleted {
		t.Fatalf("uninstall terminal event = %s", terminal)
	}
}

// TestUninstallRetriesAfterNativeServiceRemoval verifies an interrupted PATH cleanup can be retried without removing an absent service again.
// TestUninstallRetriesAfterNativeServiceRemoval 验证 PATH 清理中断后可重试，且不会再次注销已不存在的系统服务。
func TestUninstallRetriesAfterNativeServiceRemoval(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	plan.AddToPath = true
	serviceAdapter := &fakeService{}
	pathAdapter := &fakePath{}
	controller.options.ServiceFactory = func(string) (ServiceClient, error) { return serviceAdapter, nil }
	controller.options.PathFactory = func() PathClient { return pathAdapter }
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatalf("service and PATH fixture install failed at %s", kind)
		}
	}
	receipt := pathRecordPath(controller.controlStateRoot())
	receiptBytes, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(receipt); err != nil {
		t.Fatal(err)
	}
	request := tui.OperationRequest{Kind: tui.OperationUninstall, Uninstall: tui.UninstallOptions{RemoveService: true, RemovePath: true, KeepConfig: true, KeepData: true}}
	if terminalKind(collectOperation(t, controller, request)) != tui.OperationEventFailed {
		t.Fatal("missing PATH receipt did not stop uninstall after native service removal")
	}
	if serviceAdapter.status.State != "not-installed" {
		t.Fatalf("native service was not removed before PATH failure: %+v", serviceAdapter.status)
	}
	snapshot, err := controller.Snapshot(context.Background())
	if err != nil || snapshot.Installed || !snapshot.Incomplete || snapshot.IntegrityIssue != "service-missing" {
		t.Fatalf("failed uninstall was reported complete: %+v %v", snapshot, err)
	}
	if err := os.WriteFile(receipt, receiptBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if terminalKind(collectOperation(t, controller, request)) != tui.OperationEventCompleted {
		t.Fatal("uninstall could not resume after restoring the PATH receipt")
	}
	uninstalls := 0
	for _, call := range serviceAdapter.calls {
		if call == "uninstall" {
			uninstalls++
		}
	}
	if uninstalls != 1 || pathAdapter.removes != 1 {
		t.Fatalf("retry repeated native removal: service=%d PATH=%d", uninstalls, pathAdapter.removes)
	}
}

// TestUninstallPreservedProgramKeepsConfigurationAndData verifies changed owned files cannot trigger destructive root cleanup.
// TestUninstallPreservedProgramKeepsConfigurationAndData 验证受管程序已改变时，不会继续删除配置和数据库根目录。
func TestUninstallPreservedProgramKeepsConfigurationAndData(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatalf("fixture install failed at %s", kind)
		}
	}
	binaryPath := filepath.Join(plan.ProgramRoot, filepath.FromSlash(controller.identity.VMMExecutablePath))
	if err := os.WriteFile(binaryPath, []byte("locally changed program"), 0o755); err != nil {
		t.Fatal(err)
	}
	events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationUninstall, Uninstall: tui.UninstallOptions{KeepConfig: false, KeepData: false}})
	terminal := terminalKind(events)
	if terminal != tui.OperationEventFailed {
		t.Fatal("partial program removal reported complete root cleanup")
	}
	var refreshed *tui.InstallationSnapshot
	for _, event := range events {
		if event.Snapshot != nil {
			refreshed = event.Snapshot
		}
	}
	if refreshed == nil || refreshed.Installed || !refreshed.Incomplete {
		t.Fatalf("failed uninstall did not refresh incomplete state: %+v", refreshed)
	}
	for _, path := range []string{plan.ConfigRoot, plan.DataRoot, controller.options.StatePath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("preserved program lost configuration, data, or registration %q: %v", path, err)
		}
	}
	saved, err := state.Load(controller.options.StatePath)
	if err != nil || saved.InstallationComplete {
		t.Fatalf("partial uninstall retained completed registration: %+v %v", saved, err)
	}
}

// TestUninstallRemovesSelectedRootsUnderSeparateControlState verifies complete root cleanup leaves no installation registration.
// TestUninstallRemovesSelectedRootsUnderSeparateControlState 验证明确选择的配置和数据根完整清理后不会留下安装登记。
func TestUninstallRemovesSelectedRootsUnderSeparateControlState(t *testing.T) {
	controller, plan, _ := newFixtureController(t)
	for _, kind := range []tui.OperationKind{tui.OperationStagePackage, tui.OperationInstall} {
		if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: kind, Plan: plan})) != tui.OperationEventCompleted {
			t.Fatalf("fixture install failed at %s", kind)
		}
	}
	if terminalKind(collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationUninstall, Uninstall: tui.UninstallOptions{KeepConfig: false, KeepData: false}})) != tui.OperationEventCompleted {
		t.Fatal("selected root cleanup did not complete")
	}
	for _, path := range []string{plan.ConfigRoot, plan.DataRoot, controller.options.StatePath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("completed uninstall retained %q: %v", path, err)
		}
	}
	snapshot, err := controller.Snapshot(context.Background())
	if err != nil || snapshot.Installed || snapshot.Incomplete {
		t.Fatalf("completed uninstall reported an installation: %+v %v", snapshot, err)
	}
}

// TestServiceUserOwnershipGate verifies that Unix service registration checks real root ownership.
// TestServiceUserOwnershipGate 验证 Unix 服务注册会检查真实的根目录归属。
func TestServiceUserOwnershipGate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows SCM does not use a Unix service account")
	}
	if os.Geteuid() != 0 {
		t.Skip("Unix service controller tests require a root-launched manager")
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	root := testpath.CanonicalTempDir(t)
	if err := validateServiceUserForInstall(account.Username, []string{filepath.Join(root, "config"), filepath.Join(root, "data")}); err != nil {
		t.Fatalf("current account ownership check failed: %v", err)
	}
	if err := validateServiceUserForInstall(account.Username+"\x00", []string{root}); err == nil {
		t.Fatal("invalid service account was accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := validateServiceUserForInstall(account.Username, []string{filepath.Join(link, "config")}); err == nil {
		t.Fatal("symlinked service root was accepted")
	}
}

// TestServiceUserPermissionGate verifies each ancestor and existing file mode is checked.
// TestServiceUserPermissionGate 验证逐级祖先目录和现有文件的权限位都会被检查。
func TestServiceUserPermissionGate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows SCM does not use Unix permission bits")
	}
	if os.Geteuid() != 0 {
		t.Skip("Unix service controller tests require a root-launched manager")
	}
	account, err := user.Current()
	if err != nil || account.Username == "" {
		t.Fatalf("user.Current() error = %v", err)
	}
	root := testpath.CanonicalTempDir(t)
	if err := os.Chmod(root, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateServiceUserForInstall(account.Username, []string{filepath.Join(root, "data")}); err == nil {
		t.Fatal("private ancestor without execute permission was accepted")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configFile, []byte("storage:\n  mode: native\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateServiceUserForInstall(account.Username, []string{configFile}); err != nil {
		t.Fatalf("readable config file rejected: %v", err)
	}
	if err := os.Chmod(configFile, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := validateServiceUserAccess(account.Username, []servicePathCheck{{path: configFile, writable: false}}); err != nil {
		t.Fatalf("read-only config file rejected: %v", err)
	}
	if err := validateServiceUserAccess(account.Username, []servicePathCheck{{path: configFile, writable: true}}); err == nil {
		t.Fatal("read-only file was accepted for a writable service path")
	}
}

// TestFailedOperationDoesNotExposeSecrets checks the bounded terminal error contract.
// TestFailedOperationDoesNotExposeSecrets 验证失败终止事件不会暴露秘密或路径。
func TestFailedOperationDoesNotExposeSecrets(t *testing.T) {
	controller, _, _ := newFixtureController(t)
	secret := "super-secret-value"
	events := collectOperation(t, controller, tui.OperationRequest{Kind: tui.OperationInstall, Plan: tui.InstallPlan{ConfigFields: []tui.ConfigField{{Value: secret}}}})
	if terminalKind(events) != tui.OperationEventFailed {
		t.Fatalf("terminal event = %v", terminalKind(events))
	}
	for _, event := range events {
		if strings.Contains(event.Message, secret) || strings.Contains(event.Message, "program-file") {
			t.Fatalf("unsafe error event: %+v", event)
		}
	}
}

// fixturePackage contains the signed release and real archive used by controller tests.
// fixturePackage 保存 controller 测试使用的签名发行版和真实压缩包。
type fixturePackage struct {
	identity platform.Identity
	tag      string
	commit   string
	archive  string
	artifact manifest.Artifact
	release  manifest.VerifiedManifest
}

// fakeService implements the controller service boundary without invoking a platform manager.
// fakeService 实现 controller 服务边界，但不会调用真实平台服务管理器。
type fakeService struct {
	status        service.Status
	calls         []string
	lastUser      string
	installErr    error
	installErrors []error
	uninstallErr  error
	startErr      error
	stopErr       error
	statusErr     error
}

// Install records service registration.
// Install 记录服务注册。
func (f *fakeService) Install(_ context.Context, _ string, _ string, serviceUser string, _ bool) error {
	f.calls = append(f.calls, "install")
	f.lastUser = serviceUser
	if len(f.installErrors) > 0 {
		err := f.installErrors[0]
		f.installErrors = f.installErrors[1:]
		if err != nil {
			return err
		}
	}
	if f.installErr != nil {
		return f.installErr
	}
	f.status.State = "stopped"
	return nil
}

// Uninstall records service removal.
// Uninstall 记录服务移除。
func (f *fakeService) Uninstall(context.Context, string) error {
	f.calls = append(f.calls, "uninstall")
	if f.uninstallErr != nil {
		return f.uninstallErr
	}
	f.status.State = "not-installed"
	return nil
}

// Start records service start.
// Start 记录服务启动。
func (f *fakeService) Start(context.Context, string) error {
	f.calls = append(f.calls, "start")
	if f.startErr != nil {
		return f.startErr
	}
	f.status.State = "running"
	return nil
}

// Stop records service stop.
// Stop 记录服务停止。
func (f *fakeService) Stop(context.Context, string) error {
	f.calls = append(f.calls, "stop")
	if f.stopErr != nil {
		return f.stopErr
	}
	f.status.State = "stopped"
	return nil
}

// Restart records service restart.
// Restart 记录服务重启。
func (f *fakeService) Restart(context.Context, string) error {
	f.calls = append(f.calls, "restart")
	return nil
}

// Enable records automatic-start enablement.
// Enable 记录自动启动开启。
func (f *fakeService) Enable(context.Context, string) error {
	f.calls = append(f.calls, "enable")
	return nil
}

// Disable records automatic-start disablement.
// Disable 记录自动启动关闭。
func (f *fakeService) Disable(context.Context, string) error {
	f.calls = append(f.calls, "disable")
	return nil
}

// GetStatus returns the machine-readable service status used by Snapshot.
// GetStatus 返回 Snapshot 使用的机器可读服务状态。
func (f *fakeService) GetStatus(context.Context, string) (service.Status, error) {
	f.calls = append(f.calls, "status")
	if f.statusErr != nil {
		return service.Status{}, f.statusErr
	}
	return f.status, nil
}

// called reports whether one lifecycle action was recorded.
// called 判断是否记录过指定生命周期动作。
func (f *fakeService) called(wanted string) bool {
	for _, call := range f.calls {
		if call == wanted {
			return true
		}
	}
	return false
}

// fakeProcess supplies a stopped foreground status for installation snapshots.
// fakeProcess 为安装快照提供已停止的前台状态。
type fakeProcess struct {
	running     bool
	calls       []string
	startErr    error
	startErrors []error
	stopErr     error
	statusErr   error
}

// Start implements foreground start for tests.
// Start 为测试实现前台启动。
func (f *fakeProcess) Start(context.Context, string, string) error {
	f.calls = append(f.calls, "start")
	if len(f.startErrors) > 0 {
		err := f.startErrors[0]
		f.startErrors = f.startErrors[1:]
		if err != nil {
			return err
		}
	}
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	return nil
}

// Stop implements foreground stop for tests.
// Stop 为测试实现前台停止。
func (f *fakeProcess) Stop(context.Context, string) error {
	f.calls = append(f.calls, "stop")
	if f.stopErr != nil {
		return f.stopErr
	}
	f.running = false
	return nil
}

// Restart implements foreground restart for tests.
// Restart 为测试实现前台重启。
func (f *fakeProcess) Restart(context.Context, string, string) error {
	f.calls = append(f.calls, "restart")
	if f.stopErr != nil {
		return f.stopErr
	}
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	return nil
}

// Status reports a stopped foreground process.
// Status 报告前台进程已停止。
func (f *fakeProcess) Status(context.Context, string) (ProcessStatus, error) {
	f.calls = append(f.calls, "status")
	if f.statusErr != nil {
		return ProcessStatus{}, f.statusErr
	}
	return ProcessStatus{Running: f.running}, nil
}

// called reports whether a foreground lifecycle action was recorded.
// called 判断是否记录过指定的前台生命周期动作。
func (f *fakeProcess) called(wanted string) bool {
	for _, call := range f.calls {
		if call == wanted {
			return true
		}
	}
	return false
}

// fakePath supplies a valid manager-owned PATH record and records reversals.
// fakePath 提供有效的管理器拥有 PATH 记录并记录撤销操作。
type fakePath struct {
	installs  int
	removes   int
	onInstall func()
}

// Install returns a platform-valid manager-owned record.
// Install 返回平台有效的管理器拥有记录。
func (f *fakePath) Install(options pathctl.Options) (pathctl.Record, error) {
	f.installs++
	if f.onInstall != nil {
		f.onInstall()
	}
	record := pathctl.Record{Version: pathctl.RecordVersion, Path: state.PATHState{Owner: state.PATHOwnerManager, Scope: state.PATHScopeUser}, Directory: options.Directory}
	if runtime.GOOS == "windows" {
		record.Method = pathctl.MethodWindowsUserPath
		record.Path.Entries = []string{filepath.Clean(options.Directory)}
		record.AfterSHA256 = strings.Repeat("a", 64)
		record.AfterType = 1
	} else if options.Method == pathctl.MethodDarwinPathsD {
		record.Method = pathctl.MethodDarwinPathsD
		record.Path.Scope = state.PATHScopeSystem
		record.ProfilePath = pathctl.DarwinPathsFile
		record.Path.Entries = []string{filepath.Clean(options.Directory)}
		record.AfterSHA256 = strings.Repeat("a", 64)
	} else {
		record.Method = pathctl.MethodUnixLocalBin
		record.LinkPath = filepath.Join(options.Directory, ".test-bin", "vmmm")
		record.TargetPath = filepath.Join(options.Directory, options.TargetPath)
		record.Path.Entries = []string{filepath.Dir(record.LinkPath)}
	}
	return record, nil
}

// Remove records a safe manager-owned PATH removal.
// Remove 记录安全的管理器拥有 PATH 移除。
func (f *fakePath) Remove(pathctl.Record) error {
	f.removes++
	return nil
}

// newFixtureController builds one controller with a real signed archive and injected deterministic adapters.
// newFixtureController 构造带真实签名压缩包和确定性适配器的 controller。
func newFixtureController(t *testing.T) (*Controller, tui.InstallPlan, fixturePackage) {
	t.Helper()
	return newFixtureControllerAt(t, fixtureInstallBase(t))
}

// newFixtureControllerAt binds the authenticated package fixture to an explicit installation parent.
// newFixtureControllerAt 将已认证安装包夹具绑定到明确的安装父目录，供不同账户权限测试使用。
func newFixtureControllerAt(t *testing.T, base string) (*Controller, tui.InstallPlan, fixturePackage) {
	t.Helper()
	fixture := newFixturePackage(t)
	plan := tui.InstallPlan{
		Source:      tui.SourceOption{Source: download.DefaultSources()[0], Available: true},
		Version:     tui.VersionOption{Tag: fixture.tag, Commit: fixture.commit, Available: true},
		ProgramRoot: filepath.Join(base, "program"),
		ConfigRoot:  filepath.Join(base, "config"),
		DataRoot:    filepath.Join(base, "data"),
		Storage:     tui.StorageOption{Mode: tui.StorageNative},
		StorageSettings: tui.StorageSettings{
			NativeSQLitePath:  filepath.Join(base, "data", "sqlite.db"),
			NativeLanceDBPath: filepath.Join(base, "data", "lancedb"),
		},
		ServiceMode: tui.ServiceModeForeground,
	}
	publicKey := ed25519.NewKeyFromSeed(testSeed(7)).Public().(ed25519.PublicKey)
	statePath := filepath.Join(base, "control", "vmmm-state.json")
	options := Options{
		ManagerVersion:        "vmmm-test",
		ManagerRoot:           filepath.Join(base, "manager"),
		StatePath:             statePath,
		CacheRoot:             filepath.Join(base, "cache"),
		TrustKeys:             map[string]ed25519.PublicKey{"test": publicKey},
		Identity:              fixture.identity,
		Process:               &fakeProcess{},
		ServicePrivilegeCheck: func() error { return nil },
		WaitHealthy:           func(context.Context, string, string) error { return nil },
		Discover: func(context.Context, release.Request) (release.Result, error) {
			return release.Result{Manifest: fixture.release, Product: manifest.ProductVMM, Repository: download.RepositoryVMM, Source: plan.Source.Source, Tag: fixture.tag, Commit: fixture.commit}, nil
		},
		Fetch: func(context.Context, fetch.Request) (fetch.Result, error) {
			return fetch.Result{Path: fixture.archive, Filename: fixture.artifact.Filename, Bytes: fixture.artifact.Bytes, SHA256: fixture.artifact.SHA256}, nil
		},
		Schema: func(context.Context, string, string) (configbridge.Schema, error) {
			return testSchema(), nil
		},
		Validate: func(_ context.Context, binaryPath string, configRoot string) (configbridge.ValidationResult, error) {
			if _, err := os.Stat(binaryPath); err != nil {
				return configbridge.ValidationResult{}, err
			}
			if _, err := os.Stat(filepath.Join(configRoot, "config.yaml")); err != nil {
				return configbridge.ValidationResult{}, err
			}
			return configbridge.ValidationResult{Valid: true, Errors: []configbridge.ValidationError{}}, nil
		},
	}
	controller, err := New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return controller, plan, fixture
}

// fixtureInstallBase places privileged service fixtures below a root-owned, protected ancestor.
// fixtureInstallBase 将特权服务测试目录放在由 root 持有且受保护的上级目录中。
//
// Unix service registration rejects world-writable /tmp and runner-owned ancestors by design;
// the root test must exercise the same protected layout as a real system installation.
// Unix 服务注册会按设计拒绝全局可写的 /tmp 和运行器持有的上级目录；
// root 测试必须使用与真实系统安装相同的受保护目录布局。
func fixtureInstallBase(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		return testpath.CanonicalTempDir(t)
	}
	account, err := user.Lookup("root")
	if err != nil || account.HomeDir == "" {
		t.Fatalf("root account home lookup failed: %v", err)
	}
	rootHome, err := filepath.EvalSymlinks(account.HomeDir)
	if err != nil {
		t.Fatalf("resolve root home: %v", err)
	}
	base, err := os.MkdirTemp(rootHome, ".vmmm-controller-test-")
	if err != nil {
		t.Fatalf("create protected service fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

// TestPrivilegedServiceCommitContract verifies the exact privileged package transaction without hiding its error.
// TestPrivilegedServiceCommitContract 直接验证提权安装事务，并在失败时保留精确错误原因。
func TestPrivilegedServiceCommitContract(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("requires a root Unix test process")
	}
	controller, plan, _ := newFixtureController(t)
	plan.ServiceMode = tui.ServiceModeService
	plan.ServiceUser = currentServiceUser(t)
	events := make(chan tui.OperationEvent, 32)
	if err := controller.stagePackage(context.Background(), plan, events); err != nil {
		t.Fatalf("stagePackage() error = %v", err)
	}
	prepared, err := controller.matchStaged(plan)
	if err != nil {
		t.Fatalf("matchStaged() error = %v", err)
	}
	defer prepared.prepared.Close()
	configFiles, err := controller.buildConfigFiles(context.Background(), plan, prepared.packageData.Root)
	if err != nil {
		t.Fatalf("buildConfigFiles() error = %v", err)
	}
	request := install.Request{
		ManagerRoot: controller.options.ManagerRoot, Operation: prepared.operation,
		ManagerVersion: controller.options.ManagerVersion, Manifest: prepared.release.Manifest,
		Artifact: prepared.artifact, Package: prepared.packageData, Expected: prepared.expected,
		Paths:     state.InstallPaths{ProgramRoot: plan.ProgramRoot, ConfigRoot: plan.ConfigRoot, DataRoot: plan.DataRoot},
		StatePath: controller.options.StatePath, Source: sourceState(plan.Source.Source),
		Service: serviceStateForPlan(plan, controller.options.ServiceName), PATH: emptyPATHState(),
		ConfigFiles: configFiles, ValidateConfig: controller.validateFunc(),
	}
	if _, err := prepared.prepared.CommitInstall(context.Background(), request); err != nil {
		t.Fatalf("CommitInstall() error = %v", err)
	}
	if err := validateServiceUserAccess(plan.ServiceUser, controller.servicePathChecks(plan, plan.ConfigRoot, plan.DataRoot)); err != nil {
		t.Fatalf("installed service path access error = %v", err)
	}
}

// currentServiceUser returns the account that owns test-created configuration and data roots.
// currentServiceUser 返回拥有测试创建配置和数据根目录的账户。
func currentServiceUser(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		t.Skip("Unix service controller tests require a root-launched manager")
	}
	account, err := user.Current()
	if err != nil || account.Username == "" {
		t.Fatalf("user.Current() error = %v", err)
	}
	return account.Username
}

// testSchema returns the fields used by storage and provider orchestration tests.
// testSchema 返回存储与供应商编排测试使用的字段。
func testSchema() configbridge.Schema {
	return configbridge.Schema{
		Version:    "v1",
		ConfigType: "Config",
		Fields: []configbridge.Field{
			{Path: "logging.directory", Type: "string"},
			{Path: "storage.mode", Type: "string", Enum: []string{"native", "split", "controller", "combined"}},
			{Path: "storage.local_data_root", Type: "string"},
			{Path: "storage.combined_provider", Type: "string", Enum: []string{"postgres"}},
			{Path: "sqlite.native.path", Type: "string"},
			{Path: "lancedb.native.path", Type: "string"},
			{Path: "controller.endpoint", Type: "string"},
			{Path: "postgres.dsn", Type: "string"},
			{Path: "postgres.flavor", Type: "string", Enum: []string{"standard", "paradedb"}},
			{Path: "llm.routes", Type: "array"},
			{Path: "embedding", Type: "object"},
			{Path: "rerank", Type: "object"},
		},
	}
}

// collectOperation drains one controller event stream and requires a closed stream.
// collectOperation 消费一次 controller 事件流并要求流正常关闭。
func collectOperation(t *testing.T, controller *Controller, request tui.OperationRequest) []tui.OperationEvent {
	t.Helper()
	stream, err := controller.Start(context.Background(), request)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	var events []tui.OperationEvent
	for event := range stream {
		events = append(events, event)
	}
	if len(events) == 0 {
		t.Fatal("controller emitted no events")
	}
	return events
}

// terminalKind returns the last terminal event kind in a bounded event stream.
// terminalKind 返回有界事件流中的最后一个终止事件类型。
func terminalKind(events []tui.OperationEvent) tui.OperationEventKind {
	var terminal tui.OperationEventKind
	for _, event := range events {
		switch event.Kind {
		case tui.OperationEventCompleted, tui.OperationEventFailed, tui.OperationEventCancelled:
			terminal = event.Kind
		}
	}
	return terminal
}

// hasVerifiedPackage checks that stage metadata was emitted before configuration work.
// hasVerifiedPackage 检查配置工作前是否发出了已验证暂存包元数据。
func hasVerifiedPackage(events []tui.OperationEvent) bool {
	for _, event := range events {
		if event.Package != nil && event.Package.Verified {
			return true
		}
	}
	return false
}

// newFixturePackage creates an authenticated VMM archive matching the production extractor contract.
// newFixturePackage 创建符合生产解包契约的已认证 VMM 压缩包。
func newFixturePackage(t *testing.T) fixturePackage {
	t.Helper()
	identity, err := platform.Current()
	if err != nil {
		t.Fatal(err)
	}
	base := testpath.CanonicalTempDir(t)
	tag := "v1.2.3"
	commit := strings.Repeat("a", 40)
	packageName := "vulcan-memory-mesh-" + tag + "-" + identity.PlatformID
	packageRoot := filepath.Join(base, packageName)
	files := map[string][]byte{
		"bin/" + filepath.Base(filepath.FromSlash(identity.VMMExecutablePath)): []byte("vmm executable"),
		"configs/base.yaml": []byte("mode: native\n"),
		"libs/vldb.dll":     []byte("vldb library"),
	}
	receipt := archive.Receipt{
		ManifestSchema: archive.ManifestSchemaVersion,
		Version:        tag,
		Commit:         commit,
		Platform:       identity.PlatformID,
		Target:         fixtureTarget(identity.PlatformID),
		StorageMode:    archive.StorageModeNative,
		StorageProfile: "all",
		Capabilities: archive.Capabilities{
			SchemaVersion: 1,
			StorageModes:  []archive.StorageMode{archive.StorageModeSplit, archive.StorageModeController, archive.StorageModeNative, archive.StorageModeCombined},
			Combined:      &archive.CombinedCapability{Provider: "postgres", Flavors: []string{"standard", "paradedb"}},
		},
		Files: map[string]string{},
	}
	for relative, data := range files {
		path := filepath.Join(packageRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		// Production release executables are readable and executable by the selected service account.
		// 正式发行的可执行文件允许所选服务账户读取和执行，测试归档必须保留相同权限。
		mode := os.FileMode(0o644)
		if strings.HasPrefix(relative, "bin/") {
			mode = 0o755
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		receipt.Files[relative] = hex.EncodeToString(digest[:])
	}
	receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageRoot, "release-manifest.json"), append(receiptBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(base, packageName+fixtureArchiveSuffix(identity.PlatformID))
	writeFixtureArchive(t, archivePath, packageRoot, packageName, identity.PlatformID)
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archiveBytes)
	artifact := manifest.Artifact{Platform: identity.PlatformID, Filename: filepath.Base(archivePath), Bytes: int64(len(archiveBytes)), SHA256: hex.EncodeToString(digest[:])}
	manifestBytes, err := json.Marshal(manifest.Manifest{ProtocolVersion: manifest.ProtocolVersion, Product: manifest.ProductVMM, Tag: tag, Commit: commit, Artifacts: []manifest.Artifact{artifact}})
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(testSeed(7))
	signature := ed25519.Sign(privateKey, manifestBytes)
	signatureBytes, err := json.Marshal(manifest.SignatureEnvelope{Version: manifest.SignatureVersion, KeyID: "test", Signature: base64.StdEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := manifest.Verify(manifestBytes, signatureBytes, map[string]ed25519.PublicKey{"test": privateKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	return fixturePackage{identity: identity, tag: tag, commit: commit, archive: archivePath, artifact: artifact, release: verified}
}

// writeFixtureArchive uses the same platform archive family as production releases.
// writeFixtureArchive 使用与生产发行版相同的平台压缩包类型。
func writeFixtureArchive(t *testing.T, destination string, root string, packageName string, platformID string) {
	t.Helper()
	file, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	closeFile := func() {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if platformID == "windows-x64" {
		writer := zip.NewWriter(file)
		err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return walkErr
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = packageName + "/" + filepath.ToSlash(relative)
			header.Method = zip.Deflate
			writerEntry, err := writer.CreateHeader(header)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			_, err = writerEntry.Write(data)
			return err
		})
		if err == nil {
			err = writer.Close()
		}
		closeFile()
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = packageName + "/" + filepath.ToSlash(relative)
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err == nil {
		err = tarWriter.Close()
	}
	if err == nil {
		err = gzipWriter.Close()
	}
	closeFile()
	if err != nil {
		t.Fatal(err)
	}
}

// fixtureArchiveSuffix selects the production archive suffix for one platform.
// fixtureArchiveSuffix 选择一个平台对应的生产压缩包后缀。
func fixtureArchiveSuffix(platformID string) string {
	if platformID == "windows-x64" {
		return ".zip"
	}
	return ".tar.gz"
}

// fixtureTarget returns the closed release target mapping used by archive verification.
// fixtureTarget 返回归档校验使用的封闭发行目标映射。
func fixtureTarget(platformID string) string {
	return map[string]string{
		"windows-x64": "x86_64-pc-windows-msvc",
		"linux-x64":   "x86_64-unknown-linux-gnu",
		"linux-arm64": "aarch64-unknown-linux-gnu",
		"macos-intel": "x86_64-apple-darwin",
		"macos-arm64": "aarch64-apple-darwin",
	}[platformID]
}

// testSeed creates the deterministic Ed25519 seed used by local controller fixtures.
// testSeed 创建本地 controller 夹具使用的确定性 Ed25519 种子。
func testSeed(value byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = value
	}
	return seed
}
