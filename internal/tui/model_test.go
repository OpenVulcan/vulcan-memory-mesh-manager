// This file verifies TUI state transitions, Unicode input, staging order, and viewport bounds.
// 本文件验证 TUI 状态迁移、Unicode 输入、暂存顺序和视口边界。
package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"charm.land/bubbletea/v2"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/i18n"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/providerwizard"
)

// testLocalizer keeps model tests independent from catalog text while preserving key routing.
// testLocalizer 让模型测试独立于目录文本，同时保留消息键路由。
type testLocalizer struct{}

// Text returns the key and ignores values because state tests inspect navigation, not copywriting.
// Text 返回消息键并忽略值，因为状态测试关注导航而不是文案。
func (testLocalizer) Text(_ Language, key i18n.MessageKey, _ map[string]string) string {
	return string(key)
}

// testController emits deterministic terminal events for the wizard migration test.
// testController 为向导状态迁移测试发出确定性的终止事件。
type testController struct {
	// requests records every request sent by the model.
	// requests 记录模型发出的每个请求。
	requests []OperationRequest
	// validationValid optionally overrides the deterministic validation result.
	// validationValid 可选地覆盖确定性的配置校验结果。
	validationValid *bool
}

// Start returns one completed event for each supported operation.
// Start 为每个受支持操作返回一个完成事件。
func (c *testController) Start(_ context.Context, request OperationRequest) (<-chan OperationEvent, error) {
	c.requests = append(c.requests, request)
	stream := make(chan OperationEvent, 1)
	switch request.Kind {
	case OperationProbeSource:
		stream <- OperationEvent{Kind: OperationEventCompleted, Versions: []VersionOption{{Tag: "v0.1.0", Available: true}}}
	case OperationStagePackage:
		stream <- OperationEvent{Kind: OperationEventCompleted, Package: &StagedPackage{Verified: true, Version: "v0.1.0", Platform: "windows-x64", StorageModes: []StorageMode{StorageNative, StorageSplit, StorageController, StoragePostgreSQL, StorageParadeDB}}}
	case OperationValidate:
		valid := true
		if c.validationValid != nil {
			valid = *c.validationValid
		}
		validation := &ValidationSummary{Valid: valid, Summary: "valid"}
		if !valid {
			validation.Summary = "invalid"
			validation.Errors = []string{"storage configuration is invalid"}
		}
		stream <- OperationEvent{Kind: OperationEventCompleted, Validation: validation}
	case OperationInstall:
		stream <- OperationEvent{Kind: OperationEventCompleted, Snapshot: &InstallationSnapshot{Installed: true, VMMVersion: "v0.1.0", Storage: request.Plan.Storage.Mode, ServiceMode: request.Plan.ServiceMode}}
	default:
		stream <- OperationEvent{Kind: OperationEventCompleted}
	}
	close(stream)
	return stream, nil
}

// OpenConfigFields returns one editable field for provider and advanced-field pages.
// OpenConfigFields 为供应商和高级字段页面返回一个可编辑字段。

func (c *testController) OpenConfigFields(_ context.Context, request ConfigFieldsRequest) (ConfigFieldsResult, error) {
	if request.Prefix == "storage" {
		return ConfigFieldsResult{Fields: []ConfigField{{Path: "storage.local_data_root", Type: "string", Value: "C:/VMMM/data", Editable: true}}}, nil
	}
	return ConfigFieldsResult{Fields: []ConfigField{{Path: "llm.provider", Type: "string", Value: "openai", Editable: true}}}, nil
}

// OpenProviderWizard returns a deterministic typed provider catalog and preconfigured test draft.
// OpenProviderWizard 返回确定性的强类型供应商目录和已配置的测试草稿。
func (c *testController) OpenProviderWizard(_ context.Context, request ProviderWizardRequest) (ProviderWizardResult, error) {
	providers, err := providerwizard.ProviderCatalog(request.Purpose)
	if err != nil {
		return ProviderWizardResult{}, err
	}
	draft := request.Draft
	if draft.Provider == "" && len(providers) > 0 {
		draft.Provider = providers[0].ID
	}
	if request.Purpose == ProviderPurposeLLM {
		draft.Endpoint = "https://api.example.test/v1"
		draft.Model = "test-model"
		draft.APIKeyEnvironmentNames = []string{"VMMM_TEST_KEY"}
		draft.CredentialConfigured = true
	}
	draft.Purpose = request.Purpose
	return ProviderWizardResult{Purpose: request.Purpose, Providers: providers, Draft: draft, Summary: "typed provider loaded"}, nil
}

// press creates a Bubble Tea v2 key message with printable or special key data.
// press 使用 Bubble Tea v2 按键数据创建可打印或特殊键消息。
func press(code rune, text string) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: code, Text: text})
}

// update applies one message and evaluates its command when present.
// update 应用一条消息，并在有命令时执行该命令。
func update(t *testing.T, model *Model, message tea.Msg) *Model {
	t.Helper()
	result, command := model.Update(message)
	model = result.(*Model)
	if command != nil {
		result, command = model.Update(command())
		model = result.(*Model)
		if command != nil {
			result, command = model.Update(command())
			model = result.(*Model)
		}
	}
	return model
}

// TestFirstInstallStateFlow proves that staging precedes configuration and final install.
// TestFirstInstallStateFlow 证明先暂存安装包，再配置，最后才执行安装。
func TestFirstInstallStateFlow(t *testing.T) {
	controller := &testController{}
	model := NewModel(ModelConfig{
		Controller: controller,
		Localizer:  testLocalizer{},
		Language:   LanguageEnglish,
		Defaults: InstallPlan{
			ProgramRoot: "C:/VMMM",
			ConfigRoot:  "C:/VMMM/config",
			DataRoot:    "C:/VMMM/data",
		},
	})

	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenSource {
		t.Fatalf("language page should lead to source page, got %v", model.Screen())
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenVersion {
		t.Fatalf("source probe should lead to version page, got %v", model.Screen())
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenInstallPath {
		t.Fatalf("version page should lead to path page, got %v", model.Screen())
	}
	model.input = "C:/VMMM"
	model = update(t, model, press(tea.KeyEnter, ""))
	model.input = "C:/VMMM/config"
	model = update(t, model, press(tea.KeyEnter, ""))
	model.input = "C:/VMMM/data"
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenStorage || model.plan.Package.Verified != true {
		t.Fatalf("path completion should stage a verified package before storage, screen=%v package=%+v", model.Screen(), model.plan.Package)
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	model = update(t, model, press(tea.KeyDown, ""))
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.plan.StorageSettings.LocalDataRoot != "C:/VMMM/data" {
		t.Fatalf("storage schema field was not mapped: %+v", model.plan.StorageSettings)
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenProviderChoice {
		t.Fatalf("provider shortcut should open typed provider choices, got %v", model.Screen())
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenProviderWizard {
		t.Fatalf("provider choice should open typed fields, got %v", model.Screen())
	}
	for index := 0; index < len(providerFieldKeys(ProviderPurposeLLM)); index++ {
		model = update(t, model, press(tea.KeyDown, ""))
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenProviders {
		t.Fatalf("saving typed provider fields should return to provider page, got %v", model.Screen())
	}
	for index := 0; index < 3; index++ {
		model = update(t, model, press(tea.KeyDown, ""))
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenPath {
		t.Fatalf("service selection should lead to path choice, got %v", model.Screen())
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenFieldEdit {
		t.Fatalf("advanced config should open the field editor, got %v", model.Screen())
	}
	model = update(t, model, press(tea.KeyDown, ""))
	model = update(t, model, press(tea.KeyEnter, ""))
	model = update(t, model, press(tea.KeyDown, ""))
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenConfirm {
		t.Fatalf("valid configuration should lead to confirmation, got %v", model.Screen())
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenRunning {
		t.Fatalf("final install should lead to running page, got %v", model.Screen())
	}
	for _, request := range controller.requests {
		if request.Kind == OperationInstall && !request.Plan.Package.Verified {
			t.Fatal("final install request must carry a verified staged package")
		}
	}
}

// TestUnicodeInputAndViewportBounds keeps Chinese input intact and honors narrow terminals.
// TestUnicodeInputAndViewportBounds 保持中文输入完整，并遵守窄终端边界。
func TestUnicodeInputAndViewportBounds(t *testing.T) {
	model := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageEnglish})
	model.screen = ScreenCustomSource
	model.input = "中国"
	model = update(t, model, press(tea.KeyBackspace, ""))
	if model.input != "中" {
		t.Fatalf("backspace removed the wrong UTF-8 unit: %q", model.input)
	}
	model.width = 12
	model.height = 4
	view := model.View().Content
	for _, line := range strings.Split(view, "\n") {
		if len([]rune(line)) > 12 {
			t.Fatalf("line exceeds viewport: %q", line)
		}
	}
}

// TestAdvancedFieldViewportKeepsSelectedTailVisible verifies large schemas remain navigable.
// TestAdvancedFieldViewportKeepsSelectedTailVisible 验证字段很多时仍可看到列表末尾的选中项。
func TestAdvancedFieldViewportKeepsSelectedTailVisible(t *testing.T) {
	model := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageEnglish})
	model.screen = ScreenFieldEdit
	model.width = 90
	model.height = 12
	for index := 0; index < 40; index++ {
		model.configFields.Fields = append(model.configFields.Fields, ConfigField{Path: fmt.Sprintf("field_%02d", index), Type: "string", Editable: true})
	}
	model.cursor = 39
	view := model.View().Content
	if !strings.Contains(view, "> field_39") || !strings.Contains(view, "Enter run") {
		t.Fatalf("selected field or footer is hidden: %q", view)
	}
	if len(strings.Split(view, "\n")) > model.height {
		t.Fatalf("view exceeds viewport height: %q", view)
	}
	model.editingField = 39
	model.input = "updated"
	view = model.View().Content
	if !strings.Contains(view, "    > updated") {
		t.Fatalf("active field input is hidden: %q", view)
	}
	model.editingField = -1
	model.cursor = len(model.configFields.Fields)
	if view = model.View().Content; !strings.Contains(view, "> Save and return") {
		t.Fatalf("save option is hidden: %q", view)
	}
}

// TestStructuredFieldMultilineInput verifies collection YAML can be edited across lines.
// TestStructuredFieldMultilineInput 验证集合 YAML 可以跨行编辑。
func TestStructuredFieldMultilineInput(t *testing.T) {
	model := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageEnglish})
	model.screen = ScreenFieldEdit
	model.cursor = 0
	model.height = 9
	model.configFields.Fields = []ConfigField{{Path: "llm.routes", Type: "array", Value: "- model: old", Editable: true}}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.input != "- model: old" {
		t.Fatalf("existing structured value was not loaded: %q", model.input)
	}
	model.input = "- model: first"
	model = update(t, model, tea.KeyPressMsg(tea.Key{Code: 'o', Mod: tea.ModCtrl}))
	model = update(t, model, press(' ', "  name: primary"))
	if !strings.Contains(model.View().Content, "name: primary") {
		t.Fatalf("active multiline input is hidden: %q", model.View().Content)
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.configFields.Fields[0].Value != "- model: first\n  name: primary" {
		t.Fatalf("multiline field value = %q", model.configFields.Fields[0].Value)
	}
}

// TestRenderedConfigCannotInjectTerminalControls verifies untrusted values are display-safe.
// TestRenderedConfigCannotInjectTerminalControls 验证不可信配置值不能注入终端控制字符。
func TestRenderedConfigCannotInjectTerminalControls(t *testing.T) {
	model := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageEnglish})
	model.screen = ScreenFieldEdit
	model.cursor = 0
	model.configFields.Fields = []ConfigField{{Path: "unsafe", Type: "string", Value: "first\x1b[2J\rsecond", Editable: true}}
	view := model.View().Content
	if strings.ContainsAny(view, "\x1b\r") || !strings.Contains(view, "first [2J second") {
		t.Fatalf("unsafe terminal output: %q", view)
	}
}

// TestValidationGateRequiresFreshPlanValidation prevents confirmation after a plan mutation.
// TestValidationGateRequiresFreshPlanValidation 防止计划变更后沿用旧结果进入确认。
func TestValidationGateRequiresFreshPlanValidation(t *testing.T) {
	controller := &testController{}
	model := NewModel(ModelConfig{Controller: controller, Localizer: testLocalizer{}, Language: LanguageEnglish})
	model.screen = ScreenConfigCheck
	model.plan.Package = StagedPackage{Verified: true, StorageModes: []StorageMode{StorageNative}}
	model.cursor = 2
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenConfigCheck {
		t.Fatalf("unvalidated plan entered confirmation: %v", model.Screen())
	}

	model.validation = ValidationSummary{Valid: true, Summary: "valid"}
	model.cursor = 2
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenConfirm {
		t.Fatalf("validated plan did not enter confirmation: %v", model.Screen())
	}

	model.screen = ScreenService
	model.cursor = 0
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Validation().Valid {
		t.Fatal("service choice did not invalidate the old validation result")
	}

	model.screen = ScreenConfirm
	model.cursor = 0
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenConfigCheck {
		t.Fatalf("unvalidated install was not redirected to configuration check: %v", model.Screen())
	}
	for _, request := range controller.requests {
		if request.Kind == OperationInstall {
			t.Fatal("unvalidated plan unexpectedly reached the controller")
		}
	}
}

// TestFailedValidationCannotConfirm verifies a failed VMM validation never reaches confirmation.
// TestFailedValidationCannotConfirm 验证 VMM 校验失败时不能进入确认页。
func TestFailedValidationCannotConfirm(t *testing.T) {
	valid := false
	controller := &testController{validationValid: &valid}
	model := NewModel(ModelConfig{Controller: controller, Localizer: testLocalizer{}, Language: LanguageEnglish})
	model.screen = ScreenConfigCheck
	model.plan.Package = StagedPackage{Verified: true, StorageModes: []StorageMode{StorageNative}}
	model.cursor = 1
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenConfigCheck {
		t.Fatalf("failed validation entered an unexpected screen: %v", model.Screen())
	}
	if model.Validation().Valid {
		t.Fatal("failed validation was recorded as valid")
	}
	model.cursor = 2
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenConfigCheck {
		t.Fatalf("failed validation reached confirmation: %v", model.Screen())
	}
	for _, request := range controller.requests {
		if request.Kind == OperationInstall {
			t.Fatal("failed validation unexpectedly reached the install controller operation")
		}
	}
}

// TestServiceUserMustBeConfirmedAndInvalidatesValidation verifies explicit local-user confirmation.
// TestServiceUserMustBeConfirmedAndInvalidatesValidation 验证本机用户必须明确确认且会使旧校验失效。
func TestServiceUserMustBeConfirmedAndInvalidatesValidation(t *testing.T) {
	model := NewModel(ModelConfig{
		Localizer:  testLocalizer{},
		Language:   LanguageEnglish,
		PlatformOS: "linux",
		Defaults:   InstallPlan{ServiceUser: "alice"},
	})
	model.screen = ScreenService
	model.plan.ServiceMode = ServiceModeForeground
	model.validation = ValidationSummary{Valid: true, Summary: "valid"}
	model.cursor = 1
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenServiceUser {
		t.Fatalf("Linux service selection opened %v", model.Screen())
	}
	if !strings.Contains(model.View().Content, "alice") {
		t.Fatal("prefilled service user was not displayed for confirmation")
	}
	model.input = "bob"
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenPath || model.plan.ServiceUser != "bob" {
		t.Fatalf("confirmed service user = %q, screen=%v", model.plan.ServiceUser, model.Screen())
	}
	if model.Validation().Valid {
		t.Fatal("service-user edit kept the previous validation result")
	}

	empty := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageEnglish, PlatformOS: "darwin"})
	empty.screen = ScreenService
	empty.cursor = 1
	empty = update(t, empty, press(tea.KeyEnter, ""))
	empty.input = ""
	empty = update(t, empty, press(tea.KeyEnter, ""))
	if empty.Screen() != ScreenServiceUser {
		t.Fatalf("empty service user was accepted on %v", empty.Screen())
	}

	windows := NewModel(ModelConfig{
		Localizer:  testLocalizer{},
		Language:   LanguageEnglish,
		PlatformOS: "windows",
		Defaults:   InstallPlan{ServiceUser: "alice"},
	})
	if windows.plan.ServiceUser != "" {
		t.Fatalf("Windows defaults retained service user %q", windows.plan.ServiceUser)
	}
	windows.screen = ScreenService
	windows.plan.ServiceUser = "alice"
	windows.cursor = 1
	if strings.Contains(windows.View().Content, "alice") {
		t.Fatal("Windows service page exposed a service user")
	}
	windows = update(t, windows, press(tea.KeyEnter, ""))
	if windows.Screen() != ScreenPath || windows.plan.ServiceUser != "" {
		t.Fatalf("Windows service selection = user %q, screen=%v", windows.plan.ServiceUser, windows.Screen())
	}
}

// TestValidServiceUserMatchesServiceAdapterGrammar verifies the exact adapter account grammar.
// TestValidServiceUserMatchesServiceAdapterGrammar 验证服务适配器要求的精确账户语法。
func TestValidServiceUserMatchesServiceAdapterGrammar(t *testing.T) {
	valid := []string{
		"alice",
		"_service",
		"john.doe",
		"svc-user_1",
		strings.Repeat("a", 128),
	}
	for _, value := range valid {
		if !validServiceUser(value) {
			t.Errorf("validServiceUser(%q) = false, want true", value)
		}
	}

	invalid := []string{
		"",
		"-alice",
		".alice",
		"alice@domain",
		"alice/domain",
		"alice\\domain",
		"alice name",
		" alice",
		"alice ",
		"服务用户",
		strings.Repeat("a", 129),
	}
	for _, value := range invalid {
		if validServiceUser(value) {
			t.Errorf("validServiceUser(%q) = true, want false", value)
		}
	}

	model := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageEnglish, PlatformOS: "linux"})
	model.screen = ScreenServiceUser
	model.input = "alice@domain"
	model.plan.ServiceUser = "alice"
	model.validation = ValidationSummary{Valid: true, Summary: "valid"}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenServiceUser {
		t.Fatalf("invalid service user advanced to %v", model.Screen())
	}
	if model.plan.ServiceUser != "alice" {
		t.Fatalf("invalid service user replaced confirmed value with %q", model.plan.ServiceUser)
	}
	if !model.Validation().Valid {
		t.Fatal("invalid service user changed validation before confirmation")
	}
}

// TestCustomSourceIsProbedAndReused verifies custom HTTPS source creation and probing.
// TestCustomSourceIsProbedAndReused 验证自定义 HTTPS 源创建后会探测并继续复用。
func TestCustomSourceIsProbedAndReused(t *testing.T) {
	controller := &testController{}
	model := NewModel(ModelConfig{Controller: controller, Localizer: testLocalizer{}, Language: LanguageEnglish})
	model.screen = ScreenSource
	model.cursor = len(model.sources)
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenCustomSource {
		t.Fatalf("custom source action opened %v", model.Screen())
	}
	model.input = "https://mirror.example/"
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.Screen() != ScreenVersion {
		t.Fatalf("probed custom source did not continue to version selection: %v", model.Screen())
	}
	if !strings.HasPrefix(string(model.selectedSource.Source.ID), "github-proxy-custom-") {
		t.Fatalf("selected source ID = %q, want custom source ID", model.selectedSource.Source.ID)
	}
	if len(controller.requests) != 1 || controller.requests[0].Kind != OperationProbeSource {
		t.Fatalf("custom source requests = %+v, want one source probe", controller.requests)
	}
	if controller.requests[0].Source.Source.ID != model.selectedSource.Source.ID {
		t.Fatalf("probe source ID = %q, selected ID = %q", controller.requests[0].Source.Source.ID, model.selectedSource.Source.ID)
	}
}

// TestStorageCredentialSeparatesReferenceAndSecret verifies DSN references and write-only values.
// TestStorageCredentialSeparatesReferenceAndSecret 验证 DSN 引用与只写秘密值分离。
func TestStorageCredentialSeparatesReferenceAndSecret(t *testing.T) {
	secret := "postgres://user:secret@db.example/vmm"
	model := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageEnglish})
	model.plan.Storage.Mode = StoragePostgreSQL
	model.screen = ScreenStorageCredential
	model.storageCredential = StorageCredentialDraft{
		Variable:         "VMMM_POSTGRES_DSN",
		OriginalVariable: "VMMM_POSTGRES_DSN",
		Value:            secret,
		Path:             "C:/VMMM/.env",
	}
	model.saveStorageCredential()
	if model.plan.StorageSettings.PostgreSQLDSNVariable != "VMMM_POSTGRES_DSN" {
		t.Fatalf("DSN variable = %q", model.plan.StorageSettings.PostgreSQLDSNVariable)
	}
	if model.plan.StorageSettings.PostgreSQLDSNValue != secret {
		t.Fatalf("DSN value was not staged for the controller")
	}
	if model.storageCredential.Value != "" {
		t.Fatal("storage credential draft retained the raw DSN after staging")
	}
	if strings.Contains(model.View().Content, secret) {
		t.Fatal("storage view exposed the raw DSN")
	}

	retained := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageEnglish})
	retained.plan.Storage.Mode = StoragePostgreSQL
	retained.plan.StorageSettings = StorageSettings{
		PostgreSQLDSNVariable:          "VMMM_POSTGRES_DSN",
		PostgreSQLCredentialPath:       "C:/VMMM/.env",
		PostgreSQLCredentialConfigured: true,
	}
	retained.screen = ScreenStorageCredential
	retained.storageCredential = StorageCredentialDraft{
		Variable:           "VMMM_NEW_DSN",
		OriginalVariable:   "VMMM_POSTGRES_DSN",
		Path:               "C:/VMMM/.env",
		OriginalPath:       "C:/VMMM/.env",
		ExistingConfigured: true,
	}
	retained.saveStorageCredential()
	if retained.Screen() != ScreenStorageCredential {
		t.Fatalf("changed DSN variable retained an unrelated credential")
	}
	if retained.plan.StorageSettings.PostgreSQLDSNVariable != "VMMM_POSTGRES_DSN" {
		t.Fatalf("failed credential edit changed the previous DSN variable")
	}
}

// TestProviderWizardKeepsExistingSecretAndStagesTypedRoute checks masked .env behavior.
// TestProviderWizardKeepsExistingSecretAndStagesTypedRoute 检查遮蔽 .env 行为和强类型路由暂存。
func TestProviderWizardKeepsExistingSecretAndStagesTypedRoute(t *testing.T) {
	model := NewModel(ModelConfig{Localizer: testLocalizer{}, Language: LanguageEnglish})
	model.providerPurpose = ProviderPurposeLLM
	model.providerOptions = []ProviderMetadata{{
		ID:                           "openai",
		DisplayNameEN:                "OpenAI-compatible",
		EndpointRequirement:          providerwizard.RequirementRequired,
		ModelRequirement:             providerwizard.RequirementRequired,
		APIKeyEnvironmentRequirement: providerwizard.RequirementRequired,
	}}
	model.providerDraft = ProviderDraft{
		Purpose:                ProviderPurposeLLM,
		Provider:               "openai",
		Endpoint:               "https://api.example.test/v1",
		Model:                  "test-model",
		APIKeyEnvironmentNames: []string{"VMMM_TEST_KEY"},
		CredentialConfigured:   true,
	}
	model.providerOriginalKeyNames = []string{"VMMM_TEST_KEY"}
	model.screen = ScreenProviderWizard
	keys := providerFieldKeys(ProviderPurposeLLM)
	secretIndex := 0
	for index, key := range keys {
		if key == "api_key_value" {
			secretIndex = index
			break
		}
	}
	model.cursor = secretIndex
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.providerEditingField != secretIndex || model.input != "" {
		t.Fatalf("existing secret was not opened as write-only input: field=%d input=%q", model.providerEditingField, model.input)
	}
	model = update(t, model, press(tea.KeyEnter, ""))
	if model.providerEditingField != -1 || len(model.plan.Providers.CredentialUpdates) != 0 {
		t.Fatalf("empty secret input did not retain existing credential: field=%d updates=%+v", model.providerEditingField, model.plan.Providers.CredentialUpdates)
	}
	model.cursor = len(keys)
	model = update(t, model, press(tea.KeyEnter, ""))
	if len(model.plan.Providers.LLMRoutes) != 1 || model.plan.Providers.LLMRoutes[0].Provider != "openai" {
		t.Fatalf("typed provider route was not staged: %+v", model.plan.Providers.LLMRoutes)
	}
	if strings.Contains(model.View().Content, "super-secret") {
		t.Fatal("provider view exposed a secret value")
	}
}
