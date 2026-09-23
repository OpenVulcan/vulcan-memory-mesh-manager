// This file implements the Bubble Tea state machine and controller event boundary for VMMM.
// 本文件实现 VMMM 的 Bubble Tea 状态机与 Controller 事件边界。
package tui

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"charm.land/bubbletea/v2"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/i18n"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/providerwizard"
)

// Model is the Bubble Tea state machine for first install and installed management.
// Model 是首次安装与已安装管理使用的 Bubble Tea 状态机。
type Model struct {
	// providerTest stores a diagnostic for the current candidate only, separately from static validation.
	// providerTest 只保存当前候选配置的诊断，与静态校验分离。
	providerTest *ProviderTestSummary
	// editingInstalled stages the installed signed version before entering its configuration editor.
	// editingInstalled 在进入配置编辑器前暂存当前已安装的签名版本。
	editingInstalled bool
	// registeringService requires account confirmation for the installed-page service action.
	// registeringService 要求已安装页面的服务注册操作先确认账户。
	registeringService bool
	// controller owns every operation that can block or mutate the machine.
	// controller 负责所有可能阻塞或修改机器状态的操作。
	controller Controller
	// localizer resolves all catalog-backed user-facing text.
	// localizer 解析所有基于目录的用户可见文本。
	localizer Localizer
	// language is the active catalog language.
	// language 是当前使用的目录语言。
	language Language
	// platformOS identifies the target platform for service-user presentation.
	// platformOS 标识服务用户界面所针对的平台。
	platformOS string
	// screen identifies the active page.
	// screen 标识当前页面。
	screen Screen
	// previousScreen is the safe destination for Escape navigation.
	// previousScreen 是 Escape 返回时使用的安全目标页面。
	previousScreen Screen
	// width and height are updated by Bubble Tea resize events.
	// width 和 height 由 Bubble Tea resize 事件更新。
	width  int
	height int
	// cursor is the selected item on list-based pages.
	// cursor 是列表页面当前选择项。
	cursor int
	// input is the Unicode-safe text buffer used by custom source and path pages.
	// input 是自定义源和路径页面使用的 Unicode 安全文本缓冲区。
	input string
	// inputField selects the path field currently being edited.
	// inputField 选择当前正在编辑的路径字段。
	inputField int
	// sources and versions are immutable choices supplied or discovered by the controller.
	// sources 和 versions 是由配置或 Controller 提供的不可变选择。
	sources  []SourceOption
	versions []VersionOption
	// storage contains the five truthful storage explanations.
	// storage 包含五种真实的存储说明。
	storage []StorageOption
	// selectedSource, selectedVersion, and selectedStorage form the current install plan.
	// selectedSource、selectedVersion 和 selectedStorage 组成当前安装计划。
	selectedSource  SourceOption
	selectedVersion VersionOption
	selectedStorage StorageOption
	// plan holds install choices while the user moves through the wizard.
	// plan 在用户浏览向导时保存安装选择。
	plan InstallPlan
	// snapshot is the sanitized installed-state summary.
	// snapshot 是已脱敏的已安装状态摘要。
	snapshot InstallationSnapshot
	// validation is the latest authoritative VMM validation result.
	// validation 是最近一次 VMM 权威校验结果。
	validation ValidationSummary
	// configFields is the latest advanced configuration snapshot.
	// configFields 是最近一次高级配置字段快照。
	configFields ConfigFieldsResult
	// providerPurpose identifies the typed provider surface being edited.
	// providerPurpose 标识当前正在编辑的强类型供应商用途。
	providerPurpose ProviderPurpose
	// providerOptions contains the verified provider catalog for the active purpose.
	// providerOptions 保存当前用途的已核实供应商目录。
	providerOptions []ProviderMetadata
	// providerDraft contains typed values and a write-only credential input.
	// providerDraft 保存强类型值和只写凭据输入。
	providerDraft ProviderDraft
	// providerOriginalKeyNames records the loaded references for safe keep-existing behavior.
	// providerOriginalKeyNames 记录已加载引用，用于安全地保留现有凭据。
	providerOriginalKeyNames []string
	// providerEditingField is the active typed wizard field, or -1 when list-focused.
	// providerEditingField 是当前强类型向导字段，列表聚焦时为 -1。
	providerEditingField int
	// storageCredential contains the combined-database write-only credential form.
	// storageCredential 保存组合数据库只写凭据表单。
	storageCredential StorageCredentialDraft
	// storageEditingField is the active storage credential field, or -1 when list-focused.
	// storageEditingField 是当前存储凭据字段，列表聚焦时为 -1。
	storageEditingField int
	// fieldCursor selects one schema-backed field or the save action.
	// fieldCursor 选择一个 schema 字段或保存动作。
	fieldCursor int
	// editingField is the active field index, or -1 when the list is focused.
	// editingField 是当前编辑字段索引，列表聚焦时为 -1。
	editingField int
	// editingPrefix identifies the advanced configuration area being edited.
	// editingPrefix 标识当前编辑的高级配置区域。
	editingPrefix string
	// uninstall stores reversible retention choices.
	// uninstall 保存可逆的保留选择。
	uninstall UninstallOptions
	// serviceMode and autoStart are copied into plan before execution.
	// serviceMode 和 autoStart 在执行前复制到 plan。
	serviceMode ServiceMode
	autoStart   bool
	// addToPath is the explicit PATH choice.
	// addToPath 是明确的 PATH 选择。
	addToPath bool
	// busy indicates that a controller operation is still being observed.
	// busy 表示仍在观察 Controller 操作。
	busy bool
	// cancel is the context cancellation function for the active operation.
	// cancel 是当前操作的上下文取消函数。
	cancel context.CancelFunc
	// operationID rejects stale events from a cancelled operation.
	// operationID 拒绝已取消操作的过期事件。
	operationID uint64
	// operationKind and operationScreen remember how to route a completed operation.
	// operationKind 和 operationScreen 记录操作完成后的路由信息。
	operationKind   OperationKind
	operationScreen Screen
	// lastRequest is retained only for an explicit retry choice after failure.
	// lastRequest 仅在失败后用户明确选择重试时保留。
	lastRequest OperationRequest
	// retryable controls whether the error page offers retry.
	// retryable 控制错误页面是否提供重试。
	retryable bool
	// progress is the latest bounded progress snapshot.
	// progress 是最新的有界进度快照。
	progress Progress
	// status is a sanitized status line shown below the page heading.
	// status 是显示在页面标题下方的已脱敏状态行。
	status string
	// errorMessage is a recoverable user-facing error.
	// errorMessage 是可恢复的用户可见错误。
	errorMessage string
	// closed requests the Bubble Tea program to exit after a final message.
	// closed 请求 Bubble Tea 程序在最终消息后退出。
	closed bool
}

// operationStartedMsg carries the controller stream after Start returns.
// operationStartedMsg 携带 Start 返回的 Controller 操作流。
type operationStartedMsg struct {
	// id identifies the operation that owns the channel.
	// id 标识拥有该通道的操作。
	id uint64
	// events is the controller's progress stream.
	// events 是 Controller 的进度流。
	events <-chan OperationEvent
	// err is intentionally handled generically so raw errors cannot leak secrets.
	// err 只用于生成通用错误，避免原始错误泄漏密钥。
	err error
}

// operationEventMsg carries one event and the stream needed for the next read.
// operationEventMsg 携带一个事件以及下一次读取所需的事件流。
type operationEventMsg struct {
	// id identifies the active operation.
	// id 标识当前操作。
	id uint64
	// event is safe for direct display according to the Controller contract.
	// event 按 Controller 契约可直接安全展示。
	event OperationEvent
	// events is the same stream after this event.
	// events 是当前事件之后的同一事件流。
	events <-chan OperationEvent
}

// operationClosedMsg reports a stream that closed without a terminal event.
// operationClosedMsg 报告未发终止事件就关闭的操作流。
type operationClosedMsg struct {
	// id identifies the closed operation.
	// id 标识已关闭的操作。
	id uint64
}

// configFieldsMsg carries the result of the advanced configuration editor.
// configFieldsMsg 携带高级配置编辑器的结果。
type configFieldsMsg struct {
	// id identifies the editor invocation.
	// id 标识编辑器调用。
	id uint64
	// result contains display-safe fields.
	// result 包含可安全展示的字段。
	result ConfigFieldsResult
	// prefix identifies the schema area that was opened.
	// prefix 标识打开的 schema 区域。
	prefix string
	// err is rendered as a generic operation error.
	// err 渲染为通用操作错误。
	err error
}

// providerWizardMsg carries one typed provider catalog result.
// providerWizardMsg 携带一次强类型供应商目录结果。
type providerWizardMsg struct {
	// id identifies the editor invocation.
	// id 标识本次编辑器调用。
	id uint64
	// result contains the authoritative catalog and value-free draft.
	// result 包含权威目录和不含秘密值的草稿。
	result ProviderWizardResult
	// err is rendered as a generic user-facing error.
	// err 渲染为通用的用户可见错误。
	err error
}

// NewModel constructs a model without inspecting the host or performing network work.
// NewModel 构造模型时不检查主机，也不执行网络操作。
func NewModel(config ModelConfig) *Model {
	language := config.Language
	if language == "" {
		language = LanguageChinese
	}
	localizer := config.Localizer
	if localizer == nil {
		catalogLocalizer := NewCatalogLocalizer()
		localizer = catalogLocalizer
	}
	platformOS := strings.ToLower(strings.TrimSpace(config.PlatformOS))
	if platformOS == "" {
		platformOS = runtime.GOOS
	}
	sources := append([]SourceOption(nil), config.Sources...)
	if len(sources) == 0 {
		sources = DefaultSourceOptions()
	}
	storage := append([]StorageOption(nil), config.Storage...)
	if len(storage) == 0 {
		storage = DefaultStorageOptions()
	}
	snapshot := config.Initial
	if snapshot.ServiceMode == "" {
		snapshot.ServiceMode = ServiceModeForeground
	}
	screen := ScreenLanguage
	if snapshot.Installed || snapshot.Incomplete {
		screen = ScreenHome
	}
	cursor := 0
	if screen == ScreenLanguage && language == LanguageEnglish {
		cursor = 1
	}
	serviceMode := snapshot.ServiceMode
	autoStart := snapshot.AutoStart
	addToPath := snapshot.PathEnabled
	if !snapshot.Installed && !snapshot.Incomplete {
		if config.Defaults.ServiceMode != "" {
			serviceMode = config.Defaults.ServiceMode
		}
		autoStart = config.Defaults.AutoStart
		addToPath = config.Defaults.AddToPath
	}
	model := &Model{
		controller:           config.Controller,
		localizer:            localizer,
		language:             language,
		platformOS:           platformOS,
		screen:               screen,
		cursor:               cursor,
		width:                80,
		height:               24,
		sources:              sources,
		versions:             append([]VersionOption(nil), config.Versions...),
		storage:              storage,
		snapshot:             snapshot,
		serviceMode:          serviceMode,
		autoStart:            autoStart,
		addToPath:            addToPath,
		editingField:         -1,
		providerEditingField: -1,
		storageEditingField:  -1,
	}
	model.plan = config.Defaults
	if model.platformOS == "windows" {
		model.plan.ServiceUser = ""
	}
	model.plan.Source = model.sourceAt(0)
	model.selectedSource = model.sourceAt(0)
	if snapshot.Installed || snapshot.Incomplete {
		if snapshot.SourcePrefix != "" {
			if source, err := download.NewCustomProxy(snapshot.SourcePrefix); err == nil {
				model.sources = append(model.sources, SourceOption{Source: source, DisplayName: source.Name})
			}
		}
		for _, source := range model.sources {
			if string(source.Source.ID) == snapshot.SourceID {
				model.plan.Source = source
				model.selectedSource = source
				break
			}
		}
	}
	if model.plan.Storage.Mode == "" {
		model.plan.Storage = storage[0]
	}
	model.selectedStorage = model.plan.Storage
	if model.plan.ServiceMode == "" {
		model.plan.ServiceMode = model.serviceMode
	}
	if config.Initial.ProgramRoot != "" {
		model.plan.ProgramRoot = config.Initial.ProgramRoot
	}
	if config.Initial.ConfigRoot != "" {
		model.plan.ConfigRoot = config.Initial.ConfigRoot
	}
	if config.Initial.DataRoot != "" {
		model.plan.DataRoot = config.Initial.DataRoot
	}
	if config.Initial.Storage != "" {
		for _, option := range storage {
			if option.Mode == config.Initial.Storage {
				model.plan.Storage = option
				model.selectedStorage = option
				break
			}
		}
	}
	model.plan.ServiceMode = model.serviceMode
	model.plan.AutoStart = model.autoStart
	model.plan.AddToPath = model.addToPath
	if snapshot.Installed {
		switch config.EntryAction {
		case "edit":
			model.editingInstalled = true
			model.plan.Version = VersionOption{Tag: snapshot.VMMVersion, Available: true}
			model.setScreen(ScreenSource)
		case "upgrade", "rollback":
			model.plan.Rollback = config.EntryAction == "rollback"
			model.setScreen(ScreenSource)
		}
	}
	return model
}

// Init satisfies tea.Model and deliberately schedules no work before user input.
// Init 实现 tea.Model，并有意不在用户输入前调度任何工作。
func (m *Model) Init() tea.Cmd {
	return nil
}

// Run starts Bubble Tea with the supplied model and program options.
// Run 使用给定模型和程序选项启动 Bubble Tea。
func Run(model *Model, options ...tea.ProgramOption) error {
	if model == nil {
		return errors.New("tui: model is nil")
	}
	_, err := tea.NewProgram(model, options...).Run()
	return err
}

// Update applies one Bubble Tea message and returns the next command.
// Update 应用一条 Bubble Tea 消息并返回下一条命令。
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch message := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
		return m, nil
	case tea.KeyPressMsg:
		return m.updateKey(message)
	case operationStartedMsg:
		return m.updateOperationStarted(message)
	case operationEventMsg:
		return m.updateOperationEvent(message)
	case operationClosedMsg:
		return m.updateOperationClosed(message)
	case configFieldsMsg:
		return m.updateConfigFields(message)
	case providerWizardMsg:
		return m.updateProviderWizard(message)
	default:
		return m, nil
	}
}

// View renders a plain-text tea.View so narrow or colorless terminals remain usable.
// View 渲染纯文本 tea.View，使窄终端或无色终端仍可使用。
func (m *Model) View() tea.View {
	return tea.NewView(m.render())
}

// Screen returns the current page for deterministic tests and CLI integration.
// Screen 返回当前页面，供确定性测试和 CLI 集成使用。
func (m *Model) Screen() Screen {
	return m.screen
}

// Busy reports whether a cancellable controller operation is in flight.
// Busy 报告是否存在正在运行的可取消 Controller 操作。
func (m *Model) Busy() bool {
	return m.busy
}

// Snapshot returns a copy of the installed-state summary.
// Snapshot 返回已安装状态摘要的副本。
func (m *Model) Snapshot() InstallationSnapshot {
	return m.snapshot
}

// Validation returns a copy of the latest validation summary.
// Validation 返回最近校验摘要的副本。
func (m *Model) Validation() ValidationSummary {
	result := m.validation
	result.Errors = append([]string(nil), m.validation.Errors...)
	return result
}

// CloseRequested reports whether the user requested program termination.
// CloseRequested 报告用户是否请求退出程序。
func (m *Model) CloseRequested() bool {
	return m.closed
}

// updateKey handles global navigation, text entry, and page actions.
// updateKey 处理全局导航、文本输入和页面动作。
func (m *Model) updateKey(message tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if keyMatches(message, "ctrl+c") {
		if m.cancel != nil {
			m.cancel()
		}
		m.closed = true
		return m, tea.Quit
	}
	if keyMatches(message, "q") && !m.isTextInput() && !m.busy {
		m.closed = true
		return m, tea.Quit
	}
	if keyMatches(message, "esc") {
		return m.handleEscape()
	}
	if m.busy {
		if keyMatches(message, "esc") && m.cancel != nil {
			m.cancel()
			m.status = m.label("已请求取消；正在等待操作安全结束", "Cancellation requested; waiting for safe completion")
		}
		return m, nil
	}
	if m.isTextInput() {
		return m.updateTextInput(message)
	}
	if keyMatches(message, "up") || keyMatches(message, "k") {
		m.moveCursor(-1)
		return m, nil
	}
	if keyMatches(message, "down") || keyMatches(message, "j") {
		m.moveCursor(1)
		return m, nil
	}
	if keyMatches(message, "enter") || keyMatches(message, "right") {
		return m.activateSelection()
	}
	return m, nil
}

// handleEscape cancels active work or moves to the previous safe page.
// handleEscape 取消正在执行的工作，或返回上一个安全页面。
func (m *Model) handleEscape() (tea.Model, tea.Cmd) {
	if m.busy {
		if m.cancel != nil {
			m.cancel()
		}
		m.status = m.label("已请求取消；正在等待操作安全结束", "Cancellation requested; waiting for safe completion")
		return m, nil
	}
	switch m.screen {
	case ScreenLanguage:
		m.closed = true
		return m, tea.Quit
	case ScreenHome:
		m.closed = true
		return m, tea.Quit
	case ScreenSource, ScreenUninstall:
		m.setScreen(ScreenHome)
	case ScreenVersion:
		m.setScreen(ScreenSource)
	case ScreenInstallPath:
		m.setScreen(ScreenVersion)
	case ScreenDownload:
		m.setScreen(ScreenInstallPath)
	case ScreenStorage:
		m.setScreen(ScreenInstallPath)
	case ScreenStorageCredential:
		if m.storageEditingField >= 0 {
			m.storageEditingField = -1
			m.input = ""
			return m, nil
		}
		m.setScreen(ScreenStorage)
	case ScreenProviders:
		m.setScreen(ScreenStorage)
	case ScreenProviderChoice:
		m.setScreen(ScreenProviders)
	case ScreenProviderWizard:
		if m.providerEditingField >= 0 {
			m.providerEditingField = -1
			m.input = ""
			return m, nil
		}
		m.setScreen(ScreenProviderChoice)
	case ScreenFieldEdit:
		if m.editingField >= 0 {
			m.input = ""
			m.editingField = -1
			return m, nil
		}
		if m.operationScreen == ScreenConfigCheck {
			m.setScreen(ScreenConfigCheck)
		} else if m.operationScreen == ScreenStorage {
			m.setScreen(ScreenStorage)
		} else {
			m.setScreen(ScreenProviders)
		}
	case ScreenService:
		m.setScreen(ScreenProviders)
	case ScreenServiceUser:
		if m.registeringService {
			m.registeringService = false
			m.setScreen(ScreenHome)
			return m, nil
		}
		m.setScreen(ScreenService)
	case ScreenPath:
		m.setScreen(ScreenService)
	case ScreenConfigCheck:
		m.setScreen(ScreenPath)
	case ScreenConfirm:
		m.setScreen(ScreenConfigCheck)
	case ScreenProviderTest:
		m.setScreen(ScreenConfigCheck)
	case ScreenRunning, ScreenDone, ScreenError:
		if m.screen == ScreenError && m.operationScreen != ScreenError {
			m.setScreen(m.operationScreen)
		} else {
			m.setScreen(ScreenHome)
		}
	default:
		m.setScreen(ScreenHome)
	}
	return m, nil
}

// updateTextInput edits Unicode text and activates the current field on Enter.
// updateTextInput 编辑 Unicode 文本，并在 Enter 时提交当前字段。
func (m *Model) updateTextInput(message tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := message.Key()
	if keyMatches(message, "ctrl+u") {
		m.input = ""
		return m, nil
	}
	if m.screen == ScreenFieldEdit && m.editingField >= 0 && keyMatches(message, "ctrl+o", "alt+enter") {
		m.input += "\n"
		return m, nil
	}
	if keyMatches(message, "backspace") || keyMatches(message, "delete") {
		m.input = removeLastRune(m.input)
		return m, nil
	}
	if keyMatches(message, "enter") {
		return m.activateTextInput()
	}
	if key.Text != "" {
		m.input += key.Text
	}
	return m, nil
}

// activateTextInput commits custom source or one install path field.
// activateTextInput 提交自定义源或一个安装路径字段。
func (m *Model) activateTextInput() (tea.Model, tea.Cmd) {
	value := strings.TrimSpace(m.input)
	if m.screen == ScreenFieldEdit && m.editingField >= 0 && m.editingField < len(m.configFields.Fields) && m.configFields.Fields[m.editingField].RuleAsset {
		value = m.input
	}
	if value == "" && m.screen != ScreenFieldEdit && m.screen != ScreenProviderWizard && m.screen != ScreenStorageCredential {
		m.errorMessage = m.label("输入不能为空", "Input must not be empty")
		return m, nil
	}
	switch m.screen {
	case ScreenCustomSource:
		source, err := download.NewCustomProxy(value)
		if err != nil {
			m.errorMessage = m.label("自定义源必须是有效的 HTTPS GitHub 代理前缀", "Custom source must be a valid HTTPS GitHub proxy prefix")
			return m, nil
		}
		custom := SourceOption{Source: source, DisplayName: source.Name}
		customIndex := len(m.sources)
		for index := range m.sources {
			if m.sources[index].Source.ID == source.ID {
				m.sources[index] = custom
				customIndex = index
				break
			}
		}
		if customIndex == len(m.sources) {
			m.sources = append(m.sources, custom)
		}
		m.selectedSource = m.sources[customIndex]
		m.plan.Source = m.selectedSource
		m.invalidateValidation()
		m.setScreen(ScreenSource)
		m.cursor = customIndex
		return m, m.beginOperation(OperationRequest{Kind: OperationProbeSource, Source: m.selectedSource})
	case ScreenVersion:
		m.selectedVersion = VersionOption{Tag: value, Available: true}
		m.plan.Version = m.selectedVersion
		m.invalidateValidation()
		m.inputField = 0
		m.input = m.pathValue(0)
		m.setScreen(ScreenInstallPath)
		m.input = m.pathValue(0)
	case ScreenFieldEdit:
		if m.editingField < 0 || m.editingField >= len(m.configFields.Fields) {
			return m, nil
		}
		field := &m.configFields.Fields[m.editingField]
		if !field.Editable {
			m.status = m.label("该字段由 VMM schema 设为只读", "This field is read-only in the VMM schema")
			m.editingField = -1
			return m, nil
		}
		if field.Sensitive && value == "" {
			m.editingField = -1
			m.input = ""
			m.status = m.label("已保留现有敏感值，未修改该字段", "Existing sensitive value kept; field was not changed")
			return m, nil
		}
		field.Value = value
		field.Changed = true
		m.configFields.Changed = true
		m.editingField = -1
		m.input = ""
		m.status = m.label("字段已暂存，选择保存后才会写入配置", "Field staged; choose save before it is written")
	case ScreenProviderWizard:
		m.commitProviderTextInput(value)
	case ScreenStorageCredential:
		m.commitStorageCredentialTextInput(value)
	case ScreenServiceUser:
		if !validServiceUser(value) {
			m.errorMessage = m.label("服务用户格式无效：需匹配 [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", "Invalid service user: must match [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
			return m, nil
		}
		m.plan.ServiceUser = value
		m.invalidateValidation()
		if m.registeringService {
			m.registeringService = false
			return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionInstall, TargetMode: ServiceModeService, Plan: m.plan})
		}
		m.setScreen(ScreenPath)
	case ScreenInstallPath:
		switch m.inputField {
		case 0:
			m.plan.ProgramRoot = value
		case 1:
			m.plan.ConfigRoot = value
			m.plan.Providers.CredentialPath = filepath.Join(value, ".env")
			m.plan.StorageSettings.PostgreSQLCredentialPath = filepath.Join(value, ".env")
		case 2:
			m.plan.DataRoot = value
		}
		m.invalidateValidation()
		if m.inputField < 2 {
			m.inputField++
			m.input = m.pathValue(m.inputField)
			return m, nil
		}
		m.setScreen(ScreenDownload)
		return m, m.beginOperation(OperationRequest{Kind: OperationStagePackage, Plan: m.plan})
	}
	return m, nil
}

// activateSelection handles list selection without touching external state directly.
// activateSelection 处理列表选择，不直接触碰外部状态。
func (m *Model) activateSelection() (tea.Model, tea.Cmd) {
	switch m.screen {
	case ScreenLanguage:
		if m.cursor == 0 {
			m.language = LanguageChinese
		} else {
			m.language = LanguageEnglish
		}
		m.setScreen(ScreenSource)
	case ScreenHome:
		return m.activateHomeSelection()
	case ScreenSource:
		if m.cursor == len(m.sources) {
			m.input = ""
			m.setScreen(ScreenCustomSource)
			return m, nil
		}
		if m.cursor < 0 || m.cursor >= len(m.sources) {
			return m, nil
		}
		m.selectedSource = m.sourceAt(m.cursor)
		m.plan.Source = m.selectedSource
		m.invalidateValidation()
		return m, m.beginOperation(OperationRequest{Kind: OperationProbeSource, Source: m.selectedSource})
	case ScreenVersion:
		if len(m.versions) == 0 {
			m.input = ""
			m.setScreen(ScreenVersion)
			return m, nil
		}
		selected := m.versions[m.cursor]
		if !selected.Available {
			m.status = m.label("该版本尚未通过来源检查，已禁用选择", "This version has not passed source verification; selection is disabled")
			return m, nil
		}
		m.selectedVersion = selected
		m.plan.Version = m.selectedVersion
		m.invalidateValidation()
		m.inputField = 0
		m.setScreen(ScreenInstallPath)
		m.input = m.pathValue(0)
	case ScreenStorage:
		if m.cursor < 0 || m.cursor >= len(m.storage) {
			return m, nil
		}
		if !m.packageSupportsStorage(m.storage[m.cursor].Mode) {
			m.status = m.label("当前安装包不包含该存储模式，已禁用选择", "The staged package does not contain this storage mode; selection is disabled")
			return m, nil
		}
		m.selectedStorage = m.storage[m.cursor]
		m.plan.Storage = m.selectedStorage
		m.invalidateValidation()
		return m, m.beginConfigFields("storage")
	case ScreenStorageCredential:
		return m.activateStorageCredentialSelection()
	case ScreenProviders:
		if m.cursor == 3 {
			m.setScreen(ScreenService)
			return m, nil
		}
		return m, m.beginProviderWizard(providerPurposeAt(m.cursor))
	case ScreenProviderChoice:
		return m.activateProviderChoice()
	case ScreenProviderWizard:
		return m.activateProviderFieldSelection()
	case ScreenFieldEdit:
		return m.activateFieldSelection()
	case ScreenService:
		m.serviceMode = ServiceModeForeground
		m.autoStart = false
		if m.cursor == 1 {
			m.serviceMode = ServiceModeService
		}
		if m.cursor == 2 {
			m.serviceMode = ServiceModeService
			m.autoStart = true
		}
		m.plan.ServiceMode = m.serviceMode
		m.plan.AutoStart = m.autoStart
		m.invalidateValidation()
		if m.serviceMode == ServiceModeService && m.serviceUserVisible() {
			m.setScreen(ScreenServiceUser)
			m.input = m.plan.ServiceUser
		} else {
			m.plan.ServiceUser = ""
			m.setScreen(ScreenPath)
		}
	case ScreenPath:
		m.addToPath = m.cursor == 0
		m.plan.AddToPath = m.addToPath
		m.invalidateValidation()
		m.setScreen(ScreenConfigCheck)
	case ScreenConfigCheck:
		switch m.cursor {
		case 4:
			m.setScreen(ScreenProviderTest)
		case 0:
			return m, m.beginConfigFields("")
		case 1:
			return m, m.beginOperation(OperationRequest{Kind: OperationValidate, Plan: m.plan})
		case 3:
			return m, m.beginConfigFields("@rules")
		default:
			if !m.validation.Valid {
				m.status = m.label("必须先通过 VMM 配置检查，才能继续确认", "The VMM configuration must pass validation before confirmation")
				return m, nil
			}
			m.setScreen(ScreenConfirm)
		}
	case ScreenConfirm:
		if m.cursor == 0 {
			if !m.validation.Valid {
				m.setScreen(ScreenConfigCheck)
				m.status = m.label("当前计划尚未通过 VMM 配置检查", "The current plan has not passed VMM validation")
				return m, nil
			}
			return m, m.beginOperation(OperationRequest{Kind: OperationInstall, Plan: m.plan})
		}
		m.setScreen(ScreenConfigCheck)
	case ScreenProviderTest:
		if m.cursor == 0 {
			m.setScreen(ScreenConfigCheck)
			return m, nil
		}
		return m, m.beginOperation(OperationRequest{Kind: OperationTestProvider, Plan: m.plan, ProviderPurpose: providerPurposeAt(m.cursor - 1), ConfirmProviderNetwork: true})
	case ScreenRunning:
		return m.activateRunningSelection()
	case ScreenUninstall:
		return m.activateUninstallSelection()
	case ScreenError:
		if m.retryable && m.cursor == 0 {
			m.setScreen(m.operationScreen)
			return m, m.beginOperation(m.lastRequest)
		}
		if m.operationScreen != ScreenError {
			m.setScreen(m.operationScreen)
		} else {
			m.setScreen(ScreenHome)
		}
	case ScreenDone:
		m.setScreen(ScreenHome)
	}
	return m, nil
}

// activateFieldSelection focuses one editable schema field or commits the field set.
// activateFieldSelection 聚焦一个可编辑 schema 字段，或提交字段集合。
func (m *Model) activateFieldSelection() (tea.Model, tea.Cmd) {
	if m.cursor == len(m.configFields.Fields) {
		m.plan.ConfigFields = mergeConfigFields(m.plan.ConfigFields, m.configFields.Fields)
		m.applyStorageFields(m.configFields.Fields)
		m.invalidateValidation()
		m.status = m.label("配置字段已暂存，下一步会由 VMM CLI 校验", "Configuration fields staged; VMM CLI will validate them next")
		if m.operationScreen == ScreenConfigCheck {
			m.setScreen(ScreenConfigCheck)
		} else if m.operationScreen == ScreenStorage && isCombinedStorage(m.plan.Storage.Mode) {
			m.openStorageCredential()
		} else {
			m.setScreen(ScreenProviders)
		}
		return m, nil
	}
	if m.cursor < 0 || m.cursor >= len(m.configFields.Fields) {
		return m, nil
	}
	field := m.configFields.Fields[m.cursor]
	if !field.Editable {
		m.status = m.label("该字段由 VMM schema 设为只读", "This field is read-only in the VMM schema")
		return m, nil
	}
	m.editingField = m.cursor
	m.input = field.Value
	if field.Sensitive {
		m.input = ""
	}
	return m, nil
}

// activateProviderChoice selects an exact catalog entry before opening typed fields.
// activateProviderChoice 先选择精确目录项，再打开强类型字段。
func (m *Model) activateProviderChoice() (tea.Model, tea.Cmd) {
	if m.cursor < 0 || m.cursor >= len(m.providerOptions) {
		return m, nil
	}
	metadata := m.providerOptions[m.cursor]
	previousProvider := m.providerDraft.Provider
	if previousProvider != "" && previousProvider != metadata.ID {
		// Provider-specific values and credentials cannot be carried to a different catalog entry.
		// 供应商专属字段和凭据不能带到另一个目录项，避免误用旧 endpoint 或密钥。
		m.providerDraft.Endpoint = ""
		m.providerDraft.Model = ""
		m.providerDraft.Dimension = 0
		m.providerDraft.APIKeyEnvironmentNames = nil
		m.providerDraft.APIKeyValue = ""
		m.providerDraft.CredentialConfigured = false
		m.providerOriginalKeyNames = nil
	}
	m.providerDraft.Provider = metadata.ID
	if m.providerDraft.Endpoint == "" && metadata.EndpointRequirement == providerwizard.RequirementDefaulted {
		m.providerDraft.Endpoint = metadata.EndpointDefault
	}
	if m.providerDraft.Model == "" && metadata.ModelRequirement == providerwizard.RequirementDefaulted {
		m.providerDraft.Model = metadata.ModelDefault
	}
	m.providerEditingField = -1
	m.setScreen(ScreenProviderWizard)
	return m, nil
}

// activateProviderFieldSelection focuses a typed field, toggles rerank, or commits the draft.
// activateProviderFieldSelection 聚焦强类型字段、切换 rerank 或提交草稿。
func (m *Model) activateProviderFieldSelection() (tea.Model, tea.Cmd) {
	keys := providerFieldKeys(m.providerPurpose)
	if m.cursor == len(keys) {
		return m, m.saveProviderDraft()
	}
	if m.cursor < 0 || m.cursor >= len(keys) {
		return m, nil
	}
	key := keys[m.cursor]
	if key == "credential_path" {
		m.status = m.label("凭据路径由所选配置根确定", "Credential path follows the selected configuration root")
		return m, nil
	}
	if key == "enabled" {
		m.providerDraft.Enabled = !m.providerDraft.Enabled
		return m, nil
	}
	m.providerEditingField = m.cursor
	m.input = providerFieldValue(m.providerDraft, key)
	if key == "api_key_value" {
		m.input = ""
	}
	return m, nil
}

// commitProviderTextInput applies one typed field without writing external state.
// commitProviderTextInput 应用一个强类型字段，但不写入外部状态。
func (m *Model) commitProviderTextInput(value string) {
	keys := providerFieldKeys(m.providerPurpose)
	if m.providerEditingField < 0 || m.providerEditingField >= len(keys) {
		return
	}
	key := keys[m.providerEditingField]
	switch key {
	case "name":
		m.providerDraft.Name = value
	case "endpoint":
		m.providerDraft.Endpoint = value
	case "model":
		m.providerDraft.Model = value
	case "dimension":
		if value == "" {
			m.providerDraft.Dimension = 0
			break
		}
		dimension, err := strconv.Atoi(value)
		if err != nil || dimension <= 0 {
			m.errorMessage = m.label("维度必须是正整数", "Dimension must be a positive integer")
			return
		}
		m.providerDraft.Dimension = dimension
	case "priority":
		if value == "" {
			m.providerDraft.Priority = 0
			break
		}
		priority, err := strconv.Atoi(value)
		if err != nil || priority < 0 {
			m.errorMessage = m.label("优先级必须是非负整数", "Priority must be a non-negative integer")
			return
		}
		m.providerDraft.Priority = priority
	case "api_key_names":
		m.providerDraft.APIKeyEnvironmentNames = splitEnvironmentNames(value)
	case "api_key_value":
		m.providerDraft.APIKeyValue = value
	case "credential_path":
		m.providerDraft.CredentialPath = value
	}
	m.errorMessage = ""
	m.providerEditingField = -1
	m.input = ""
}

// saveProviderDraft validates the typed values against returned metadata and updates the install plan.
// saveProviderDraft 按返回的元数据校验强类型值，并更新安装计划。
func (m *Model) saveProviderDraft() tea.Cmd {
	metadata, found := m.activeProviderMetadata()
	if !found {
		m.errorMessage = m.label("未选择有效供应商", "No valid provider is selected")
		return nil
	}
	needsRouteValues := m.providerPurpose != ProviderPurposeRerank || m.providerDraft.Enabled
	if needsRouteValues && metadata.EndpointRequirement == providerwizard.RequirementRequired && strings.TrimSpace(m.providerDraft.Endpoint) == "" {
		m.errorMessage = m.label("该供应商要求填写 endpoint", "This provider requires an endpoint")
		return nil
	}
	if needsRouteValues && metadata.ModelRequirement == providerwizard.RequirementRequired && strings.TrimSpace(m.providerDraft.Model) == "" {
		m.errorMessage = m.label("该供应商要求填写模型", "This provider requires a model")
		return nil
	}
	if needsRouteValues && metadata.DimensionRequirement == providerwizard.RequirementRequired && m.providerDraft.Dimension <= 0 {
		m.errorMessage = m.label("该 embedding 供应商要求填写正数维度", "This embedding provider requires a positive dimension")
		return nil
	}
	if needsRouteValues && metadata.APIKeyEnvironmentRequirement == providerwizard.RequirementRequired && len(m.providerDraft.APIKeyEnvironmentNames) == 0 {
		m.errorMessage = m.label("该供应商要求至少一个 API key 环境变量引用", "This provider requires at least one API key environment reference")
		return nil
	}
	for _, name := range m.providerDraft.APIKeyEnvironmentNames {
		if !validEnvironmentName(name) {
			m.errorMessage = m.label("API key 环境变量名无效", "An API key environment name is invalid")
			return nil
		}
	}
	keepExisting := sameStrings(m.providerDraft.APIKeyEnvironmentNames, m.providerOriginalKeyNames) && m.providerDraft.CredentialConfigured
	if strings.TrimSpace(m.providerDraft.APIKeyValue) != "" && len(m.providerDraft.APIKeyEnvironmentNames) == 0 {
		m.errorMessage = m.label("输入 API key 前必须先填写环境变量名", "Enter an environment variable name before entering an API key")
		return nil
	}
	if needsRouteValues && metadata.APIKeyEnvironmentRequirement == providerwizard.RequirementRequired && !keepExisting && strings.TrimSpace(m.providerDraft.APIKeyValue) == "" {
		m.errorMessage = m.label("请输入 API key，或保留已存在的 .env 凭据", "Enter an API key or retain an existing .env credential")
		return nil
	}
	if m.providerPurpose == providerPurposeAt(2) && m.providerDraft.Enabled && m.providerDraft.Provider == "" {
		m.errorMessage = m.label("启用 rerank 时必须选择供应商", "An enabled reranker must select a provider")
		return nil
	}

	route := ProviderRoute{
		Name:                   m.providerDraft.Name,
		Provider:               m.providerDraft.Provider,
		Endpoint:               m.providerDraft.Endpoint,
		Model:                  m.providerDraft.Model,
		Dimension:              m.providerDraft.Dimension,
		Priority:               m.providerDraft.Priority,
		APIKeyEnvironmentNames: append([]string(nil), m.providerDraft.APIKeyEnvironmentNames...),
	}
	switch m.providerPurpose {
	case ProviderPurposeLLM:
		m.plan.Providers.LLMRoutes = []ProviderRoute{route}
	case ProviderPurposeEmbedding:
		m.plan.Providers.Embedding = &route
	case ProviderPurposeRerank:
		m.plan.Providers.RerankConfigured = true
		m.plan.Providers.RerankEnabled = m.providerDraft.Enabled
		if m.providerDraft.Enabled {
			m.plan.Providers.RerankRoutes = []ProviderRoute{route}
		} else {
			m.plan.Providers.RerankRoutes = nil
		}
	}
	m.plan.Providers.CredentialPath = m.providerDraft.CredentialPath
	if strings.TrimSpace(m.providerDraft.APIKeyValue) != "" && len(m.providerDraft.APIKeyEnvironmentNames) > 0 {
		m.plan.Providers.CredentialUpdates = upsertCredentialUpdate(m.plan.Providers.CredentialUpdates, CredentialUpdate{
			EnvironmentName: m.providerDraft.APIKeyEnvironmentNames[0],
			Value:           m.providerDraft.APIKeyValue,
		})
	}
	m.providerDraft.APIKeyValue = ""
	m.providerDraft.CredentialConfigured = true
	m.invalidateValidation()
	m.status = m.label("供应商配置已暂存，密钥将在安装事务中安全写入 .env", "Provider configuration staged; the key will be written to .env inside the install transaction")
	m.setScreen(ScreenProviders)
	return nil
}

// activeProviderMetadata returns the exact metadata selected in the current provider catalog.
// activeProviderMetadata 返回当前目录中选定供应商的精确元数据。
func (m *Model) activeProviderMetadata() (ProviderMetadata, bool) {
	for _, metadata := range m.providerOptions {
		if metadata.ID == m.providerDraft.Provider {
			return metadata, true
		}
	}
	return ProviderMetadata{}, false
}

// beginProviderWizard loads typed provider metadata in a Bubble Tea command.
// beginProviderWizard 在 Bubble Tea 命令中加载强类型供应商元数据。
func (m *Model) beginProviderWizard(purpose ProviderPurpose) tea.Cmd {
	controller, ok := m.controller.(ProviderWizardController)
	if !ok {
		m.operationScreen = m.screen
		m.setScreen(ScreenError)
		m.errorMessage = m.label("当前控制器未提供强类型供应商向导", "The current controller does not provide the typed provider wizard")
		return nil
	}
	m.operationID++
	id := m.operationID
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.busy = true
	m.errorMessage = ""
	m.status = m.label("正在加载供应商目录", "Loading provider catalog")
	m.operationScreen = m.screen
	m.retryable = false
	m.providerPurpose = purpose
	draft := m.providerDraftForPurpose(purpose)
	draft.CredentialPath = filepath.Join(m.plan.ConfigRoot, ".env")
	draft.APIKeyValue = ""
	request := ProviderWizardRequest{Purpose: purpose, Draft: draft}
	return func() tea.Msg {
		result, err := controller.OpenProviderWizard(ctx, request)
		return providerWizardMsg{id: id, result: result, err: err}
	}
}

// updateProviderWizard stores the typed catalog result and enters provider selection.
// updateProviderWizard 保存强类型目录结果并进入供应商选择页。
func (m *Model) updateProviderWizard(message providerWizardMsg) (tea.Model, tea.Cmd) {
	if message.id != m.operationID {
		return m, nil
	}
	m.busy = false
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if message.err != nil {
		m.setScreen(ScreenError)
		m.errorMessage = m.label("供应商目录无法打开", "Provider catalog could not be opened")
		return m, nil
	}
	if message.result.Purpose != "" && message.result.Purpose != m.providerPurpose {
		m.setScreen(ScreenError)
		m.errorMessage = m.label("供应商目录用途不匹配", "Provider catalog purpose does not match the requested wizard")
		return m, nil
	}
	m.providerOptions = append([]ProviderMetadata(nil), message.result.Providers...)
	m.providerDraft = message.result.Draft
	m.providerDraft.Purpose = m.providerPurpose
	m.providerDraft.APIKeyValue = ""
	m.providerOriginalKeyNames = append([]string(nil), m.providerDraft.APIKeyEnvironmentNames...)
	m.status = operationMessage(message.result.Summary, m.label("供应商目录已加载", "Provider catalog loaded"))
	if len(m.providerOptions) == 0 {
		m.setScreen(ScreenError)
		m.errorMessage = m.label("供应商目录为空", "Provider catalog is empty")
		return m, nil
	}
	m.setScreen(ScreenProviderChoice)
	for index, metadata := range m.providerOptions {
		if metadata.ID == m.providerDraft.Provider {
			m.cursor = index
			break
		}
	}
	return m, nil
}

// providerDraftForPurpose converts the plan to a value-free wizard draft.
// providerDraftForPurpose 将计划转换为不含秘密值的向导草稿。
func (m *Model) providerDraftForPurpose(purpose ProviderPurpose) ProviderDraft {
	draft := ProviderDraft{Purpose: purpose, CredentialPath: m.plan.Providers.CredentialPath}
	switch purpose {
	case ProviderPurposeLLM:
		if len(m.plan.Providers.LLMRoutes) > 0 {
			draft = draftFromRoute(purpose, m.plan.Providers.LLMRoutes[0])
		}
	case ProviderPurposeEmbedding:
		if m.plan.Providers.Embedding != nil {
			draft = draftFromRoute(purpose, *m.plan.Providers.Embedding)
		}
	case ProviderPurposeRerank:
		draft.Enabled = m.plan.Providers.RerankEnabled
		if len(m.plan.Providers.RerankRoutes) > 0 {
			draft = draftFromRoute(purpose, m.plan.Providers.RerankRoutes[0])
			draft.Enabled = m.plan.Providers.RerankEnabled
		}
	}
	draft.Purpose = purpose
	draft.CredentialPath = m.plan.Providers.CredentialPath
	return draft
}

// draftFromRoute copies plan route values into a typed wizard draft.
// draftFromRoute 将计划路由值复制到强类型向导草稿。
func draftFromRoute(purpose ProviderPurpose, route ProviderRoute) ProviderDraft {
	return ProviderDraft{
		Purpose:                purpose,
		Name:                   route.Name,
		Provider:               route.Provider,
		Endpoint:               route.Endpoint,
		Model:                  route.Model,
		Dimension:              route.Dimension,
		Priority:               route.Priority,
		APIKeyEnvironmentNames: append([]string(nil), route.APIKeyEnvironmentNames...),
		CredentialConfigured:   len(route.APIKeyEnvironmentNames) > 0,
	}
}

// providerFieldKeys returns the stable typed field order for one provider purpose.
// providerFieldKeys 返回一个供应商用途的稳定强类型字段顺序。
func providerFieldKeys(purpose ProviderPurpose) []string {
	keys := make([]string, 0, 8)
	if purpose == ProviderPurposeLLM || purpose == ProviderPurposeRerank {
		keys = append(keys, "name")
	}
	if purpose == ProviderPurposeRerank {
		keys = append(keys, "enabled", "priority")
	}
	keys = append(keys, "endpoint", "model")
	if purpose == ProviderPurposeEmbedding {
		keys = append(keys, "dimension")
	}
	keys = append(keys, "api_key_names", "api_key_value", "credential_path")
	return keys
}

// providerFieldValue returns a safe editable representation of one typed field.
// providerFieldValue 返回一个强类型字段的安全可编辑表示。
func providerFieldValue(draft ProviderDraft, key string) string {
	switch key {
	case "name":
		return draft.Name
	case "endpoint":
		return draft.Endpoint
	case "model":
		return draft.Model
	case "dimension":
		if draft.Dimension > 0 {
			return strconv.Itoa(draft.Dimension)
		}
	case "priority":
		return strconv.Itoa(draft.Priority)
	case "api_key_names":
		return strings.Join(draft.APIKeyEnvironmentNames, ",")
	case "credential_path":
		return draft.CredentialPath
	}
	return ""
}

// splitEnvironmentNames parses comma or whitespace separated environment names without secrets.
// splitEnvironmentNames 解析逗号或空白分隔的环境变量名称，不处理秘密值。
func splitEnvironmentNames(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' })
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}

// sameStrings compares environment references in their declared order.
// sameStrings 按声明顺序比较环境变量引用。
func sameStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// upsertCredentialUpdate replaces one pending secret update by environment name.
// upsertCredentialUpdate 按环境变量名称替换一条待写入的秘密更新。
func upsertCredentialUpdate(existing []CredentialUpdate, update CredentialUpdate) []CredentialUpdate {
	result := append([]CredentialUpdate(nil), existing...)
	for index := range result {
		if result[index].EnvironmentName == update.EnvironmentName {
			result[index] = update
			return result
		}
	}
	return append(result, update)
}

// openStorageCredential prepares the PostgreSQL or ParadeDB credential form.
// openStorageCredential 准备 PostgreSQL 或 ParadeDB 凭据表单。
func (m *Model) openStorageCredential() {
	settings := m.plan.StorageSettings
	settings.PostgreSQLCredentialPath = filepath.Join(m.plan.ConfigRoot, ".env")
	m.storageCredential = StorageCredentialDraft{
		Variable:           settings.PostgreSQLDSNVariable,
		OriginalVariable:   settings.PostgreSQLDSNVariable,
		Path:               settings.PostgreSQLCredentialPath,
		OriginalPath:       settings.PostgreSQLCredentialPath,
		ExistingConfigured: settings.PostgreSQLCredentialConfigured,
	}
	if m.storageCredential.Variable == "" {
		m.storageCredential.Variable = "VMMM_POSTGRES_DSN"
	}
	m.storageEditingField = -1
	m.setScreen(ScreenStorageCredential)
}

// activateStorageCredentialSelection focuses a credential field or commits the protected form.
// activateStorageCredentialSelection 聚焦凭据字段或提交受保护表单。
func (m *Model) activateStorageCredentialSelection() (tea.Model, tea.Cmd) {
	keys := storageCredentialKeys()
	if m.cursor == len(keys) {
		m.saveStorageCredential()
		return m, nil
	}
	if m.cursor < 0 || m.cursor >= len(keys) {
		return m, nil
	}
	if keys[m.cursor] == "path" {
		m.status = m.label("凭据路径由所选配置根确定", "Credential path follows the selected configuration root")
		return m, nil
	}
	m.storageEditingField = m.cursor
	m.input = storageCredentialValue(m.storageCredential, keys[m.cursor])
	if keys[m.cursor] == "value" {
		m.input = ""
	}
	return m, nil
}

// commitStorageCredentialTextInput applies one storage credential field without writing files.
// commitStorageCredentialTextInput 应用一个存储凭据字段，但不写入文件。
func (m *Model) commitStorageCredentialTextInput(value string) {
	keys := storageCredentialKeys()
	if m.storageEditingField < 0 || m.storageEditingField >= len(keys) {
		return
	}
	switch keys[m.storageEditingField] {
	case "variable":
		m.storageCredential.Variable = value
	case "value":
		m.storageCredential.Value = value
	case "path":
		m.storageCredential.Path = value
	}
	m.errorMessage = ""
	m.storageEditingField = -1
	m.input = ""
}

// saveStorageCredential validates and copies the protected combined-database form to the plan.
// saveStorageCredential 校验并将受保护的组合数据库表单复制到计划。
func (m *Model) saveStorageCredential() {
	variable := strings.TrimSpace(m.storageCredential.Variable)
	if !validEnvironmentName(variable) {
		m.errorMessage = m.label("DSN 环境变量名无效", "DSN environment variable name is invalid")
		return
	}
	path := strings.TrimSpace(m.storageCredential.Path)
	keepExisting := m.storageCredential.ExistingConfigured && variable == m.storageCredential.OriginalVariable && path == strings.TrimSpace(m.storageCredential.OriginalPath)
	if strings.TrimSpace(m.storageCredential.Value) == "" && !keepExisting {
		m.errorMessage = m.label("请输入 PostgreSQL/ParadeDB DSN，或保留已存在的 .env 凭据", "Enter the PostgreSQL/ParadeDB DSN or retain the existing .env credential")
		return
	}
	settings := &m.plan.StorageSettings
	settings.PostgreSQLDSNVariable = variable
	settings.PostgreSQLDSNValue = m.storageCredential.Value
	settings.PostgreSQLCredentialPath = path
	settings.PostgreSQLCredentialConfigured = keepExisting || strings.TrimSpace(m.storageCredential.Value) != ""
	m.storageCredential.Value = ""
	m.invalidateValidation()
	m.status = m.label("数据库凭据已暂存，DSN 将在安装事务中安全写入 .env", "Database credential staged; the DSN will be written to .env inside the install transaction")
	m.setScreen(ScreenProviders)
}

// storageCredentialKeys returns the stable fields shown for combined storage.
// storageCredentialKeys 返回组合存储显示的稳定字段。
func storageCredentialKeys() []string {
	return []string{"variable", "value", "path"}
}

// storageCredentialValue returns a non-secret display value for one credential field.
// storageCredentialValue 返回一个凭据字段的非秘密显示值。
func storageCredentialValue(draft StorageCredentialDraft, key string) string {
	switch key {
	case "variable":
		return draft.Variable
	case "path":
		return draft.Path
	default:
		return ""
	}
}

// validEnvironmentName checks the portable environment-variable grammar without external state.
// validEnvironmentName 在不访问外部状态的情况下检查可移植环境变量语法。
func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, char := range value {
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (index > 0 && char == '_') || (index > 0 && char >= '0' && char <= '9') {
			continue
		}
		return false
	}
	return true
}

// isCombinedStorage identifies PostgreSQL and ParadeDB modes requiring a DSN credential.
// isCombinedStorage 标识需要 DSN 凭据的 PostgreSQL 和 ParadeDB 模式。
func isCombinedStorage(mode StorageMode) bool {
	return mode == StoragePostgreSQL || mode == StorageParadeDB
}

// applyStorageFields mirrors only confirmed VMM schema paths into the typed install settings.
// applyStorageFields 只将已确认的 VMM schema 路径映射到类型化安装设置。
func (m *Model) applyStorageFields(fields []ConfigField) {
	for _, field := range fields {
		switch field.Path {
		case "storage.local_data_root":
			m.plan.StorageSettings.LocalDataRoot = field.Value
		case "sqlite.native.path":
			m.plan.StorageSettings.NativeSQLitePath = field.Value
		case "lancedb.native.path":
			m.plan.StorageSettings.NativeLanceDBPath = field.Value
		case "controller.endpoint":
			m.plan.StorageSettings.ControllerEndpoint = field.Value
		case "postgres.dsn":
			m.applyPostgreSQLDSNReference(field.Value)
		case "postgres.flavor":
			m.plan.StorageSettings.PostgreSQLFlavor = field.Value
		}
	}
}

// applyPostgreSQLDSNReference records only a safe environment reference or configured marker.
// applyPostgreSQLDSNReference 只记录安全的环境引用或已配置标记。
func (m *Model) applyPostgreSQLDSNReference(value string) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		name := strings.TrimSuffix(strings.TrimPrefix(value, "${"), "}")
		if validEnvironmentName(name) {
			m.plan.StorageSettings.PostgreSQLDSNVariable = name
		}
		m.plan.StorageSettings.PostgreSQLCredentialConfigured = true
		return
	}
	if value != "" {
		m.plan.StorageSettings.PostgreSQLCredentialConfigured = true
	}
}

// packageSupportsStorage enforces the package receipt capability boundary before configuration.
// packageSupportsStorage 在配置前执行安装包收据能力边界检查。
func (m *Model) packageSupportsStorage(mode StorageMode) bool {
	if !m.plan.Package.Verified || len(m.plan.Package.StorageModes) == 0 {
		return false
	}
	for _, supported := range m.plan.Package.StorageModes {
		if supported == mode {
			return true
		}
	}
	return false
}

// mergeConfigFields replaces edited paths while preserving fields from previous editor areas.
// mergeConfigFields 替换已编辑路径，同时保留其他编辑区域的字段。
func mergeConfigFields(existing []ConfigField, updates []ConfigField) []ConfigField {
	result := cloneConfigFields(existing)
	for _, update := range updates {
		if !update.Changed {
			continue
		}
		update.Enum = append([]string(nil), update.Enum...)
		replaced := false
		for index := range result {
			if result[index].Path == update.Path {
				result[index] = update
				replaced = true
				break
			}
		}
		if !replaced {
			result = append(result, update)
		}
	}
	return result
}

// cloneConfigFields copies field metadata so controller-owned slices cannot mutate the model.
// cloneConfigFields 复制字段元数据，避免 Controller 拥有的切片修改模型。
func cloneConfigFields(fields []ConfigField) []ConfigField {
	result := make([]ConfigField, len(fields))
	for index, field := range fields {
		result[index] = field
		result[index].Enum = append([]string(nil), field.Enum...)
	}
	return result
}

// activateHomeSelection maps installed actions to controller requests or pages.
// activateHomeSelection 将已安装操作映射为 Controller 请求或页面。
func (m *Model) activateHomeSelection() (tea.Model, tea.Cmd) {
	if m.snapshot.Incomplete && m.cursor != 11 && m.cursor != 1 && m.cursor != 4 && m.cursor != 9 {
		m.errorMessage = m.label("安装未完成，请选择重新安装 / 修复", "Installation is incomplete; choose Reinstall / repair")
		return m, nil
	}
	switch m.cursor {
	case 0:
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionStart, TargetMode: m.snapshot.ServiceMode})
	case 1:
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionStop, TargetMode: m.snapshot.ServiceMode})
	case 2:
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionRestart, TargetMode: m.snapshot.ServiceMode})
	case 3:
		if m.serviceUserVisible() {
			m.registeringService = true
			m.setScreen(ScreenServiceUser)
			m.input = m.plan.ServiceUser
			return m, nil
		}
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionInstall, TargetMode: ServiceModeService, Plan: m.plan})
	case 4:
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionUninstall, TargetMode: m.snapshot.ServiceMode})
	case 5:
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionEnable, TargetMode: m.snapshot.ServiceMode})
	case 6:
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionDisable, TargetMode: m.snapshot.ServiceMode})
	case 7:
		m.plan.Repair = false
		m.editingInstalled = true
		m.plan.Rollback = false
		m.plan.Version = VersionOption{Tag: m.snapshot.VMMVersion, Available: true}
		m.setScreen(ScreenSource)
		m.status = m.label("先验证并下载当前版本，再编辑配置", "Verify and download the installed release before editing configuration")
	case 8:
		m.plan.Repair = false
		m.editingInstalled = false
		m.plan.Rollback = false
		m.setScreen(ScreenSource)
	case 9:
		m.setScreen(ScreenUninstall)
	case 10:
		m.plan.Repair = false
		m.editingInstalled = false
		m.plan.Rollback = true
		m.setScreen(ScreenSource)
	case 11:
		m.plan.Repair = true
		m.editingInstalled = m.snapshot.VMMVersion != ""
		m.plan.Rollback = false
		m.plan.Version = VersionOption{Tag: m.snapshot.VMMVersion, Available: true}
		m.setScreen(ScreenSource)
		m.status = m.label("重新下载签名包并检查配置后安装，保留数据库", "Download the signed package and validate configuration before reinstalling; keep databases")
	}
	return m, nil
}

// activateRunningSelection provides direct lifecycle controls after installation.
// activateRunningSelection 在安装完成后提供直接生命周期控制。
func (m *Model) activateRunningSelection() (tea.Model, tea.Cmd) {
	switch m.cursor {
	case 0:
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionStart, TargetMode: m.snapshot.ServiceMode})
	case 1:
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionStop, TargetMode: m.snapshot.ServiceMode})
	case 2:
		return m, m.beginOperation(OperationRequest{Kind: OperationService, ServiceAction: ServiceActionRestart, TargetMode: m.snapshot.ServiceMode})
	case 3:
		m.setScreen(ScreenProviders)
	case 4:
		m.setScreen(ScreenHome)
	}
	return m, nil
}

// activateUninstallSelection toggles retention and starts the explicit uninstall action.
// activateUninstallSelection 切换保留选项，并启动明确的卸载动作。
func (m *Model) activateUninstallSelection() (tea.Model, tea.Cmd) {
	switch m.cursor {
	case 0:
		m.uninstall.KeepConfig = !m.uninstall.KeepConfig
	case 1:
		m.uninstall.KeepData = !m.uninstall.KeepData
	case 2:
		m.uninstall.RemoveService = !m.uninstall.RemoveService
	case 3:
		m.uninstall.RemovePath = !m.uninstall.RemovePath
	case 4:
		return m, m.beginOperation(OperationRequest{Kind: OperationUninstall, Uninstall: m.uninstall})
	case 5:
		m.setScreen(ScreenHome)
	}
	return m, nil
}

// beginOperation starts a controller stream in a Bubble Tea command closure.
// beginOperation 在 Bubble Tea 命令闭包中启动 Controller 事件流。
func (m *Model) beginOperation(request OperationRequest) tea.Cmd {
	if request.Kind == OperationInstall && !m.validation.Valid {
		m.operationScreen = m.screen
		m.lastRequest = request
		m.retryable = false
		m.setScreen(ScreenError)
		m.errorMessage = m.label("当前计划尚未通过 VMM 配置检查，不能执行安装", "The current plan has not passed VMM validation")
		return nil
	}
	if request.Kind == OperationInstall && !request.Plan.Package.Verified {
		m.operationScreen = m.screen
		m.lastRequest = request
		m.retryable = false
		m.setScreen(ScreenError)
		m.errorMessage = m.label("安装包尚未通过完整校验，不能执行安装", "Installation cannot start before the package passes complete verification")
		return nil
	}
	if request.Kind == OperationStagePackage {
		// A new source, version, or root selection must never reuse an older verified receipt.
		// 新的来源、版本或根目录选择绝不能复用旧的已验证收据。
		m.plan.Package = StagedPackage{}
		request.Plan.Package = StagedPackage{}
		m.invalidateValidation()
	}
	if request.Kind == OperationValidate {
		m.validation = ValidationSummary{}
	}
	if request.Kind == OperationTestProvider {
		m.providerTest = nil
	}
	if m.controller == nil {
		m.operationScreen = m.screen
		m.setScreen(ScreenError)
		m.errorMessage = m.label("当前没有可用的安装控制器", "No installation controller is available")
		return nil
	}
	m.operationID++
	id := m.operationID
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.busy = true
	m.errorMessage = ""
	m.status = m.label("正在执行操作", "Operation in progress")
	m.progress = Progress{Stage: string(request.Kind), Message: m.status}
	m.operationKind = request.Kind
	m.operationScreen = m.screen
	m.lastRequest = request
	m.retryable = request.Kind != OperationTestProvider
	return func() tea.Msg {
		events, err := m.controller.Start(ctx, request)
		return operationStartedMsg{id: id, events: events, err: err}
	}
}

// beginConfigFields invokes the advanced editor without blocking Update.
// beginConfigFields 调用高级编辑器且不阻塞 Update。
func (m *Model) beginConfigFields(prefix string) tea.Cmd {
	if m.controller == nil {
		m.operationScreen = m.screen
		m.setScreen(ScreenError)
		m.errorMessage = m.label("当前没有可用的安装控制器", "No installation controller is available")
		return nil
	}
	m.operationID++
	id := m.operationID
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.busy = true
	m.errorMessage = ""
	m.status = m.label("正在打开高级配置", "Opening advanced configuration")
	m.operationScreen = m.screen
	m.retryable = false
	request := ConfigFieldsRequest{Prefix: prefix, Fields: mergeConfigFields(m.plan.ConfigFields, m.configFields.Fields)}
	return func() tea.Msg {
		result, err := m.controller.OpenConfigFields(ctx, request)
		return configFieldsMsg{id: id, result: result, prefix: prefix, err: err}
	}
}

// updateOperationStarted validates the controller stream before observing it.
// updateOperationStarted 在观察事件流前校验 Controller 返回值。
func (m *Model) updateOperationStarted(message operationStartedMsg) (tea.Model, tea.Cmd) {
	if message.id != m.operationID {
		return m, nil
	}
	if message.err != nil || message.events == nil {
		m.finishOperation(false, m.label("操作无法启动", "Operation could not start"))
		return m, nil
	}
	return m, waitOperation(message.id, message.events)
}

// updateOperationEvent applies a progress or terminal event and schedules the next read.
// updateOperationEvent 应用进度或终止事件，并调度下一次读取。
func (m *Model) updateOperationEvent(message operationEventMsg) (tea.Model, tea.Cmd) {
	if message.id != m.operationID {
		return m, nil
	}
	if message.event.Snapshot != nil {
		m.snapshot = *message.event.Snapshot
	}
	if message.event.ProviderTest != nil {
		result := *message.event.ProviderTest
		m.providerTest = &result
	}
	if message.event.Package != nil {
		m.plan.Package = *message.event.Package
		m.plan.Package.StorageModes = append([]StorageMode(nil), message.event.Package.StorageModes...)
		m.plan.Package.CombinedFlavors = append([]string(nil), message.event.Package.CombinedFlavors...)
	}
	if len(message.event.Sources) > 0 {
		selectedID := m.selectedSource.Source.ID
		m.sources = append([]SourceOption(nil), message.event.Sources...)
		for _, source := range m.sources {
			if source.Source.ID == selectedID {
				m.selectedSource = source
				m.plan.Source = source
				break
			}
		}
	}
	if len(message.event.Versions) > 0 {
		m.versions = append([]VersionOption(nil), message.event.Versions...)
	}
	if message.event.Validation != nil {
		m.validation = *message.event.Validation
		m.validation.Errors = append([]string(nil), message.event.Validation.Errors...)
	}
	if message.event.Progress.Message != "" || message.event.Progress.Stage != "" {
		m.progress = message.event.Progress
	}
	if message.event.Message != "" {
		m.status = message.event.Message
	}
	if message.event.Kind == OperationEventProgress {
		return m, waitOperation(message.id, message.events)
	}
	if message.event.Kind == OperationEventFailed {
		m.retryable = message.event.Retryable
		m.finishOperation(false, operationMessage(message.event.Message, m.label("操作失败", "Operation failed")))
		return m, nil
	}
	if message.event.Kind == OperationEventCancelled {
		m.finishOperation(false, m.label("操作已取消", "Operation cancelled"))
		return m, nil
	}
	if message.event.Kind == OperationEventCompleted {
		m.finishOperation(true, operationMessage(message.event.Message, m.label("操作完成", "Operation completed")))
		if m.operationKind == OperationProbeSource && m.editingInstalled {
			m.setScreen(ScreenDownload)
			return m, m.beginOperation(OperationRequest{Kind: OperationStagePackage, Plan: m.plan})
		}
		m.routeCompletedOperation()
		return m, nil
	}
	return m, waitOperation(message.id, message.events)
}

// updateOperationClosed turns a stream that ended without a terminal event into an error.
// updateOperationClosed 将未发终止事件就结束的流转换为错误。
func (m *Model) updateOperationClosed(message operationClosedMsg) (tea.Model, tea.Cmd) {
	if message.id != m.operationID {
		return m, nil
	}
	m.finishOperation(false, m.label("操作异常结束", "Operation ended unexpectedly"))
	return m, nil
}

// updateConfigFields stores editor output and returns to the page that requested it.
// updateConfigFields 保存编辑器输出，并返回发起调用的页面。
func (m *Model) updateConfigFields(message configFieldsMsg) (tea.Model, tea.Cmd) {
	if message.id != m.operationID {
		return m, nil
	}
	m.busy = false
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if message.err != nil {
		m.setScreen(ScreenError)
		m.errorMessage = m.label("高级配置无法打开", "Advanced configuration could not be opened")
		return m, nil
	}
	m.configFields = message.result
	m.configFields.Fields = cloneConfigFields(message.result.Fields)
	m.editingPrefix = message.prefix
	m.editingField = -1
	m.status = operationMessage(message.result.Summary, m.label("配置编辑器已返回", "Configuration editor returned"))
	m.setScreen(ScreenFieldEdit)
	m.editingField = -1
	return m, nil
}

// finishOperation clears cancellation state and records a safe status message.
// finishOperation 清理取消状态，并记录安全的状态消息。
func (m *Model) finishOperation(success bool, message string) {
	m.busy = false
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if success {
		m.errorMessage = ""
		m.status = message
	} else {
		m.status = ""
		m.setScreen(ScreenError)
		m.errorMessage = message
	}
}

// routeCompletedOperation returns the user to the appropriate next page.
// routeCompletedOperation 将用户导航到操作完成后的适当页面。
func (m *Model) routeCompletedOperation() {
	switch m.operationKind {
	case OperationProbeSource, OperationFetchVersions:
		m.setScreen(ScreenVersion)
	case OperationStagePackage:
		if !m.plan.Package.Verified {
			m.setScreen(ScreenError)
			m.errorMessage = m.label("安装包尚未通过完整校验", "The package has not passed complete verification")
			return
		}
		if m.editingInstalled {
			m.setScreen(ScreenProviders)
		} else {
			m.setScreen(ScreenStorage)
		}
	case OperationValidate:
		if m.validation.Valid {
			m.setScreen(ScreenConfirm)
		} else {
			m.setScreen(ScreenConfigCheck)
		}
	case OperationTestProvider:
		m.setScreen(ScreenConfigCheck)
	case OperationInstall:
		m.snapshot.Installed = true
		m.snapshot.Incomplete = false
		m.snapshot.IntegrityIssue = ""
		m.snapshot.ConfigRoot = m.plan.ConfigRoot
		m.snapshot.DataRoot = m.plan.DataRoot
		m.snapshot.ProgramRoot = m.plan.ProgramRoot
		m.snapshot.Storage = m.plan.Storage.Mode
		m.snapshot.ServiceMode = m.plan.ServiceMode
		m.snapshot.AutoStart = m.plan.AutoStart
		m.snapshot.PathEnabled = m.plan.AddToPath
		m.setScreen(ScreenRunning)
	case OperationUninstall:
		m.snapshot.Installed = false
		m.setScreen(ScreenDone)
	case OperationService, OperationPath, OperationRefresh:
		m.setScreen(ScreenHome)
	default:
		m.setScreen(m.operationScreen)
	}
}

// waitOperation reads one stream item without blocking the Bubble Tea update loop.
// waitOperation 读取一个事件流项目，不阻塞 Bubble Tea 更新循环。
func waitOperation(id uint64, events <-chan OperationEvent) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-events
		if !ok {
			return operationClosedMsg{id: id}
		}
		return operationEventMsg{id: id, event: event, events: events}
	}
}

// moveCursor wraps the list cursor while keeping empty pages safe.
// moveCursor 在列表范围内循环移动光标，并安全处理空页面。
func (m *Model) moveCursor(delta int) {
	count := m.itemCount()
	if count <= 0 {
		m.cursor = 0
		return
	}
	m.cursor = (m.cursor + delta) % count
	if m.cursor < 0 {
		m.cursor += count
	}
}

// itemCount returns the number of selectable items on the current page.
// itemCount 返回当前页面可选择项目数量。
func (m *Model) itemCount() int {
	switch m.screen {
	case ScreenLanguage:
		return 2
	case ScreenHome:
		return 12
	case ScreenSource:
		return len(m.sources) + 1
	case ScreenVersion:
		if len(m.versions) == 0 {
			return 1
		}
		return len(m.versions)
	case ScreenStorage:
		return len(m.storage)
	case ScreenStorageCredential:
		return len(storageCredentialKeys()) + 1
	case ScreenProviders:
		return 4
	case ScreenProviderChoice:
		return len(m.providerOptions)
	case ScreenProviderWizard:
		return len(providerFieldKeys(m.providerPurpose)) + 1
	case ScreenFieldEdit:
		return len(m.configFields.Fields) + 1
	case ScreenService:
		return 3
	case ScreenServiceUser:
		return 1
	case ScreenPath:
		return 2
	case ScreenConfigCheck:
		return 5
	case ScreenProviderTest:
		return 4
	case ScreenConfirm:
		return 2
	case ScreenRunning:
		return 5
	case ScreenUninstall:
		return 6
	case ScreenError:
		if m.retryable {
			return 2
		}
		return 1
	default:
		return 0
	}
}

// setScreen resets page-local cursor and input state while recording the back target.
// setScreen 记录返回目标并重置页面局部光标与输入状态。
func (m *Model) setScreen(screen Screen) {
	if m.screen != screen {
		m.previousScreen = m.screen
	}
	m.screen = screen
	m.cursor = 0
	if screen == ScreenSource {
		for index, source := range m.sources {
			if source.Source.ID == m.selectedSource.Source.ID {
				m.cursor = index
				break
			}
		}
	}
	m.input = ""
	m.providerEditingField = -1
	m.storageEditingField = -1
	m.errorMessage = ""
}

// invalidateValidation marks the current plan dirty so only a fresh VMM validation can confirm it.
// invalidateValidation 将当前计划标记为已修改，只有重新通过 VMM 检查才能确认。
func (m *Model) invalidateValidation() {
	m.validation = ValidationSummary{}
	m.providerTest = nil
}

// sourceAt returns a safe source selection for a possibly stale cursor.
// sourceAt 为可能过期的光标返回安全的下载源选择。
func (m *Model) sourceAt(index int) SourceOption {
	if index < 0 || index >= len(m.sources) {
		return SourceOption{}
	}
	return m.sources[index]
}

// pathValue returns the current install plan value for one path field.
// pathValue 返回安装计划中一个路径字段的当前值。
func (m *Model) pathValue(field int) string {
	switch field {
	case 0:
		return m.plan.ProgramRoot
	case 1:
		return m.plan.ConfigRoot
	case 2:
		return m.plan.DataRoot
	default:
		return ""
	}
}

// isTextInput reports whether the current page accepts printable text.
// isTextInput 报告当前页面是否接受可打印文本。
func (m *Model) isTextInput() bool {
	return m.screen == ScreenCustomSource || m.screen == ScreenInstallPath || m.screen == ScreenServiceUser || (m.screen == ScreenVersion && len(m.versions) == 0) || (m.screen == ScreenFieldEdit && m.editingField >= 0) || (m.screen == ScreenProviderWizard && m.providerEditingField >= 0) || (m.screen == ScreenStorageCredential && m.storageEditingField >= 0)
}

// label selects one of two built-in labels when no catalog key exists.
// label 在没有目录键时选择中英文内置标签。
func (m *Model) label(chinese string, english string) string {
	if m.language == LanguageEnglish {
		return english
	}
	return chinese
}

// serviceUserVisible reports whether the platform should expose a service-account field.
// serviceUserVisible 判断当前平台是否应展示服务账户字段。
func (m *Model) serviceUserVisible() bool {
	return m.platformOS != "windows"
}

// text resolves a real i18n catalog key and never displays raw formatting errors.
// text 解析真实 i18n 目录键，且不会展示原始格式化错误。
func (m *Model) text(key i18n.MessageKey, values map[string]string) string {
	return m.localizer.Text(m.language, key, values)
}

// operationMessage prefers a safe controller message and otherwise uses a fallback.
// operationMessage 优先使用安全的 Controller 消息，否则使用回退文本。
func operationMessage(message string, fallback string) string {
	if strings.TrimSpace(message) == "" {
		return fallback
	}
	return message
}

// removeLastRune removes one complete UTF-8 rune for Chinese input correctness.
// removeLastRune 为中文输入正确移除一个完整 UTF-8 字符。
func removeLastRune(value string) string {
	if value == "" {
		return value
	}
	_, size := utf8.DecodeLastRuneInString(value)
	if size <= 0 || size > len(value) {
		return ""
	}
	return value[:len(value)-size]
}

// validServiceUser enforces the service adapter grammar [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}.
// validServiceUser 强制执行服务适配器语法 [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}。
func validServiceUser(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if index == 0 {
			if !((char >= 'A' && char <= 'Z') ||
				(char >= 'a' && char <= 'z') ||
				(char >= '0' && char <= '9') || char == '_') {
				return false
			}
			continue
		}
		if !((char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '.' || char == '-') {
			return false
		}
	}
	return true
}

// keyMatches compares Bubble Tea's stable keystroke spelling without relying on removed v1 helpers.
// keyMatches 使用 Bubble Tea 稳定的按键字符串比较，避免依赖已移除的 v1 辅助方法。
func keyMatches(message tea.KeyPressMsg, names ...string) bool {
	value := message.String()
	for _, name := range names {
		if value == name {
			return true
		}
	}
	return false
}

// configPrefix maps provider shortcut items to authoritative schema prefixes.
// configPrefix 将供应商快捷项目映射到权威 schema 前缀。
func configPrefix(index int) string {
	switch index {
	case 0:
		return "llm"
	case 1:
		return "embedding"
	case 2:
		return "rerank"
	default:
		return ""
	}
}

// providerPurposeAt maps the three shortcut entries to their exact provider purposes.
// providerPurposeAt 将三个快捷入口映射到精确的供应商用途。
func providerPurposeAt(index int) ProviderPurpose {
	switch index {
	case 0:
		return ProviderPurposeLLM
	case 1:
		return ProviderPurposeEmbedding
	case 2:
		return ProviderPurposeRerank
	default:
		return ""
	}
}
