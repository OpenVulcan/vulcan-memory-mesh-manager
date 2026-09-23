// Package tui contains the event-driven terminal interface for VMMM installation and management.
// tui 包负责 VMMM 安装与管理的事件驱动终端界面。
//
// The package owns presentation state only; filesystem, network, process, service, and PATH work
// is delegated through Controller so the same flow can be exercised by deterministic tests.
// 本包只拥有展示状态；文件系统、网络、进程、服务和 PATH 操作都通过 Controller 委托，以便使用确定性测试复用流程。
package tui

import (
	"context"
	"time"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/i18n"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/providerwizard"
)

// Screen identifies the current user-facing page in the installer state machine.
// Screen 标识安装器状态机当前展示的用户界面。
type Screen uint8

const (
	// ScreenLanguage asks for the preferred display language during first install.
	// ScreenLanguage 在首次安装时询问显示语言。
	ScreenLanguage Screen = iota

	// ScreenHome is the installed-instance management page.
	// ScreenHome 是已安装实例的管理首页。
	ScreenHome

	// ScreenSource selects a trusted or custom VMM download source.
	// ScreenSource 选择受信或自定义 VMM 下载源。
	ScreenSource

	// ScreenCustomSource accepts a user-supplied HTTPS proxy prefix.
	// ScreenCustomSource 接受用户填写的 HTTPS 代理前缀。
	ScreenCustomSource

	// ScreenVersion selects a VMM release version.
	// ScreenVersion 选择 VMM 发行版本。
	ScreenVersion

	// ScreenInstallPath collects stable program, configuration, and data roots.
	// ScreenInstallPath 收集稳定的程序、配置和数据根目录。
	ScreenInstallPath

	// ScreenDownload displays manifest, package, and archive verification progress.
	// ScreenDownload 展示发行清单、安装包和归档校验进度。
	ScreenDownload

	// ScreenStorage selects one of the five supported storage modes.
	// ScreenStorage 选择五种受支持的存储模式之一。
	ScreenStorage
	// ScreenStorageCredential collects a PostgreSQL or ParadeDB environment reference and secret.
	// ScreenStorageCredential 收集 PostgreSQL 或 ParadeDB 的环境变量引用和秘密值。
	ScreenStorageCredential

	// ScreenProviders opens the provider shortcut configuration entry point.
	// ScreenProviders 打开供应商快捷配置入口。
	ScreenProviders
	// ScreenProviderChoice selects an exact provider from the verified catalog.
	// ScreenProviderChoice 从已核实目录中选择精确供应商。
	ScreenProviderChoice
	// ScreenProviderWizard edits typed provider values and protected credential references.
	// ScreenProviderWizard 编辑强类型供应商值和受保护的凭据引用。
	ScreenProviderWizard
	// ScreenFieldEdit edits schema-backed provider, storage, and advanced fields.
	// ScreenFieldEdit 编辑由 schema 支持的供应商、存储和高级字段。
	ScreenFieldEdit
	// ScreenService selects foreground, service, and automatic-start behavior.
	// ScreenService 选择前台、服务和自动启动行为。
	ScreenService
	// ScreenServiceUser confirms the local account used by Linux or macOS services.
	// ScreenServiceUser 确认 Linux 或 macOS 服务使用的本机账户。
	ScreenServiceUser
	// ScreenPath selects whether the manager command is added to PATH.
	// ScreenPath 选择是否将管理器命令加入 PATH。
	ScreenPath
	// ScreenConfigCheck displays the authoritative VMM validation summary.
	// ScreenConfigCheck 展示 VMM 权威配置校验摘要。
	ScreenConfigCheck
	// ScreenConfirm asks for final execution confirmation.
	// ScreenConfirm 询问最终执行确认。
	ScreenConfirm
	// ScreenRunning displays the running or service-managed instance state.
	// ScreenRunning 展示前台或服务管理实例的运行状态。
	ScreenRunning
	// ScreenUninstall controls reversible uninstall choices.
	// ScreenUninstall 控制可保留数据的卸载选项。
	ScreenUninstall
	// ScreenError displays a recoverable operation error.
	// ScreenError 展示可恢复的操作错误。
	ScreenError
	// ScreenDone displays the final result of an operation.
	// ScreenDone 展示操作的最终结果。
	ScreenDone
)

// ProviderPurpose aliases the verified VMM provider surface used by the typed wizard.
// ProviderPurpose 对应经过核实的 VMM 供应商配置用途，供强类型向导使用。
type ProviderPurpose = providerwizard.Purpose

const (
	// ProviderPurposeLLM selects the text-generation route wizard.
	// ProviderPurposeLLM 选择文本生成路由向导。
	ProviderPurposeLLM = providerwizard.PurposeLLM
	// ProviderPurposeEmbedding selects the embedding provider wizard.
	// ProviderPurposeEmbedding 选择 embedding 供应商向导。
	ProviderPurposeEmbedding = providerwizard.PurposeEmbedding
	// ProviderPurposeRerank selects the rerank route wizard.
	// ProviderPurposeRerank 选择 rerank 路由向导。
	ProviderPurposeRerank = providerwizard.PurposeRerank
)

// ProviderMetadata is the verified localized catalog entry shown before provider input.
// ProviderMetadata 是选择供应商前展示的、带双语标签的已核实目录项。
type ProviderMetadata = providerwizard.ProviderMetadata

// Language is the locale selected in the TUI.
// Language 是 TUI 中选择的语言区域。
type Language = i18n.Language

const (
	// LanguageEnglish selects the English catalog.
	// LanguageEnglish 选择英文目录。
	LanguageEnglish = i18n.English
	// LanguageChinese selects the Simplified Chinese catalog.
	// LanguageChinese 选择简体中文目录。
	LanguageChinese = i18n.SimplifiedChinese
)

// StorageMode identifies the five VMM storage choices exposed by the installer.
// StorageMode 标识安装器展示的五种 VMM 存储选择。
type StorageMode string

const (
	// StorageNative uses VMM's native SQLite and LanceDB adapters.
	// StorageNative 使用 VMM 原生 SQLite 与 LanceDB 适配器。
	StorageNative StorageMode = "native"
	// StorageSplit uses the packaged split SQLite and LanceDB libraries.
	// StorageSplit 使用安装包内的分离式 SQLite 与 LanceDB 库。
	StorageSplit StorageMode = "split"
	// StorageController uses the VLDB controller endpoint.
	// StorageController 使用 VLDB 控制器端点。
	StorageController StorageMode = "controller"
	// StoragePostgreSQL uses the standard PostgreSQL combined store.
	// StoragePostgreSQL 使用标准 PostgreSQL 组合存储。
	StoragePostgreSQL StorageMode = "postgres"
	// StorageParadeDB uses PostgreSQL with ParadeDB search extensions.
	// StorageParadeDB 使用带 ParadeDB 搜索扩展的 PostgreSQL。
	StorageParadeDB StorageMode = "paradedb"
)

// ServiceMode describes whether VMM is controlled as a service or by a foreground command.
// ServiceMode 描述 VMM 采用服务控制还是前台命令控制。
type ServiceMode string

const (
	// ServiceModeForeground keeps VMM under an explicit foreground command.
	// ServiceModeForeground 让 VMM 由显式前台命令控制。
	ServiceModeForeground ServiceMode = "foreground"
	// ServiceModeService registers VMM with the platform service manager.
	// ServiceModeService 将 VMM 注册到平台服务管理器。
	ServiceModeService ServiceMode = "service"
)

// ServiceAction identifies a lifecycle action selected from the installed page.
// ServiceAction 标识已安装页面选择的生命周期动作。
type ServiceAction string

const (
	// ServiceActionInstall registers the service without changing its running state.
	// ServiceActionInstall 注册服务且不改变当前运行状态。
	ServiceActionInstall ServiceAction = "install"
	// ServiceActionUninstall removes the service registration.
	// ServiceActionUninstall 移除服务注册。
	ServiceActionUninstall ServiceAction = "uninstall"
	// ServiceActionStart starts the registered service.
	// ServiceActionStart 启动已注册服务。
	ServiceActionStart ServiceAction = "start"
	// ServiceActionStop stops the registered service.
	// ServiceActionStop 停止已注册服务。
	ServiceActionStop ServiceAction = "stop"
	// ServiceActionRestart restarts the registered service.
	// ServiceActionRestart 重启已注册服务。
	ServiceActionRestart ServiceAction = "restart"
	// ServiceActionEnable enables automatic service startup.
	// ServiceActionEnable 开启服务自动启动。
	ServiceActionEnable ServiceAction = "enable"
	// ServiceActionDisable disables automatic service startup.
	// ServiceActionDisable 关闭服务自动启动。
	ServiceActionDisable ServiceAction = "disable"
	// ServiceActionStatus refreshes the service status.
	// ServiceActionStatus 刷新服务状态。
	ServiceActionStatus ServiceAction = "status"
)

// OperationKind identifies work executed by the injected controller.
// OperationKind 标识注入 Controller 执行的工作类型。
type OperationKind string

const (
	// OperationProbeSource checks the selected source against trusted VMM assets.
	// OperationProbeSource 使用受信 VMM 资产检测所选下载源。
	OperationProbeSource OperationKind = "probe-source"
	// OperationFetchVersions loads release versions for the selected source.
	// OperationFetchVersions 加载所选源的发行版本。
	OperationFetchVersions OperationKind = "fetch-versions"
	// OperationDownloadInstall downloads, verifies, and stages the VMM package.
	// OperationDownloadInstall is retained as a compatibility alias for staging.
	// OperationDownloadInstall 保留为暂存操作的兼容别名。
	OperationDownloadInstall OperationKind = "stage-package"
	// OperationStagePackage downloads, verifies, and stages the VMM package before configuration.
	// OperationStagePackage 在配置向导前下载、校验并暂存 VMM 安装包。
	OperationStagePackage OperationKind = "stage-package"
	// OperationInstall applies the configured plan using the already verified staged package.
	// OperationInstall 使用已校验的暂存包应用配置计划。
	OperationInstall OperationKind = "install"
	// OperationValidate validates the saved configuration with the VMM CLI.
	// OperationValidate 使用 VMM CLI 校验已保存配置。
	OperationValidate OperationKind = "validate"
	// OperationService applies one service lifecycle action.
	// OperationService 执行一项服务生命周期操作。
	OperationService OperationKind = "service"
	// OperationPath applies the manager PATH choice.
	// OperationPath 应用管理器 PATH 选择。
	OperationPath OperationKind = "path"
	// OperationUninstall removes the program and optional service while respecting retention choices.
	// OperationUninstall 按保留选择移除程序和可选服务。
	OperationUninstall OperationKind = "uninstall"
	// OperationRefresh refreshes installed status after an action.
	// OperationRefresh 在操作后刷新安装状态。
	OperationRefresh OperationKind = "refresh"
)

// OperationEventKind identifies one event emitted by a controller operation stream.
// OperationEventKind 标识 Controller 操作流发出的事件类型。
type OperationEventKind string

const (
	// OperationEventProgress updates the progress screen.
	// OperationEventProgress 更新进度页面。
	OperationEventProgress OperationEventKind = "progress"
	// OperationEventCompleted marks successful operation completion.
	// OperationEventCompleted 标记操作成功完成。
	OperationEventCompleted OperationEventKind = "completed"
	// OperationEventFailed reports a sanitized, user-facing failure.
	// OperationEventFailed 报告已脱敏的用户可见失败信息。
	OperationEventFailed OperationEventKind = "failed"
	// OperationEventCancelled confirms cancellation was observed by the controller.
	// OperationEventCancelled 确认 Controller 已观察到取消。
	OperationEventCancelled OperationEventKind = "cancelled"
)

// Progress is a bounded progress snapshot rendered without color or terminal escape codes.
// Progress 是不使用颜色或终端转义码渲染的有界进度快照。
type Progress struct {
	// Stage is a short stable stage identifier.
	// Stage 是稳定的短阶段标识。
	Stage string
	// Message is already localized or safe for direct display.
	// Message 已完成本地化或可直接安全展示。
	Message string
	// Current is the completed unit count.
	// Current 是已完成的单位数量。
	Current int64
	// Total is the expected unit count; zero means indeterminate.
	// Total 是预期单位数量，零表示无法确定总量。
	Total int64
}

// VersionOption describes one release choice shown to the user.
// VersionOption 描述展示给用户的一个发行版本选择。
type VersionOption struct {
	// Tag is the immutable release tag.
	// Tag 是不可变的发行标签。
	Tag string
	// Commit is the release source commit when known.
	// Commit 是已知时的发行源提交。
	Commit string
	// PublishedAt is the source publication time.
	// PublishedAt 是源站发布时间。
	PublishedAt time.Time
	// Available reports whether the source probe made this version usable.
	// Available 表示源检测是否确认该版本可用。
	Available bool
}

// SourceOption enriches an exact download.Source with probe state for the TUI.
// SourceOption 为精确 download.Source 增加 TUI 所需的检测状态。
type SourceOption struct {
	// Source contains the allowlisted URL construction policy.
	// Source 包含白名单 URL 构造策略。
	Source download.Source
	// DisplayName is the localized or user-supplied display label.
	// DisplayName 是本地化或用户填写的展示名称。
	DisplayName string
	// Available indicates that the last source probe passed.
	// Available 表示最近一次源检测通过。
	Available bool
	// ProbeMessage contains a sanitized probe result.
	// ProbeMessage 包含已脱敏的检测结果。
	ProbeMessage string
	// CheckedAt is the time of the last probe.
	// CheckedAt 是最近一次检测时间。
	CheckedAt time.Time
}

// StorageOption presents a storage mode and its retrieval algorithm explanation.
// StorageOption 展示存储模式及其记忆检索算法说明。
type StorageOption struct {
	// Mode is the stable mode value persisted in the install plan.
	// Mode 是安装计划中持久化的稳定模式值。
	Mode StorageMode
	// Label is a short user-facing name.
	// Label 是简短的用户可见名称。
	Label string
	// Algorithm describes lexical, vector, and hybrid retrieval behavior.
	// Algorithm 描述词法、向量和混合检索行为。
	Algorithm string
	// PathHint describes which path or endpoint must be configured.
	// PathHint 描述必须配置的路径或端点。
	PathHint string
	// LabelChinese is the Simplified Chinese display label.
	// LabelChinese 是简体中文展示标签。
	LabelChinese string
	// LabelEnglish is the English display label.
	// LabelEnglish 是英文展示标签。
	LabelEnglish string
	// AlgorithmChinese is the Simplified Chinese retrieval explanation.
	// AlgorithmChinese 是简体中文检索说明。
	AlgorithmChinese string
	// AlgorithmEnglish is the English retrieval explanation.
	// AlgorithmEnglish 是英文检索说明。
	AlgorithmEnglish string
	// PathHintChinese is the Simplified Chinese path or endpoint hint.
	// PathHintChinese 是简体中文路径或端点提示。
	PathHintChinese string
	// PathHintEnglish is the English path or endpoint hint.
	// PathHintEnglish 是英文路径或端点提示。
	PathHintEnglish string
}

// StorageSettings carries mode-specific paths and external database connection settings.
// StorageSettings 携带模式专用路径和外部数据库连接设置。
type StorageSettings struct {
	// LocalDataRoot is the split/controller local data root when supported by the package schema.
	// LocalDataRoot 是包 schema 支持时分离式或控制器的本地数据根目录。
	LocalDataRoot string
	// NativeSQLitePath is the native SQLite file path.
	// NativeSQLitePath 是原生 SQLite 文件路径。
	NativeSQLitePath string
	// NativeLanceDBPath is the native LanceDB directory path.
	// NativeLanceDBPath 是原生 LanceDB 目录路径。
	NativeLanceDBPath string
	// ControllerEndpoint is the VLDB controller endpoint.
	// ControllerEndpoint 是 VLDB 控制器端点。
	ControllerEndpoint string
	// PostgreSQLDSNVariable is the environment variable referenced by YAML.
	// PostgreSQLDSNVariable 是 YAML 引用的环境变量名称。
	PostgreSQLDSNVariable string
	// PostgreSQLDSNValue is the raw connection string written only to protected .env storage.
	// PostgreSQLDSNValue 是只写入受保护 .env 的原始连接字符串。
	PostgreSQLDSNValue string
	// PostgreSQLCredentialPath is the explicit .env path for the connection string.
	// PostgreSQLCredentialPath 是连接字符串使用的明确 .env 路径。
	PostgreSQLCredentialPath string
	// PostgreSQLCredentialConfigured reports that an existing .env value may be retained.
	// PostgreSQLCredentialConfigured 表示可以保留已有 .env 值。
	PostgreSQLCredentialConfigured bool
	// PostgreSQLFlavor identifies standard PostgreSQL or ParadeDB.
	// PostgreSQLFlavor 标识标准 PostgreSQL 或 ParadeDB。
	PostgreSQLFlavor string
}

// StorageCredentialDraft contains the write-only combined-database credential form.
// StorageCredentialDraft 保存组合数据库凭据表单，其中秘密值只写不可读。
type StorageCredentialDraft struct {
	// Variable is the portable environment variable name referenced by VMM YAML.
	// Variable 是 VMM YAML 引用的可移植环境变量名称。
	Variable string
	// OriginalVariable is the reference loaded with the existing credential.
	// OriginalVariable 是随现有凭据加载的原始引用名称。
	OriginalVariable string
	// OriginalPath is the credential file path loaded with the existing value.
	// OriginalPath 是随现有值加载的凭据文件路径。
	OriginalPath string
	// Value is the raw DSN held only until protected controller persistence.
	// Value 是只保留到控制器受保护持久化之前的原始 DSN。
	Value string
	// Path is the explicit .env file path.
	// Path 是明确的 .env 文件路径。
	Path string
	// ExistingConfigured allows an empty new value to retain an existing secret.
	// ExistingConfigured 允许新值为空时保留现有秘密。
	ExistingConfigured bool
}

// StagedPackage records verified package capabilities before configuration is edited.
// StagedPackage 记录配置编辑前已校验安装包的能力。
type StagedPackage struct {
	// Verified reports that signature, size, digest, archive, and receipt checks passed.
	// Verified 表示签名、大小、摘要、归档和收据校验均已通过。
	Verified bool
	// Version is the verified VMM tag.
	// Version 是已校验的 VMM 标签。
	Version string
	// Platform is the exact release platform identifier.
	// Platform 是精确的发行平台标识。
	Platform string
	// ArtifactRoot is the immutable staging root owned by the controller.
	// ArtifactRoot 是 Controller 拥有的不可变暂存根目录。
	ArtifactRoot string
	// StorageModes lists capabilities advertised by the package receipt.
	// StorageModes 列出安装包收据声明的能力。
	StorageModes []StorageMode
	// CombinedFlavors lists external combined database flavors when advertised.
	// CombinedFlavors 列出收据声明的外部组合数据库类型。
	CombinedFlavors []string
}

// InstallPlan contains all values collected before the final confirmation page.
// InstallPlan 包含最终确认前收集的全部安装值。
type InstallPlan struct {
	// Rollback permits a deliberately selected older signed runtime release.
	// Rollback 允许使用用户明确选择的旧版签名运行时发行包。
	Rollback bool
	// Source is the selected VMM download source.
	// Source 是选择的 VMM 下载源。
	Source SourceOption
	// Version is the selected immutable release.
	// Version 是选择的不可变发行版本。
	Version VersionOption
	// ProgramRoot is the stable executable and library root.
	// ProgramRoot 是稳定的可执行文件和库根目录。
	ProgramRoot string
	// ConfigRoot is the VMM configuration root.
	// ConfigRoot 是 VMM 配置根目录。
	ConfigRoot string
	// DataRoot is the user database and runtime data root.
	// DataRoot 是用户数据库和运行时数据根目录。
	DataRoot string
	// Storage is the selected storage mode.
	// Storage 是选择的存储模式。
	Storage StorageOption
	// StorageSettings contains mode-specific paths and external database settings.
	// StorageSettings 包含模式专用路径和外部数据库设置。
	StorageSettings StorageSettings
	// ConfigFields contains edited schema-backed provider and advanced values.
	// ConfigFields 包含编辑后的 schema 供应商和高级字段值。
	ConfigFields []ConfigField
	// Providers contains typed provider routes and protected credential updates.
	// Providers 包含强类型供应商路由和受保护的凭据更新。
	Providers ProviderPlan
	// Package is the verified staged package used by final installation.
	// Package 是最终安装使用的已校验暂存包。
	Package StagedPackage
	// ServiceMode selects foreground or service registration.
	// ServiceMode 选择前台或服务注册。
	ServiceMode ServiceMode
	// ServiceUser is the explicitly confirmed local account for Linux or macOS services.
	// ServiceUser 是 Linux 或 macOS 服务明确确认使用的本机账户。
	ServiceUser string
	// AutoStart controls service automatic startup.
	// AutoStart 控制服务自动启动。
	AutoStart bool
	// AddToPath controls manager PATH integration.
	// AddToPath 控制管理器 PATH 集成。
	AddToPath bool
}

// InstallationSnapshot is a non-sensitive summary used by the installed page.
// InstallationSnapshot 是已安装页面使用的非敏感摘要。
type InstallationSnapshot struct {
	// Installed identifies whether a valid manager installation record exists.
	// Installed 表示是否存在有效的管理器安装记录。
	Installed bool
	// ManagerVersion is the installed manager release.
	// ManagerVersion 是已安装的管理器版本。
	ManagerVersion string
	// VMMVersion is the installed VMM release.
	// VMMVersion 是已安装的 VMM 版本。
	VMMVersion string
	// SourceID is the persisted source identity.
	// SourceID 是持久化的下载源标识。
	SourceID string
	// SourcePrefix restores the selected custom HTTPS proxy after reopening the manager.
	// SourcePrefix 在重新打开管理器后恢复已选的自定义 HTTPS 代理。
	SourcePrefix string
	// ProgramRoot is the installed program root.
	// ProgramRoot 是已安装程序根目录。
	ProgramRoot string
	// ConfigRoot is the active VMM configuration root.
	// ConfigRoot 是当前 VMM 配置根目录。
	ConfigRoot string
	// DataRoot is the active VMM data root.
	// DataRoot 是当前 VMM 数据根目录。
	DataRoot string
	// Storage is the configured storage mode.
	// Storage 是当前配置的存储模式。
	Storage StorageMode
	// ServiceMode is the configured execution mode.
	// ServiceMode 是当前配置的执行模式。
	ServiceMode ServiceMode
	// ServiceState is a sanitized platform status string.
	// ServiceState 是已脱敏的平台状态字符串。
	ServiceState string
	// AutoStart reports the persisted service startup policy.
	// AutoStart 表示持久化的服务启动策略。
	AutoStart bool
	// PathEnabled reports manager PATH ownership.
	// PathEnabled 表示管理器是否拥有 PATH 集成。
	PathEnabled bool
	// Running reports whether VMM is currently reachable.
	// Running 表示当前 VMM 是否可达。
	Running bool
	// LastValidation is the latest sanitized validation summary.
	// LastValidation 是最近一次已脱敏的校验摘要。
	LastValidation string
}

// ValidationSummary contains authoritative validation information without secret values.
// ValidationSummary 包含不带密钥值的权威配置校验信息。
type ValidationSummary struct {
	// Valid reports whether VMM accepted the complete configuration.
	// Valid 表示 VMM 是否接受完整配置。
	Valid bool
	// Summary is a sanitized human-readable result.
	// Summary 是已脱敏的人类可读结果。
	Summary string
	// Errors contains sanitized field-level diagnostics.
	// Errors 包含已脱敏的字段级诊断。
	Errors []string
}

// ConfigField describes one optional advanced configuration field.
// ConfigField 描述一个可选的高级配置字段。
type ConfigField struct {
	// RuleAsset marks a complete prompt or rule file beneath the VMM override root.
	// RuleAsset 表示 VMM 覆盖根下的完整提示词或规则文件。
	RuleAsset bool
	// Path is the authoritative schema path.
	// Path 是权威 schema 路径。
	Path string
	// Type is the schema type name.
	// Type 是 schema 类型名称。
	Type string
	// Value is a display-safe value; secrets must already be masked.
	// Value 是可安全展示的值，密钥必须预先脱敏。
	Value string
	// Sensitive reports whether the field is secret-bearing.
	// Sensitive 表示字段是否包含敏感信息。
	Sensitive bool
	// Editable reports whether the authoritative schema permits changes.
	// Editable 表示权威 schema 是否允许修改。
	Editable bool
	// Changed records an explicit user edit so untouched schema defaults are never written.
	// Changed 记录用户明确修改，避免写入未触碰的 schema 默认值。
	Changed bool
	// Enum contains authoritative allowed values when the schema declares an enum.
	// Enum 包含 schema 声明的权威枚举值。
	Enum []string
}

// ConfigFieldsRequest identifies the advanced configuration area to open.
// ConfigFieldsRequest 标识要打开的高级配置区域。
type ConfigFieldsRequest struct {
	// Prefix is the schema prefix, such as "llm" or "memory_pipeline".
	// Prefix 是 schema 前缀，例如 "llm" 或 "memory_pipeline"。
	Prefix string
	// Fields is the current display-safe snapshot supplied by the model.
	// Fields 是模型提供的当前可安全展示字段快照。
	Fields []ConfigField
}

// ConfigFieldsResult is the result returned by an advanced configuration editor.
// ConfigFieldsResult 是高级配置编辑器返回的结果。
type ConfigFieldsResult struct {
	// Fields contains the edited display-safe fields.
	// Fields 包含编辑后的可安全展示字段。
	Fields []ConfigField
	// Changed indicates that at least one value changed.
	// Changed 表示至少有一个值发生变化。
	Changed bool
	// Summary is a sanitized editor result.
	// Summary 是已脱敏的编辑结果。
	Summary string
}

// ProviderDraft contains the typed values collected for one provider purpose.
// ProviderDraft 保存一个供应商用途向导收集的强类型值。
type ProviderDraft struct {
	// Purpose identifies whether this draft configures LLM, embedding, or rerank.
	// Purpose 标识当前草稿配置 LLM、embedding 还是 rerank。
	Purpose ProviderPurpose
	// Name is an optional route name used by multi-route LLM and rerank settings.
	// Name 是多路 LLM 和 rerank 设置使用的可选路由名称。
	Name string
	// Provider is an exact provider ID from the verified catalog.
	// Provider 是已核实目录中的精确供应商 ID。
	Provider string
	// Endpoint is the explicit provider endpoint or an authoritative default.
	// Endpoint 是明确的供应商端点或权威默认端点。
	Endpoint string
	// Model is the explicit model identifier selected by the user.
	// Model 是用户明确选择的模型标识符。
	Model string
	// Dimension is the explicit positive embedding dimension; zero means unset.
	// Dimension 是明确的正数 embedding 维度，零表示尚未填写。
	Dimension int
	// Priority is the non-negative rerank route priority.
	// Priority 是非负的 rerank 路由优先级。
	Priority int
	// Enabled controls whether rerank executes after recall.
	// Enabled 控制 rerank 是否在召回后执行。
	Enabled bool
	// APIKeyEnvironmentNames contains names only; secret values are never rendered.
	// APIKeyEnvironmentNames 只保存名称，秘密值绝不参与界面渲染。
	APIKeyEnvironmentNames []string
	// APIKeyValue is a new secret entered for the first key name and is write-only in the TUI.
	// APIKeyValue 是为第一个密钥名称输入的新秘密值，在 TUI 中只写不可读。
	APIKeyValue string
	// CredentialConfigured reports that an existing .env value can be retained.
	// CredentialConfigured 表示现有 .env 值可以保留。
	CredentialConfigured bool
	// CredentialPath is the explicit .env path selected for this provider plan.
	// CredentialPath 是本次供应商计划选择的明确 .env 路径。
	CredentialPath string
}

// ProviderRoute is the value-free provider route written into the VMM configuration plan.
// ProviderRoute 是写入 VMM 配置计划的不含秘密值的供应商路由。
type ProviderRoute struct {
	// Name is the optional route name.
	// Name 是可选的路由名称。
	Name string
	// Provider is the exact catalog provider ID.
	// Provider 是目录中的精确供应商 ID。
	Provider string
	// Endpoint is the normalized endpoint selected by the controller or user.
	// Endpoint 是控制器或用户选择的规范化端点。
	Endpoint string
	// Model is the selected model identifier.
	// Model 是选择的模型标识符。
	Model string
	// Dimension is used by embedding routes and remains zero for other purposes.
	// Dimension 用于 embedding 路由，其他用途保持为零。
	Dimension int
	// Priority is used by rerank routes and remains zero for other purposes.
	// Priority 用于 rerank 路由，其他用途保持为零。
	Priority int
	// APIKeyEnvironmentNames references secrets without carrying their values.
	// APIKeyEnvironmentNames 引用秘密但不携带秘密值。
	APIKeyEnvironmentNames []string
}

// CredentialUpdate describes one secure .env write without exposing the value in summaries.
// CredentialUpdate 描述一次安全的 .env 写入，摘要中不会暴露值。
type CredentialUpdate struct {
	// EnvironmentName is the exact portable environment variable name.
	// EnvironmentName 是精确的可移植环境变量名称。
	EnvironmentName string
	// Value is passed only to the controller for protected .env persistence.
	// Value 只传给控制器用于受保护的 .env 持久化。
	Value string
	// KeepExisting requests retaining an existing value when Value is empty.
	// KeepExisting 在 Value 为空时请求保留现有值。
	KeepExisting bool
}

// ProviderPlan contains all typed provider routes and protected credential updates.
// ProviderPlan 包含全部强类型供应商路由和受保护的凭据更新。
type ProviderPlan struct {
	// RerankConfigured distinguishes an explicit disabled choice from an untouched reranker.
	// RerankConfigured 区分明确禁用重排与尚未修改重排配置。
	RerankConfigured bool
	// LLMRoutes replaces the explicit LLM route list when the wizard saves LLM.
	// LLMRoutes 在 LLM 向导保存时替换明确的 LLM 路由列表。
	LLMRoutes []ProviderRoute
	// Embedding is the selected single embedding route, when configured.
	// Embedding 是选定的单一 embedding 路由（如果已配置）。
	Embedding *ProviderRoute
	// RerankEnabled controls whether rerank runs after vector recall.
	// RerankEnabled 控制 rerank 是否在向量召回后运行。
	RerankEnabled bool
	// RerankRoutes contains the ordered rerank routes.
	// RerankRoutes 保存有序的 rerank 路由。
	RerankRoutes []ProviderRoute
	// CredentialPath is the .env file used for credential references.
	// CredentialPath 是凭据引用使用的 .env 文件。
	CredentialPath string
	// CredentialUpdates contains secret values only for the final protected write.
	// CredentialUpdates 只在最终受保护写入时携带秘密值。
	CredentialUpdates []CredentialUpdate
}

// ProviderWizardRequest opens the typed provider flow for one VMM purpose.
// ProviderWizardRequest 为一个 VMM 用途打开强类型供应商流程。
type ProviderWizardRequest struct {
	// Purpose identifies the provider surface to load.
	// Purpose 标识要加载的供应商配置用途。
	Purpose ProviderPurpose
	// Draft carries the current value-free draft so the controller can provide defaults.
	// Draft 携带当前不含秘密值的草稿，供控制器返回默认值。
	Draft ProviderDraft
}

// ProviderWizardResult returns the authoritative provider catalog and current draft.
// ProviderWizardResult 返回权威供应商目录和当前草稿。
type ProviderWizardResult struct {
	// Purpose echoes the requested purpose for stale-result protection.
	// Purpose 回显请求用途，用于防止过期结果覆盖当前页面。
	Purpose ProviderPurpose
	// Providers contains exact IDs, localized labels, and verified requirements.
	// Providers 包含精确 ID、双语标签和已核实要求。
	Providers []ProviderMetadata
	// Draft contains current non-secret values and whether a credential already exists.
	// Draft 包含当前非秘密值以及是否已有凭据。
	Draft ProviderDraft
	// Summary is a sanitized result description.
	// Summary 是已脱敏的结果描述。
	Summary string
}

// ProviderWizardController supplies the real typed provider catalog and .env integration.
// ProviderWizardController 提供真实的强类型供应商目录和 .env 集成。
type ProviderWizardController interface {
	// OpenProviderWizard loads provider metadata and a value-free draft without writing files.
	// OpenProviderWizard 加载供应商元数据和不含秘密值的草稿，不写入文件。
	OpenProviderWizard(context.Context, ProviderWizardRequest) (ProviderWizardResult, error)
}

// UninstallOptions controls service, configuration, and data retention choices.
// UninstallOptions 控制服务、配置和数据保留选择。
type UninstallOptions struct {
	// RemoveService requests service deregistration.
	// RemoveService 请求注销服务。
	RemoveService bool
	// KeepConfig keeps the VMM configuration root.
	// KeepConfig 保留 VMM 配置根目录。
	KeepConfig bool
	// KeepData keeps the VMM database and data root.
	// KeepData 保留 VMM 数据库和数据根目录。
	KeepData bool
	// RemovePath removes only the manager-owned PATH entry.
	// RemovePath 只移除管理器拥有的 PATH 条目。
	RemovePath bool
}

// OperationRequest carries one user-approved controller action.
// OperationRequest 携带一个经用户确认的 Controller 操作。
type OperationRequest struct {
	// Kind selects the controller operation.
	// Kind 选择 Controller 操作。
	Kind OperationKind
	// Source carries source detection or download context.
	// Source 携带源检测或下载上下文。
	Source SourceOption
	// Plan carries the complete install plan when installation is requested.
	// Plan 在请求安装时携带完整安装计划。
	Plan InstallPlan
	// ServiceAction carries the requested service lifecycle action.
	// ServiceAction 携带请求的服务生命周期动作。
	ServiceAction ServiceAction
	// TargetMode tells the controller whether to use service or foreground process control.
	// TargetMode 告诉 Controller 使用服务控制还是前台进程控制。
	TargetMode ServiceMode
	// AddToPath carries the requested PATH state.
	// AddToPath 携带请求的 PATH 状态。
	AddToPath bool
	// Uninstall carries uninstall retention choices.
	// Uninstall 携带卸载保留选项。
	Uninstall UninstallOptions
}

// OperationEvent is emitted by Controller.Start and is safe for direct TUI rendering.
// OperationEvent 由 Controller.Start 发出，可直接安全渲染到 TUI。
type OperationEvent struct {
	// Kind identifies progress, completion, failure, or cancellation.
	// Kind 标识进度、完成、失败或取消。
	Kind OperationEventKind
	// Progress carries the latest bounded progress snapshot.
	// Progress 携带最新的有界进度快照。
	Progress Progress
	// Snapshot carries refreshed installation status when available.
	// Snapshot 在可用时携带刷新后的安装状态。
	Snapshot *InstallationSnapshot
	// Package carries verified staging metadata after package verification.
	// Package 在安装包校验后携带已验证的暂存元数据。
	Package *StagedPackage
	// Sources carries source probe or source list results.
	// Sources 携带源检测或源列表结果。
	Sources []SourceOption
	// Versions carries release version results.
	// Versions 携带发行版本结果。
	Versions []VersionOption
	// Validation carries authoritative configuration validation results.
	// Validation 携带权威配置校验结果。
	Validation *ValidationSummary
	// Config carries advanced editor results.
	// Config 携带高级编辑器结果。
	Config *ConfigFieldsResult
	// Message is a sanitized, localized, or stable user-facing message.
	// Message 是已脱敏、本地化或稳定的用户可见消息。
	Message string
	// Retryable reports whether the failed operation can be tried again.
	// Retryable 表示失败操作是否可以重试。
	Retryable bool
}

// Controller is the boundary between presentation and real installation work.
// Controller 是展示层与真实安装工作的边界。
type Controller interface {
	// Start begins one cancellable operation and returns a progress event stream.
	// Start 启动一个可取消操作并返回进度事件流。
	Start(context.Context, OperationRequest) (<-chan OperationEvent, error)
	// OpenConfigFields opens an advanced, schema-backed configuration editor.
	// OpenConfigFields 打开一个由 schema 支持的高级配置编辑器。
	OpenConfigFields(context.Context, ConfigFieldsRequest) (ConfigFieldsResult, error)
}

// Localizer resolves the real i18n catalog without making view code own catalog state.
// Localizer 解析真实 i18n 目录，使视图代码不拥有目录状态。
type Localizer interface {
	// Text returns one localized message with named placeholder values.
	// Text 使用命名占位值返回一条本地化消息。
	Text(Language, i18n.MessageKey, map[string]string) string
}

// ModelConfig supplies dependencies and initial state to NewModel.
// ModelConfig 为 NewModel 提供依赖和初始状态。
type ModelConfig struct {
	// EntryAction selects an explicit CLI configuration, upgrade, or rollback entry.
	// EntryAction 选择命令行明确请求的配置、升级或回滚入口。
	EntryAction string
	// Controller performs all network and system operations.
	// Controller 执行全部网络和系统操作。
	Controller Controller
	// Localizer resolves Chinese and English message catalogs.
	// Localizer 解析中英文消息目录。
	Localizer Localizer
	// Language is the initial language; Chinese is used when empty.
	// Language 是初始语言，留空时使用中文。
	Language Language
	// Initial is the locally detected installation snapshot.
	// Initial 是本地检测得到的安装状态摘要。
	Initial InstallationSnapshot
	// Defaults provides platform-specific first-install roots and baseline choices.
	// Defaults 提供平台专用的首次安装目录和基线选择。
	Defaults InstallPlan
	// Sources preloads built-in and previously saved download sources.
	// Sources 预加载内置和上次保存的下载源。
	Sources []SourceOption
	// Versions preloads immutable versions already resolved by the CLI layer.
	// Versions 预加载 CLI 层已解析的不可变版本。
	Versions []VersionOption
	// Storage preloads the five storage explanations; defaults are used when empty.
	// Storage 预加载五种存储说明，留空时使用默认值。
	Storage []StorageOption
	// PlatformOS overrides runtime.GOOS for embedding and deterministic tests.
	// PlatformOS 为嵌入场景和确定性测试覆盖 runtime.GOOS。
	PlatformOS string
}

// DefaultStorageOptions returns the five modes with truthful retrieval descriptions.
// DefaultStorageOptions 返回带有真实检索说明的五种模式。
func DefaultStorageOptions() []StorageOption {
	return []StorageOption{
		{Mode: StorageNative, Label: "Native local", LabelChinese: "原生本地", LabelEnglish: "Native local", Algorithm: "SQLite FTS5/BM25 + LanceDB vector; hybrid RRF in the application layer", AlgorithmChinese: "SQLite FTS5/BM25 + LanceDB 向量；混合 RRF 在应用层执行", AlgorithmEnglish: "SQLite FTS5/BM25 + LanceDB vector; hybrid RRF in the application layer", PathHint: "sqlite.native.path / lancedb.native.path", PathHintChinese: "sqlite.native.path / lancedb.native.path", PathHintEnglish: "sqlite.native.path / lancedb.native.path"},
		{Mode: StorageSplit, Label: "Split", LabelChinese: "本地分离", LabelEnglish: "Split", Algorithm: "VLDB SQLite lexical + LanceDB vector; native FTS5 is not writable; hybrid RRF in the application layer", AlgorithmChinese: "VLDB SQLite 词法 + LanceDB 向量；不可写入 native FTS5；混合 RRF 在应用层执行", AlgorithmEnglish: "VLDB SQLite lexical + LanceDB vector; native FTS5 is not writable; hybrid RRF in the application layer", PathHint: "storage.local_data_root", PathHintChinese: "storage.local_data_root", PathHintEnglish: "storage.local_data_root"},
		{Mode: StorageController, Label: "VLDB controller", LabelChinese: "VLDB 控制器", LabelEnglish: "VLDB controller", Algorithm: "Controller SQLite/LanceDB retrieval; VMM hybrid and rerank settings apply", AlgorithmChinese: "控制器提供 SQLite/LanceDB 检索接口；混合和重排由 VMM 配置决定", AlgorithmEnglish: "Controller SQLite/LanceDB retrieval; VMM hybrid and rerank settings apply", PathHint: "controller endpoint and storage.local_data_root", PathHintChinese: "控制器端点和 storage.local_data_root", PathHintEnglish: "controller endpoint and storage.local_data_root"},
		{Mode: StoragePostgreSQL, Label: "PostgreSQL", LabelChinese: "PostgreSQL", LabelEnglish: "PostgreSQL", Algorithm: "pgvector vector + trigram/ILIKE lexical; SQL RRF then application post-processing", AlgorithmChinese: "pgvector 向量 + trigram/ILIKE 词法；SQL 内先 RRF，再由应用层后处理", AlgorithmEnglish: "pgvector vector + trigram/ILIKE lexical; SQL RRF then application post-processing", PathHint: "PostgreSQL DSN", PathHintChinese: "PostgreSQL DSN", PathHintEnglish: "PostgreSQL DSN"},
		{Mode: StorageParadeDB, Label: "ParadeDB", LabelChinese: "ParadeDB", LabelEnglish: "ParadeDB", Algorithm: "pgvector vector + pg_search BM25 lexical; SQL RRF then application post-processing", AlgorithmChinese: "pgvector 向量 + pg_search BM25 词法；SQL 内先 RRF，再由应用层后处理", AlgorithmEnglish: "pgvector vector + pg_search BM25 lexical; SQL RRF then application post-processing", PathHint: "PostgreSQL DSN + pg_search", PathHintChinese: "PostgreSQL DSN + pg_search", PathHintEnglish: "PostgreSQL DSN + pg_search"},
	}
}

// DefaultSourceOptions returns the official source and the three observed proxy sources.
// DefaultSourceOptions 返回官方源和三个已观测代理源。
func DefaultSourceOptions() []SourceOption {
	sources := download.DefaultSources()
	result := make([]SourceOption, 0, len(sources))
	for _, source := range sources {
		result = append(result, SourceOption{Source: source, DisplayName: source.Name})
	}
	return result
}
