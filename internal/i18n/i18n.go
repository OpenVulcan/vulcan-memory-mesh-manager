// Package i18n provides the installer's stable bilingual message catalog and locale selection.
// i18n 包为安装器提供稳定的中英文消息目录与语言选择能力。
//
// The package deliberately uses named placeholders instead of printf-style formatting so user
// input is inserted as data and cannot change the formatting operation.
// 本包使用命名占位符而不是 printf 风格格式化，使用户输入始终作为数据插入而不会改变格式化操作。
package i18n

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Language identifies one supported installer language.
// Language 标识安装器支持的一种语言。
type Language string

const (
	// English selects the English message catalog.
	// English 选择英文消息目录。
	English Language = "en"

	// SimplifiedChinese selects the Simplified Chinese message catalog.
	// SimplifiedChinese 选择简体中文消息目录。
	SimplifiedChinese Language = "zh"
)

// MessageKey identifies a translated message used by the TUI and CLI.
// MessageKey 标识 TUI 与 CLI 使用的一条翻译消息。
type MessageKey string

// Message keys cover navigation, downloads, verification, storage, providers, services, PATH,
// uninstall flow, status display, and user-facing errors.
// 消息键覆盖导航、下载、验证、存储、供应商、服务、PATH、卸载流程、状态显示和面向用户的错误。
const (
	KeyAppTitle    MessageKey = "app.title"
	KeyAppSubtitle MessageKey = "app.subtitle"

	KeyNavInstall    MessageKey = "nav.install"
	KeyNavManage     MessageKey = "nav.manage"
	KeyNavConfigure  MessageKey = "nav.configure"
	KeyNavLanguage   MessageKey = "nav.language"
	KeyNavQuit       MessageKey = "nav.quit"
	KeyActionBack    MessageKey = "action.back"
	KeyActionNext    MessageKey = "action.next"
	KeyActionSave    MessageKey = "action.save"
	KeyActionCancel  MessageKey = "action.cancel"
	KeyActionRetry   MessageKey = "action.retry"
	KeyActionRefresh MessageKey = "action.refresh"
	KeyActionConfirm MessageKey = "action.confirm"
	KeyActionSkip    MessageKey = "action.skip"

	KeyDownloadTitle        MessageKey = "download.title"
	KeyDownloadSource       MessageKey = "download.source"
	KeyDownloadSourceCheck  MessageKey = "download.source.checking"
	KeyDownloadSourceOK     MessageKey = "download.source.available"
	KeyDownloadSourceBad    MessageKey = "download.source.unavailable"
	KeyDownloadSourceCustom MessageKey = "download.source.custom"
	KeyDownloadManifest     MessageKey = "download.manifest"
	KeyDownloadPackage      MessageKey = "download.package"
	KeyDownloadProgress     MessageKey = "download.progress"
	KeyDownloadComplete     MessageKey = "download.complete"

	KeyVerifySignature       MessageKey = "verify.signature"
	KeyVerifySignatureOK     MessageKey = "verify.signature.ok"
	KeyVerifySignatureFailed MessageKey = "verify.signature.failed"
	KeyVerifyChecksum        MessageKey = "verify.checksum"
	KeyVerifyChecksumOK      MessageKey = "verify.checksum.ok"
	KeyVerifyChecksumFailed  MessageKey = "verify.checksum.failed"
	KeyVerifyReceipt         MessageKey = "verify.receipt"
	KeyVerifyReceiptFailed   MessageKey = "verify.receipt.failed"

	KeyStorageTitle      MessageKey = "storage.title"
	KeyStorageNative     MessageKey = "storage.native"
	KeyStorageSplit      MessageKey = "storage.split"
	KeyStorageController MessageKey = "storage.controller"
	KeyStoragePGSQL      MessageKey = "storage.pgsql"
	KeyStorageParadeDB   MessageKey = "storage.paradedb"
	KeyStoragePath       MessageKey = "storage.path"
	KeyStorageAlgorithm  MessageKey = "storage.algorithm"
	KeyStorageSelect     MessageKey = "storage.select"

	KeyProviderTitle     MessageKey = "provider.title"
	KeyProviderLLM       MessageKey = "provider.llm"
	KeyProviderEmbedding MessageKey = "provider.embedding"
	KeyProviderRerank    MessageKey = "provider.rerank"
	KeyProviderEndpoint  MessageKey = "provider.endpoint"
	KeyProviderModel     MessageKey = "provider.model"
	KeyProviderAPIKey    MessageKey = "provider.api_key"
	KeyProviderDimension MessageKey = "provider.dimension"
	KeyProviderValidate  MessageKey = "provider.validate"
	KeyProviderValid     MessageKey = "provider.valid"
	KeyProviderInvalid   MessageKey = "provider.invalid"
	KeyProviderSaved     MessageKey = "provider.saved"

	KeyServiceTitle     MessageKey = "service.title"
	KeyServiceCLI       MessageKey = "service.cli"
	KeyServiceMode      MessageKey = "service.mode"
	KeyServiceInstall   MessageKey = "service.install"
	KeyServiceUninstall MessageKey = "service.uninstall"
	KeyServiceStart     MessageKey = "service.start"
	KeyServiceStop      MessageKey = "service.stop"
	KeyServiceRestart   MessageKey = "service.restart"
	KeyServiceEnable    MessageKey = "service.enable"
	KeyServiceDisable   MessageKey = "service.disable"
	KeyServiceStatus    MessageKey = "service.status"
	KeyServiceAutoStart MessageKey = "service.autostart"
	KeyServiceRunning   MessageKey = "service.running"
	KeyServiceStopped   MessageKey = "service.stopped"

	KeyPathTitle      MessageKey = "path.title"
	KeyPathAdd        MessageKey = "path.add"
	KeyPathAdded      MessageKey = "path.added"
	KeyPathExists     MessageKey = "path.exists"
	KeyPathPermission MessageKey = "path.permission"

	KeyUninstallTitle      MessageKey = "uninstall.title"
	KeyUninstallConfirm    MessageKey = "uninstall.confirm"
	KeyUninstallComplete   MessageKey = "uninstall.complete"
	KeyUninstallKeepConfig MessageKey = "uninstall.keep_config"
	KeyUninstallKeepData   MessageKey = "uninstall.keep_data"

	KeyStatusInstalled    MessageKey = "status.installed"
	KeyStatusNotInstalled MessageKey = "status.not_installed"
	KeyStatusUnknown      MessageKey = "status.unknown"

	KeyErrorInvalidInput        MessageKey = "error.invalid_input"
	KeyErrorMissingConfig       MessageKey = "error.missing_config"
	KeyErrorDownload            MessageKey = "error.download"
	KeyErrorVerification        MessageKey = "error.verification"
	KeyErrorUnsupportedPlatform MessageKey = "error.unsupported_platform"
	KeyErrorConfigValidation    MessageKey = "error.config_validation"
	KeyErrorPermission          MessageKey = "error.permission"
	KeyErrorOperation           MessageKey = "error.operation"
	KeyErrorNotInstalled        MessageKey = "error.not_installed"
	KeyErrorInternal            MessageKey = "error.internal"
)

// Errors identify invalid locale input, missing catalog entries, and unsafe template usage.
// Errors 标识无效语言输入、缺失目录项和不安全模板使用。
var (
	// ErrEmptyLanguage reports an empty explicit language value.
	// ErrEmptyLanguage 表示显式语言值为空。
	ErrEmptyLanguage = errors.New("i18n: language is empty")

	// ErrUnsupportedLanguage reports a language or locale that is not supported.
	// ErrUnsupportedLanguage 表示语言或区域设置不受支持。
	ErrUnsupportedLanguage = errors.New("i18n: unsupported language")

	// ErrMissingMessage reports a message key absent from a catalog.
	// ErrMissingMessage 表示消息键不在目录中。
	ErrMissingMessage = errors.New("i18n: message is missing")

	// ErrCatalogMismatch reports different key sets or placeholder sets between languages.
	// ErrCatalogMismatch 表示不同语言的消息键集合或占位符集合不一致。
	ErrCatalogMismatch = errors.New("i18n: catalog mismatch")

	// ErrMalformedTemplate reports an invalid named-placeholder template.
	// ErrMalformedTemplate 表示命名占位符模板格式无效。
	ErrMalformedTemplate = errors.New("i18n: malformed template")

	// ErrMissingPlaceholder reports a required placeholder value that was not supplied.
	// ErrMissingPlaceholder 表示调用方没有提供必需的占位符值。
	ErrMissingPlaceholder = errors.New("i18n: placeholder value is missing")

	// ErrUnexpectedPlaceholder reports a value with no corresponding placeholder in the message.
	// ErrUnexpectedPlaceholder 表示提供了消息中不存在的占位符值。
	ErrUnexpectedPlaceholder = errors.New("i18n: unexpected placeholder value")

	// ErrInvalidPlaceholder reports a placeholder name that could be ambiguous or unsafe.
	// ErrInvalidPlaceholder 表示可能含糊或不安全的占位符名称。
	ErrInvalidPlaceholder = errors.New("i18n: invalid placeholder")
)

// Catalog is an immutable view of one validated language catalog.
// Catalog 是一个经过验证的不可变语言目录视图。
type Catalog struct {
	language Language
	messages map[MessageKey]string
}

// New validates and loads the catalog for the requested language.
// New 验证并加载指定语言的消息目录。
func New(language Language) (Catalog, error) {
	if err := ValidateCatalogs(); err != nil {
		return Catalog{}, err
	}
	messages, ok := catalogs[language]
	if !ok {
		return Catalog{}, fmt.Errorf("%w: %q", ErrUnsupportedLanguage, language)
	}
	copyMessages := make(map[MessageKey]string, len(messages))
	for key, message := range messages {
		copyMessages[key] = message
	}
	return Catalog{language: language, messages: copyMessages}, nil
}

// Language returns the locale represented by the catalog.
// Language 返回该目录代表的语言。
func (c Catalog) Language() Language {
	return c.language
}

// Has reports whether the catalog contains a message key.
// Has 判断目录是否包含指定消息键。
func (c Catalog) Has(key MessageKey) bool {
	_, ok := c.messages[key]
	return ok
}

// Text returns a message template without applying placeholder substitution.
// Text 返回未经占位符替换的消息模板。
func (c Catalog) Text(key MessageKey) (string, error) {
	message, ok := c.messages[key]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrMissingMessage, key)
	}
	return message, nil
}

// Format safely substitutes all named placeholders and rejects missing or extra values.
// Format 安全替换全部命名占位符，并拒绝缺失值或多余值。
func (c Catalog) Format(key MessageKey, values map[string]string) (string, error) {
	template, err := c.Text(key)
	if err != nil {
		return "", err
	}
	return formatTemplate(template, values)
}

// Keys returns all catalog keys in deterministic lexical order.
// Keys 按稳定的字典序返回全部目录键。
func Keys() []MessageKey {
	keys := make([]MessageKey, 0, len(catalogs[English]))
	for key := range catalogs[English] {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// ValidateCatalogs checks that every supported language has the same complete key and placeholder sets.
// ValidateCatalogs 检查每种支持语言是否拥有一致且完整的消息键集合与占位符集合。
func ValidateCatalogs() error {
	english, ok := catalogs[English]
	if !ok {
		return fmt.Errorf("%w: missing English catalog", ErrCatalogMismatch)
	}
	chinese, ok := catalogs[SimplifiedChinese]
	if !ok {
		return fmt.Errorf("%w: missing Simplified Chinese catalog", ErrCatalogMismatch)
	}
	if len(english) != len(chinese) {
		return fmt.Errorf("%w: catalog key counts differ", ErrCatalogMismatch)
	}
	for key, englishTemplate := range english {
		if strings.TrimSpace(englishTemplate) == "" {
			return fmt.Errorf("%w: English %q is empty", ErrCatalogMismatch, key)
		}
		chineseTemplate, exists := chinese[key]
		if !exists {
			return fmt.Errorf("%w: %q is missing from Chinese catalog", ErrCatalogMismatch, key)
		}
		if strings.TrimSpace(chineseTemplate) == "" {
			return fmt.Errorf("%w: Chinese %q is empty", ErrCatalogMismatch, key)
		}
		englishPlaceholders, err := templatePlaceholders(englishTemplate)
		if err != nil {
			return fmt.Errorf("%w: English %q: %v", ErrCatalogMismatch, key, err)
		}
		chinesePlaceholders, err := templatePlaceholders(chineseTemplate)
		if err != nil {
			return fmt.Errorf("%w: Chinese %q: %v", ErrCatalogMismatch, key, err)
		}
		if !sameStrings(englishPlaceholders, chinesePlaceholders) {
			return fmt.Errorf("%w: placeholder sets differ for %q", ErrCatalogMismatch, key)
		}
	}
	return nil
}

// ParseLanguage parses an explicit language or a POSIX-style locale such as zh_CN.UTF-8.
// ParseLanguage 解析显式语言值或 zh_CN.UTF-8 这类 POSIX 风格区域设置。
func ParseLanguage(raw string) (Language, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return "", ErrEmptyLanguage
	}
	if dot := strings.IndexByte(normalized, '.'); dot >= 0 {
		normalized = normalized[:dot]
	}
	if modifier := strings.IndexByte(normalized, '@'); modifier >= 0 {
		normalized = normalized[:modifier]
	}
	normalized = strings.ReplaceAll(normalized, "-", "_")
	base := normalized
	if underscore := strings.IndexByte(normalized, '_'); underscore >= 0 {
		base = normalized[:underscore]
	}
	switch base {
	case string(English):
		return English, nil
	case string(SimplifiedChinese):
		return SimplifiedChinese, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedLanguage, raw)
	}
}

// DetectLanguage selects LC_ALL, then LC_MESSAGES, then LANG, defaulting to English.
// DetectLanguage 按 LC_ALL、LC_MESSAGES、LANG 的顺序选择语言，未识别时默认英文。
func DetectLanguage(env map[string]string) Language {
	for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if value := strings.TrimSpace(env[name]); value != "" {
			language, err := ParseLanguage(value)
			if err == nil {
				return language
			}
			// POSIX C/POSIX locales and malformed values intentionally use the safe English fallback.
			// POSIX 的 C/POSIX 区域设置及格式错误值有意使用安全的英文回退。
			return English
		}
	}
	return English
}

// DetectLanguageFromEnvironment reads the process locale variables and applies DetectLanguage.
// DetectLanguageFromEnvironment 读取进程区域设置变量并调用 DetectLanguage。
func DetectLanguageFromEnvironment() Language {
	return DetectLanguage(map[string]string{
		"LC_ALL":      os.Getenv("LC_ALL"),
		"LC_MESSAGES": os.Getenv("LC_MESSAGES"),
		"LANG":        os.Getenv("LANG"),
	})
}

// SelectLanguage honors an explicit value and otherwise selects from the supplied environment.
// SelectLanguage 优先使用显式值，否则从给定环境中选择语言。
func SelectLanguage(explicit string, env map[string]string) (Language, error) {
	if strings.TrimSpace(explicit) != "" {
		return ParseLanguage(explicit)
	}
	return DetectLanguage(env), nil
}

// validPlaceholderName defines the conservative ASCII name accepted by the formatter.
// validPlaceholderName 定义格式化器接受的保守 ASCII 占位符名称。
func validPlaceholderName(name string) bool {
	if name == "" || (name[0] < 'a' || name[0] > 'z') {
		return false
	}
	for index := 1; index < len(name); index++ {
		character := name[index]
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

// templatePlaceholders parses named placeholders and returns their unique names in lexical order.
// templatePlaceholders 解析命名占位符，并按字典序返回去重后的名称。
func templatePlaceholders(template string) ([]string, error) {
	names := make(map[string]struct{})
	for index := 0; index < len(template); {
		if template[index] == '}' {
			return nil, fmt.Errorf("%w: unexpected closing brace", ErrMalformedTemplate)
		}
		if template[index] != '{' {
			index++
			continue
		}
		close := strings.IndexByte(template[index+1:], '}')
		if close < 0 {
			return nil, fmt.Errorf("%w: missing closing brace", ErrMalformedTemplate)
		}
		close += index + 1
		name := template[index+1 : close]
		if !validPlaceholderName(name) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidPlaceholder, name)
		}
		names[name] = struct{}{}
		index = close + 1
	}
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

// formatTemplate performs strict named substitution without interpreting replacement text.
// formatTemplate 执行严格的命名替换，不解释替换文本中的格式语法。
func formatTemplate(template string, values map[string]string) (string, error) {
	placeholders, err := templatePlaceholders(template)
	if err != nil {
		return "", err
	}
	provided := make(map[string]struct{}, len(values))
	for name := range values {
		if !validPlaceholderName(name) {
			return "", fmt.Errorf("%w: %q", ErrInvalidPlaceholder, name)
		}
		provided[name] = struct{}{}
	}
	for _, name := range placeholders {
		if _, ok := values[name]; !ok {
			return "", fmt.Errorf("%w: %q", ErrMissingPlaceholder, name)
		}
	}
	for name := range provided {
		if !containsString(placeholders, name) {
			return "", fmt.Errorf("%w: %q", ErrUnexpectedPlaceholder, name)
		}
	}
	if len(placeholders) == 0 {
		return template, nil
	}
	var builder strings.Builder
	builder.Grow(len(template))
	for index := 0; index < len(template); {
		if template[index] != '{' {
			builder.WriteByte(template[index])
			index++
			continue
		}
		close := strings.IndexByte(template[index+1:], '}') + index + 1
		name := template[index+1 : close]
		builder.WriteString(values[name])
		index = close + 1
	}
	return builder.String(), nil
}

// containsString reports whether a sorted string slice contains a value.
// containsString 判断已排序字符串切片是否包含指定值。
func containsString(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

// sameStrings compares two sorted string slices exactly.
// sameStrings 精确比较两个已排序字符串切片。
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

// catalogs is the built-in source catalog; New copies entries before returning them to callers.
// catalogs 是内置源目录；New 返回目录前会复制条目以隔离调用方。
var catalogs = map[Language]map[MessageKey]string{
	English: {
		KeyAppTitle:                 "Vulcan Memory Mesh Manager",
		KeyAppSubtitle:              "Install, configure, and manage VMM",
		KeyNavInstall:               "Install",
		KeyNavManage:                "Manage installation",
		KeyNavConfigure:             "Configure",
		KeyNavLanguage:              "Language",
		KeyNavQuit:                  "Quit",
		KeyActionBack:               "Back",
		KeyActionNext:               "Next",
		KeyActionSave:               "Save",
		KeyActionCancel:             "Cancel",
		KeyActionRetry:              "Retry",
		KeyActionRefresh:            "Refresh",
		KeyActionConfirm:            "Confirm",
		KeyActionSkip:               "Skip",
		KeyDownloadTitle:            "Download",
		KeyDownloadSource:           "Download source: {source}",
		KeyDownloadSourceCheck:      "Checking source: {source}",
		KeyDownloadSourceOK:         "Source available: {source}",
		KeyDownloadSourceBad:        "Source unavailable: {source}",
		KeyDownloadSourceCustom:     "Custom source",
		KeyDownloadManifest:         "Downloading release manifest",
		KeyDownloadPackage:          "Downloading package: {file}",
		KeyDownloadProgress:         "Progress: {current}/{total}",
		KeyDownloadComplete:         "Download complete: {version}",
		KeyVerifySignature:          "Verifying release signature",
		KeyVerifySignatureOK:        "Release signature is valid",
		KeyVerifySignatureFailed:    "Release signature verification failed: {detail}",
		KeyVerifyChecksum:           "Verifying package checksum",
		KeyVerifyChecksumOK:         "Package checksum is valid",
		KeyVerifyChecksumFailed:     "Package checksum verification failed: {detail}",
		KeyVerifyReceipt:            "Verifying package receipt",
		KeyVerifyReceiptFailed:      "Package receipt verification failed: {detail}",
		KeyStorageTitle:             "Storage mode",
		KeyStorageNative:            "Native local storage",
		KeyStorageSplit:             "Split controller storage",
		KeyStorageController:        "VMM controller storage",
		KeyStoragePGSQL:             "PostgreSQL",
		KeyStorageParadeDB:          "ParadeDB",
		KeyStoragePath:              "Database path: {path}",
		KeyStorageAlgorithm:         "Memory retrieval algorithm: {algorithm}",
		KeyStorageSelect:            "Select a storage mode",
		KeyProviderTitle:            "Provider configuration",
		KeyProviderLLM:              "Chat model provider",
		KeyProviderEmbedding:        "Embedding provider",
		KeyProviderRerank:           "Rerank provider",
		KeyProviderEndpoint:         "Endpoint",
		KeyProviderModel:            "Model",
		KeyProviderAPIKey:           "API key",
		KeyProviderDimension:        "Embedding dimension",
		KeyProviderValidate:         "Check provider configuration",
		KeyProviderValid:            "Provider configuration is valid",
		KeyProviderInvalid:          "Provider configuration is invalid: {detail}",
		KeyProviderSaved:            "Provider configuration saved: {provider}",
		KeyServiceTitle:             "Service and command-line mode",
		KeyServiceCLI:               "Command-line mode",
		KeyServiceMode:              "Service mode",
		KeyServiceInstall:           "Install service",
		KeyServiceUninstall:         "Uninstall service",
		KeyServiceStart:             "Start service",
		KeyServiceStop:              "Stop service",
		KeyServiceRestart:           "Restart service",
		KeyServiceEnable:            "Enable automatic startup",
		KeyServiceDisable:           "Disable automatic startup",
		KeyServiceStatus:            "Service status: {state}",
		KeyServiceAutoStart:         "Start automatically",
		KeyServiceRunning:           "Running",
		KeyServiceStopped:           "Stopped",
		KeyPathTitle:                "PATH integration",
		KeyPathAdd:                  "Add manager command to PATH",
		KeyPathAdded:                "Added to PATH: {path}",
		KeyPathExists:               "Already present in PATH: {path}",
		KeyPathPermission:           "Cannot update PATH: {detail}",
		KeyUninstallTitle:           "Uninstall",
		KeyUninstallConfirm:         "Remove VMMM and its service?",
		KeyUninstallComplete:        "Uninstall complete",
		KeyUninstallKeepConfig:      "Keep configuration files",
		KeyUninstallKeepData:        "Keep database files",
		KeyStatusInstalled:          "Installed",
		KeyStatusNotInstalled:       "Not installed",
		KeyStatusUnknown:            "Unknown",
		KeyErrorInvalidInput:        "Invalid input: {detail}",
		KeyErrorMissingConfig:       "Configuration file is missing: {path}",
		KeyErrorDownload:            "Download failed: {detail}",
		KeyErrorVerification:        "Verification failed: {detail}",
		KeyErrorUnsupportedPlatform: "Unsupported platform: {platform}",
		KeyErrorConfigValidation:    "Configuration validation failed: {detail}",
		KeyErrorPermission:          "Permission denied: {detail}",
		KeyErrorOperation:           "Operation failed: {detail}",
		KeyErrorNotInstalled:        "VMMM is not installed",
		KeyErrorInternal:            "Internal error: {detail}",
	},
	SimplifiedChinese: {
		KeyAppTitle:                 "Vulcan Memory Mesh 管理器",
		KeyAppSubtitle:              "安装、配置和管理 VMM",
		KeyNavInstall:               "安装",
		KeyNavManage:                "管理安装",
		KeyNavConfigure:             "配置",
		KeyNavLanguage:              "语言",
		KeyNavQuit:                  "退出",
		KeyActionBack:               "返回",
		KeyActionNext:               "下一步",
		KeyActionSave:               "保存",
		KeyActionCancel:             "取消",
		KeyActionRetry:              "重试",
		KeyActionRefresh:            "刷新",
		KeyActionConfirm:            "确认",
		KeyActionSkip:               "跳过",
		KeyDownloadTitle:            "下载",
		KeyDownloadSource:           "下载源：{source}",
		KeyDownloadSourceCheck:      "正在检查下载源：{source}",
		KeyDownloadSourceOK:         "下载源可用：{source}",
		KeyDownloadSourceBad:        "下载源不可用：{source}",
		KeyDownloadSourceCustom:     "自定义下载源",
		KeyDownloadManifest:         "正在下载发行清单",
		KeyDownloadPackage:          "正在下载安装包：{file}",
		KeyDownloadProgress:         "进度：{current}/{total}",
		KeyDownloadComplete:         "下载完成：{version}",
		KeyVerifySignature:          "正在验证发行签名",
		KeyVerifySignatureOK:        "发行签名有效",
		KeyVerifySignatureFailed:    "发行签名验证失败：{detail}",
		KeyVerifyChecksum:           "正在验证安装包校验和",
		KeyVerifyChecksumOK:         "安装包校验和有效",
		KeyVerifyChecksumFailed:     "安装包校验和验证失败：{detail}",
		KeyVerifyReceipt:            "正在验证安装包收据",
		KeyVerifyReceiptFailed:      "安装包收据验证失败：{detail}",
		KeyStorageTitle:             "存储方式",
		KeyStorageNative:            "原生本地存储",
		KeyStorageSplit:             "分离式控制器存储",
		KeyStorageController:        "VMM 控制器存储",
		KeyStoragePGSQL:             "PostgreSQL",
		KeyStorageParadeDB:          "ParadeDB",
		KeyStoragePath:              "数据库路径：{path}",
		KeyStorageAlgorithm:         "记忆检索算法：{algorithm}",
		KeyStorageSelect:            "选择存储方式",
		KeyProviderTitle:            "供应商配置",
		KeyProviderLLM:              "对话模型供应商",
		KeyProviderEmbedding:        "嵌入供应商",
		KeyProviderRerank:           "重排供应商",
		KeyProviderEndpoint:         "端点",
		KeyProviderModel:            "模型",
		KeyProviderAPIKey:           "API 密钥",
		KeyProviderDimension:        "嵌入维度",
		KeyProviderValidate:         "检查供应商配置",
		KeyProviderValid:            "供应商配置有效",
		KeyProviderInvalid:          "供应商配置无效：{detail}",
		KeyProviderSaved:            "供应商配置已保存：{provider}",
		KeyServiceTitle:             "服务与命令行模式",
		KeyServiceCLI:               "命令行模式",
		KeyServiceMode:              "服务模式",
		KeyServiceInstall:           "安装服务",
		KeyServiceUninstall:         "卸载服务",
		KeyServiceStart:             "启动服务",
		KeyServiceStop:              "停止服务",
		KeyServiceRestart:           "重启服务",
		KeyServiceEnable:            "启用自动启动",
		KeyServiceDisable:           "禁用自动启动",
		KeyServiceStatus:            "服务状态：{state}",
		KeyServiceAutoStart:         "自动启动",
		KeyServiceRunning:           "运行中",
		KeyServiceStopped:           "已停止",
		KeyPathTitle:                "PATH 集成",
		KeyPathAdd:                  "将管理器命令加入 PATH",
		KeyPathAdded:                "已加入 PATH：{path}",
		KeyPathExists:               "PATH 中已存在：{path}",
		KeyPathPermission:           "无法更新 PATH：{detail}",
		KeyUninstallTitle:           "卸载",
		KeyUninstallConfirm:         "删除 VMMM 及其服务？",
		KeyUninstallComplete:        "卸载完成",
		KeyUninstallKeepConfig:      "保留配置文件",
		KeyUninstallKeepData:        "保留数据库文件",
		KeyStatusInstalled:          "已安装",
		KeyStatusNotInstalled:       "未安装",
		KeyStatusUnknown:            "未知",
		KeyErrorInvalidInput:        "输入无效：{detail}",
		KeyErrorMissingConfig:       "配置文件不存在：{path}",
		KeyErrorDownload:            "下载失败：{detail}",
		KeyErrorVerification:        "验证失败：{detail}",
		KeyErrorUnsupportedPlatform: "不支持的平台：{platform}",
		KeyErrorConfigValidation:    "配置校验失败：{detail}",
		KeyErrorPermission:          "权限不足：{detail}",
		KeyErrorOperation:           "操作失败：{detail}",
		KeyErrorNotInstalled:        "VMMM 尚未安装",
		KeyErrorInternal:            "内部错误：{detail}",
	},
}
