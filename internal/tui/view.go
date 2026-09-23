// This file renders every TUI page as bounded, colorless terminal text.
// 本文件将所有 TUI 页面渲染为有界的无色终端文本。
package tui

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/download"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/i18n"
	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/providerwizard"
)

// render builds the complete plain-text screen and bounds every line to the terminal width.
// render 构造完整纯文本页面，并将每一行限制在终端宽度内。
func (m *Model) render() string {
	header := []string{
		m.text(i18n.KeyAppTitle, nil),
		m.text(i18n.KeyAppSubtitle, nil),
		strings.Repeat("-", m.renderWidth()),
	}
	if m.status != "" {
		header = append(header, m.status)
	}
	if m.errorMessage != "" {
		header = append(header, m.label("错误：", "Error: ")+m.errorMessage)
	}
	page := m.renderPage()
	tail := []string{"", m.footer()}
	if m.busy {
		tail = append([]string{m.renderProgress()}, tail...)
	}
	page = visiblePage(page, m.renderHeight()-len(header)-len(tail), m.isTextInput() && m.screen == ScreenFieldEdit)
	lines := append(header, page...)
	lines = append(lines, tail...)
	return boundLines(lines, m.renderWidth(), m.renderHeight())
}

// visiblePage keeps the selected item and its active input inside a bounded scrolling page.
// visiblePage 在有限高度的滚动页面内保留选中项及其正在编辑的输入行。
func visiblePage(page []string, capacity int, includeInput bool) []string {
	if capacity <= 0 {
		return nil
	}
	if len(page) <= capacity {
		return page
	}
	focus := 0
	for index, line := range page {
		if strings.HasPrefix(line, "> ") {
			focus = index
			break
		}
	}
	if includeInput && focus+1 < len(page) && strings.HasPrefix(page[focus+1], "    > ") {
		for next := focus + 1; next < len(page) && strings.HasPrefix(page[next], "    "); next++ {
			focus = next
		}
	}
	start := focus - capacity + 2
	if start < 0 {
		start = 0
	}
	if start > len(page)-capacity {
		start = len(page) - capacity
	}
	return page[start : start+capacity]
}

// renderPage renders the page-specific content without terminal styling.
// renderPage 渲染不带终端样式的页面内容。
func (m *Model) renderPage() []string {
	switch m.screen {
	case ScreenLanguage:
		return m.renderLanguage()
	case ScreenHome:
		return m.renderHome()
	case ScreenSource:
		return m.renderSource()
	case ScreenCustomSource:
		return []string{m.label("输入 HTTPS GitHub 代理前缀：", "Enter HTTPS GitHub proxy prefix:"), "> " + m.input}
	case ScreenVersion:
		return m.renderVersion()
	case ScreenInstallPath:
		return m.renderInstallPath()
	case ScreenDownload:
		return []string{m.text(i18n.KeyDownloadTitle, nil), m.text(i18n.KeyDownloadManifest, nil), m.text(i18n.KeyDownloadPackage, map[string]string{"file": m.selectedVersion.Tag})}
	case ScreenStorage:
		return m.renderStorage()
	case ScreenStorageCredential:
		return m.renderStorageCredential()
	case ScreenProviders:
		return m.renderProviders()
	case ScreenProviderChoice:
		return m.renderProviderChoice()
	case ScreenProviderWizard:
		return m.renderProviderWizard()
	case ScreenFieldEdit:
		return m.renderFieldEdit()
	case ScreenService:
		return m.renderService()
	case ScreenServiceUser:
		if !m.serviceUserVisible() {
			return m.renderService()
		}
		return m.renderServiceUser()
	case ScreenPath:
		return m.renderPath()
	case ScreenConfigCheck:
		return m.renderConfigCheck()
	case ScreenConfirm:
		return m.renderConfirm()
	case ScreenRunning:
		return m.renderRunning()
	case ScreenUninstall:
		return m.renderUninstall()
	case ScreenError:
		lines := []string{m.label("操作未完成，请选择后续动作。", "Operation did not complete; choose what to do next.")}
		if m.retryable {
			lines = append(lines, m.option(0, m.text(i18n.KeyActionRetry, nil)))
			lines = append(lines, m.option(1, m.text(i18n.KeyActionBack, nil)))
		} else {
			lines = append(lines, m.option(0, m.text(i18n.KeyActionBack, nil)))
		}
		return lines
	case ScreenDone:
		return []string{m.label("操作已完成。", "Operation completed.")}
	default:
		return nil
	}
}

// renderLanguage shows the bilingual language choices.
// renderLanguage 展示中英文语言选择。
func (m *Model) renderLanguage() []string {
	return []string{
		m.label("选择语言 / Select language", "Select language / 选择语言"),
		m.option(0, "简体中文 (Simplified Chinese)"),
		m.option(1, "English (English)"),
	}
}

// renderHome shows installed status and all service/configuration actions.
// renderHome 展示已安装状态以及全部服务和配置操作。
func (m *Model) renderHome() []string {
	snapshot := m.snapshot
	status := m.text(i18n.KeyStatusNotInstalled, nil)
	if snapshot.Installed {
		status = m.text(i18n.KeyStatusInstalled, nil)
	}
	lines := []string{
		m.label("已安装管理", "Installed management"),
		m.label("状态：", "Status: ") + status,
		m.label("VMM 版本：", "VMM version: ") + valueOrDash(snapshot.VMMVersion),
		m.label("存储：", "Storage: ") + string(snapshot.Storage),
		m.label("服务：", "Service: ") + valueOrDash(snapshot.ServiceState),
		m.label("配置根：", "Config root: ") + valueOrDash(snapshot.ConfigRoot),
		m.label("数据根：", "Data root: ") + valueOrDash(snapshot.DataRoot),
		"",
	}
	for index, item := range []string{
		m.text(i18n.KeyServiceStart, nil),
		m.text(i18n.KeyServiceStop, nil),
		m.text(i18n.KeyServiceRestart, nil),
		m.text(i18n.KeyServiceInstall, nil),
		m.text(i18n.KeyServiceUninstall, nil),
		m.text(i18n.KeyServiceEnable, nil),
		m.text(i18n.KeyServiceDisable, nil),
		m.text(i18n.KeyNavConfigure, nil),
		m.text(i18n.KeyDownloadSource, map[string]string{"source": m.sourceLabel(m.selectedSource)}),
		m.text(i18n.KeyUninstallTitle, nil),
		m.label("回滚到指定版本", "Roll back to a selected release"),
	} {
		lines = append(lines, m.option(index, item))
	}
	return lines
}

// renderSource lists exact sources and the custom HTTPS input route.
// renderSource 列出精确下载源以及自定义 HTTPS 输入入口。
func (m *Model) renderSource() []string {
	lines := []string{
		m.text(i18n.KeyDownloadSource, map[string]string{"source": ""}),
		m.label("源检测必须通过后才能用于安装。", "A source must pass probing before it can be used."),
	}
	for index, source := range m.sources {
		name := m.sourceLabel(source)
		state := m.label("未检测", "unchecked")
		if source.Available {
			state = m.label("可用", "available")
		}
		if source.ProbeMessage != "" {
			state = source.ProbeMessage
		}
		lines = append(lines, m.option(index, name+" ["+state+"]"))
	}
	lines = append(lines, m.option(len(m.sources), m.text(i18n.KeyDownloadSourceCustom, nil)))
	return lines
}

// renderVersion lists immutable releases or opens the manual tag field when none were supplied.
// renderVersion 列出不可变发行版本；没有版本时打开手动标签输入。
func (m *Model) renderVersion() []string {
	lines := []string{m.label("选择 VMM 版本", "Select VMM version")}
	if len(m.versions) == 0 {
		lines = append(lines, m.label("没有预载版本，请输入发行标签：", "No preloaded versions; enter a release tag:"), "> "+m.input)
		return lines
	}
	for index, version := range m.versions {
		state := m.label("待检测", "unchecked")
		if version.Available {
			state = m.label("可用", "available")
		}
		lines = append(lines, m.option(index, version.Tag+" ["+state+"]"))
	}
	return lines
}

// renderInstallPath renders the three explicit roots required by service registration.
// renderInstallPath 渲染服务注册所需的三个明确根目录。
func (m *Model) renderInstallPath() []string {
	names := []string{
		m.label("程序根目录", "Program root"),
		m.label("配置根目录", "Config root"),
		m.label("数据根目录", "Data root"),
	}
	return []string{
		m.label("安装目录和配置目录必须在注册服务时保持稳定。", "Program and configuration roots must stay stable after service registration."),
		names[m.inputField] + ":",
		"> " + m.input,
	}
}

// renderStorage displays all five modes and their retrieval algorithms.
// renderStorage 展示五种模式及其记忆检索算法。
func (m *Model) renderStorage() []string {
	lines := []string{
		m.text(i18n.KeyStorageSelect, nil),
		m.label("混合召回、RRF、MMR 和 Weibull 由 VMM 配置决定。", "Hybrid retrieval, RRF, MMR, and Weibull are controlled by VMM configuration."),
	}
	for index, option := range m.storage {
		availability := ""
		if !m.packageSupportsStorage(option.Mode) {
			availability = m.label(" [不可用]", " [unavailable]")
		}
		lines = append(lines, m.option(index, string(option.Mode)+" - "+m.storageLabel(option)+availability))
		lines = append(lines, "    "+m.text(i18n.KeyStorageAlgorithm, map[string]string{"algorithm": m.storageAlgorithm(option)}))
		lines = append(lines, "    "+m.text(i18n.KeyStoragePath, map[string]string{"path": m.storagePathHint(option)}))
	}
	return lines
}

// renderStorageCredential displays the combined-database variable, masked DSN, and .env path.
// renderStorageCredential 展示组合数据库变量、遮蔽 DSN 和 .env 路径。
func (m *Model) renderStorageCredential() []string {
	lines := []string{
		m.label("数据库凭据配置", "Database credential setup"),
		m.label("YAML 只保存环境变量引用，原始 DSN 只写入受保护的 .env。", "YAML stores only an environment reference; the raw DSN is written only to protected .env."),
	}
	keys := storageCredentialKeys()
	for index, key := range keys {
		label := storageCredentialFieldLabel(m, key)
		value := storageCredentialValue(m.storageCredential, key)
		if key == "value" {
			if m.storageCredential.ExistingConfigured {
				value = m.label("已配置（留空保持）", "configured (leave empty to keep)")
			} else {
				value = m.label("未配置", "not configured")
			}
		}
		if m.storageEditingField == index {
			input := m.input
			if key == "value" {
				input = maskedValue(input)
			}
			lines = append(lines, m.option(index, label), "    > "+input)
			continue
		}
		lines = append(lines, m.option(index, label+" = "+value))
	}
	lines = append(lines, m.option(len(keys), m.text(i18n.KeyActionSave, nil)))
	return lines
}

// storageCredentialFieldLabel returns the localized label for one credential field.
// storageCredentialFieldLabel 返回一个凭据字段的本地化标签。
func storageCredentialFieldLabel(m *Model, key string) string {
	switch key {
	case "variable":
		return m.label("DSN 环境变量名", "DSN environment variable")
	case "value":
		return m.label("原始 DSN（秘密）", "Raw DSN (secret)")
	case "path":
		return m.label(".env 路径", ".env path")
	default:
		return key
	}
}

// renderProviders exposes the three shortcut provider areas and one advanced entry.
// renderProviders 展示三个供应商快捷区域和一个高级配置入口。
func (m *Model) renderProviders() []string {
	lines := []string{
		m.text(i18n.KeyProviderTitle, nil),
		m.label("快捷配置调用权威 schema；维度和模型不会由管理器猜测。", "Shortcuts use the authoritative schema; model and embedding dimensions are never guessed."),
	}
	for index, item := range []string{
		m.text(i18n.KeyProviderLLM, nil),
		m.text(i18n.KeyProviderEmbedding, nil),
		m.text(i18n.KeyProviderRerank, nil),
		m.label("完成供应商配置", "Finish provider configuration"),
	} {
		lines = append(lines, m.option(index, item))
	}
	for _, field := range m.configFields.Fields {
		value := field.Value
		if field.Sensitive {
			value = "********"
		}
		lines = append(lines, "  "+field.Path+" = "+value)
	}
	if m.configFields.Summary != "" {
		lines = append(lines, m.configFields.Summary)
	}
	return lines
}

// renderProviderChoice displays the controller's exact provider catalog for one purpose.
// renderProviderChoice 展示控制器为当前用途返回的精确供应商目录。
func (m *Model) renderProviderChoice() []string {
	title := m.label("选择供应商", "Select provider")
	switch m.providerPurpose {
	case ProviderPurposeLLM:
		title = m.text(i18n.KeyProviderLLM, nil)
	case ProviderPurposeEmbedding:
		title = m.text(i18n.KeyProviderEmbedding, nil)
	case ProviderPurposeRerank:
		title = m.text(i18n.KeyProviderRerank, nil)
	}
	lines := []string{title, m.label("供应商 ID 和字段要求来自已核实目录。", "Provider IDs and field requirements come from the verified catalog.")}
	for index, metadata := range m.providerOptions {
		name := metadata.DisplayNameZH
		if m.language == LanguageEnglish {
			name = metadata.DisplayNameEN
		}
		if name == "" {
			name = metadata.ID
		}
		lines = append(lines, m.option(index, name+" ["+metadata.ID+"]"))
		lines = append(lines, "    "+providerRequirementSummary(m, metadata))
	}
	return lines
}

// renderProviderWizard displays typed provider fields and masks credential input.
// renderProviderWizard 展示强类型供应商字段并遮蔽凭据输入。
func (m *Model) renderProviderWizard() []string {
	metadata, _ := m.activeProviderMetadata()
	name := metadata.DisplayNameZH
	if m.language == LanguageEnglish {
		name = metadata.DisplayNameEN
	}
	if name == "" {
		name = m.providerDraft.Provider
	}
	lines := []string{
		m.label("供应商快捷配置", "Provider quick setup"),
		m.label("供应商：", "Provider: ") + name + " [" + m.providerDraft.Provider + "]",
	}
	if metadata.DimensionHint != "" && m.providerPurpose == ProviderPurposeEmbedding {
		lines = append(lines, m.label("维度提示：", "Dimension hint: ")+metadata.DimensionHint)
	}
	keys := providerFieldKeys(m.providerPurpose)
	for index, key := range keys {
		label := providerFieldLabel(m, key)
		value := providerFieldValue(m.providerDraft, key)
		if key == "enabled" {
			value = boolState(m.providerDraft.Enabled, m.label("是", "yes"), m.label("否", "no"))
		}
		if key == "api_key_value" {
			if m.providerDraft.CredentialConfigured {
				value = m.label("已配置（留空保持）", "configured (leave empty to keep)")
			} else {
				value = m.label("未配置", "not configured")
			}
		}
		if m.providerEditingField == index {
			input := m.input
			if key == "api_key_value" {
				input = maskedValue(input)
			}
			lines = append(lines, m.option(index, label), "    > "+input)
			continue
		}
		lines = append(lines, m.option(index, label+" = "+value))
	}
	lines = append(lines, m.option(len(keys), m.text(i18n.KeyActionSave, nil)))
	return lines
}

// providerFieldLabel returns the localized label for one stable typed field key.
// providerFieldLabel 返回一个稳定强类型字段键的本地化标签。
func providerFieldLabel(m *Model, key string) string {
	switch key {
	case "name":
		return m.label("路由名称", "Route name")
	case "enabled":
		return m.label("启用 rerank", "Enable rerank")
	case "priority":
		return m.label("路由优先级", "Route priority")
	case "endpoint":
		return m.text(i18n.KeyProviderEndpoint, nil)
	case "model":
		return m.text(i18n.KeyProviderModel, nil)
	case "dimension":
		return m.text(i18n.KeyProviderDimension, nil)
	case "api_key_names":
		return m.label("API key 环境变量名（逗号分隔）", "API key environment names (comma separated)")
	case "api_key_value":
		return m.text(i18n.KeyProviderAPIKey, nil)
	case "credential_path":
		return m.label(".env 路径", ".env path")
	default:
		return key
	}
}

// providerRequirementSummary summarizes verified required fields without guessing values.
// providerRequirementSummary 总结已核实的必填字段，不猜测具体值。
func providerRequirementSummary(m *Model, metadata ProviderMetadata) string {
	parts := make([]string, 0, 4)
	if metadata.EndpointRequirement == providerwizard.RequirementRequired {
		parts = append(parts, m.label("endpoint 必填", "endpoint required"))
	}
	if metadata.ModelRequirement == providerwizard.RequirementRequired {
		parts = append(parts, m.label("模型必填", "model required"))
	}
	if metadata.DimensionRequirement == providerwizard.RequirementRequired {
		parts = append(parts, m.label("维度必填", "dimension required"))
	}
	if metadata.APIKeyEnvironmentRequirement == providerwizard.RequirementRequired {
		parts = append(parts, m.label("需要 .env key", ".env key required"))
	}
	if len(parts) == 0 {
		return m.label("使用目录中的默认值", "uses catalog defaults")
	}
	return strings.Join(parts, ", ")
}

// renderFieldEdit displays schema paths, editability, and masked sensitive values.
// renderFieldEdit 展示 schema 路径、可编辑性和脱敏敏感值。
func (m *Model) renderFieldEdit() []string {
	lines := []string{
		m.label("高级配置字段", "Advanced configuration fields"),
		m.label("只写入可编辑字段；未知字段和只读字段不会被猜测修改。", "Only editable fields are written; unknown and read-only fields are never guessed."),
		m.label("结构化字段可用 Ctrl+O 换行，Enter 保存当前字段。", "Use Ctrl+O for a newline in structured fields; Enter saves the current field."),
		m.label("敏感字段只接受 ${环境变量名} 引用，列表不会显示原值。", "Sensitive fields accept only ${ENV_NAME} references; existing values stay hidden."),
	}
	for index, field := range m.configFields.Fields {
		value := field.Value
		if field.Sensitive {
			value = maskedValue(value)
		}
		preview := strings.ReplaceAll(value, "\n", " ↵ ")
		state := m.label("只读", "read-only")
		if field.Editable {
			state = m.label("可编辑", "editable")
		}
		enumHint := ""
		if len(field.Enum) > 0 {
			enumHint = " {" + strings.Join(field.Enum, "|") + "}"
		}
		if m.editingField == index {
			input := m.input
			if field.Sensitive {
				input = maskedValue(input)
			}
			lines = append(lines, m.option(index, field.Path+enumHint+" ["+state+"]"))
			for inputLineIndex, inputLine := range strings.Split(input, "\n") {
				prefix := "      "
				if inputLineIndex == 0 {
					prefix = "    > "
				}
				lines = append(lines, prefix+inputLine)
			}
			continue
		}
		lines = append(lines, m.option(index, field.Path+enumHint+" = "+preview+" ["+state+"]"))
	}
	lines = append(lines, m.option(len(m.configFields.Fields), m.label("保存并返回", "Save and return")))
	return lines
}

// renderService displays foreground mode, service mode, and service mode with autostart.
// renderService 展示前台模式、服务模式和服务自动启动模式。
func (m *Model) renderService() []string {
	lines := []string{
		m.text(i18n.KeyServiceTitle, nil),
		m.option(0, m.text(i18n.KeyServiceCLI, nil)),
		m.option(1, m.text(i18n.KeyServiceMode, nil)+" (manual start)"),
		m.option(2, m.text(i18n.KeyServiceMode, nil)+" + "+m.text(i18n.KeyServiceAutoStart, nil)),
	}
	if m.serviceUserVisible() {
		lines = append(lines,
			m.label("本机服务用户（选择服务模式后必须确认）： ", "Local service user (must be confirmed for service mode): ")+valueOrDash(m.plan.ServiceUser),
		)
	}
	return lines
}

// renderServiceUser displays the prefilled local account and accepts explicit confirmation or replacement.
// renderServiceUser 展示预填的本机账户，并接受明确确认或替换输入。
func (m *Model) renderServiceUser() []string {
	return []string{
		m.label("确认服务运行用户", "Confirm service runtime user"),
		m.label("该账户由命令层提供；管理器不会从 SUDO_USER 推测。", "The command layer provides this account; the manager never guesses SUDO_USER."),
		m.label("本机用户：", "Local user: ") + "> " + m.input,
		m.label("直接按 Enter 确认，或编辑后按 Enter。", "Press Enter to confirm, or edit before pressing Enter."),
	}
}

// renderPath presents the explicit yes/no PATH choice.
// renderPath 展示明确的是否加入 PATH 选择。
func (m *Model) renderPath() []string {
	return []string{
		m.text(i18n.KeyPathTitle, nil),
		m.label("只写入管理器安装目录，并记录管理器拥有的条目。", "Only the manager installation root is written and ownership is recorded."),
		m.option(0, m.text(i18n.KeyPathAdd, nil)+" (yes)"),
		m.option(1, m.label("不加入 PATH", "Do not add to PATH")),
	}
}

// renderConfigCheck summarizes authoritative validation and advanced editing actions.
// renderConfigCheck 汇总权威校验并展示高级编辑动作。
func (m *Model) renderConfigCheck() []string {
	state := m.label("尚未校验", "Not validated")
	if m.validation.Valid {
		state = m.label("校验通过", "Valid")
	} else if m.validation.Summary != "" {
		state = m.validation.Summary
	}
	lines := []string{
		m.label("配置检查", "Configuration check"),
		m.label("VMM 权威结果：", "Authoritative VMM result: ") + state,
	}
	for _, diagnostic := range m.validation.Errors {
		lines = append(lines, "  "+diagnostic)
	}
	lines = append(lines,
		m.option(0, m.label("打开全部高级配置", "Open all advanced fields")),
		m.option(1, m.label("调用 VMM 校验", "Validate with VMM")),
		m.option(2, m.label("继续到执行确认", "Continue to execution confirmation")),
	)
	return lines
}

// renderConfirm shows the complete safe-to-display plan before mutation begins.
// renderConfirm 在开始修改系统前展示完整且可安全显示的计划。
func (m *Model) renderConfirm() []string {
	lines := []string{
		m.label("确认安装", "Confirm installation"),
		m.label("源：", "Source: ") + valueOrDash(m.sourceLabel(m.plan.Source)),
		m.label("版本：", "Version: ") + valueOrDash(m.plan.Version.Tag),
		m.label("存储：", "Storage: ") + string(m.plan.Storage.Mode),
		m.label("服务模式：", "Service mode: ") + string(m.plan.ServiceMode),
		m.label("自动启动：", "Autostart: ") + boolState(m.plan.AutoStart, m.label("是", "yes"), m.label("否", "no")),
		m.label("加入 PATH：", "Add to PATH: ") + boolState(m.plan.AddToPath, m.label("是", "yes"), m.label("否", "no")),
	}
	if m.serviceUserVisible() && m.plan.ServiceMode == ServiceModeService {
		lines = append(lines, m.label("服务用户：", "Service user: ")+valueOrDash(m.plan.ServiceUser))
	}
	lines = append(lines,
		m.option(0, m.text(i18n.KeyActionConfirm, nil)),
		m.option(1, m.text(i18n.KeyActionBack, nil)),
	)
	return lines
}

// renderRunning shows post-install status and direct lifecycle operations.
// renderRunning 展示安装后状态以及直接生命周期操作。
func (m *Model) renderRunning() []string {
	return []string{
		m.label("VMM 已安装", "VMM installed"),
		m.label("运行状态：", "Runtime: ") + boolState(m.snapshot.Running, m.label("运行中", "running"), m.label("已停止", "stopped")),
		m.label("服务状态：", "Service: ") + valueOrDash(m.snapshot.ServiceState),
		m.option(0, m.text(i18n.KeyServiceStart, nil)),
		m.option(1, m.text(i18n.KeyServiceStop, nil)),
		m.option(2, m.text(i18n.KeyServiceRestart, nil)),
		m.option(3, m.text(i18n.KeyNavConfigure, nil)),
		m.option(4, m.label("返回管理首页", "Return to management home")),
	}
}

// renderUninstall shows each retention flag before the destructive operation.
// renderUninstall 在有影响的卸载动作前展示每个保留标志。
func (m *Model) renderUninstall() []string {
	return []string{
		m.text(i18n.KeyUninstallTitle, nil),
		m.option(0, toggleLabel(m.text(i18n.KeyUninstallKeepConfig, nil), m.uninstall.KeepConfig)),
		m.option(1, toggleLabel(m.text(i18n.KeyUninstallKeepData, nil), m.uninstall.KeepData)),
		m.option(2, toggleLabel(m.text(i18n.KeyServiceUninstall, nil), m.uninstall.RemoveService)),
		m.option(3, toggleLabel(m.label("移除 PATH 条目", "Remove PATH entry"), m.uninstall.RemovePath)),
		m.option(4, m.text(i18n.KeyActionConfirm, nil)),
		m.option(5, m.text(i18n.KeyActionBack, nil)),
	}
}

// renderProgress presents stage, message, and bounded numeric progress.
// renderProgress 展示阶段、消息和有界数字进度。
func (m *Model) renderProgress() string {
	progress := m.progress
	if progress.Total > 0 {
		return fmt.Sprintf("[%s] %s (%d/%d)", progress.Stage, progress.Message, progress.Current, progress.Total)
	}
	return fmt.Sprintf("[%s] %s", progress.Stage, progress.Message)
}

// footer explains the small keyboard contract shared by every page.
// footer 说明所有页面共享的简短键盘契约。
func (m *Model) footer() string {
	if m.isTextInput() {
		return m.label("↑/↓ 选择  Enter 确认  Esc 返回  Ctrl+C 退出", "↑/↓ select  Enter confirm  Esc back  Ctrl+C quit")
	}
	return m.label("↑/↓ 选择  Enter 执行  Esc 返回  q 退出", "↑/↓ select  Enter run  Esc back  q quit")
}

// option renders one cursor-aware list item.
// option 渲染一个带光标状态的列表项目。
func (m *Model) option(index int, text string) string {
	marker := "  "
	if index == m.cursor {
		marker = "> "
	}
	return marker + text
}

// renderWidth returns a conservative terminal width for resize and test messages.
// renderWidth 为 resize 和测试消息返回保守的终端宽度。
func (m *Model) renderWidth() int {
	if m.width < 1 {
		return 80
	}
	return m.width
}

// renderHeight returns a conservative terminal height for resize and test messages.
// renderHeight 为 resize 和测试消息返回保守的终端高度。
func (m *Model) renderHeight() int {
	if m.height < 1 {
		return 24
	}
	return m.height
}

// boundLines truncates wide text and limits the page to the reported viewport height.
// boundLines 截断过宽文本，并将页面限制在报告的视口高度内。
func boundLines(lines []string, width int, height int) string {
	if width < 1 {
		width = 80
	}
	if height < 1 {
		height = 24
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		result = append(result, truncateRunes(sanitizeTerminalLine(line), width))
	}
	return strings.Join(result, "\n")
}

// sanitizeTerminalLine prevents config values and remote errors from controlling the terminal.
// sanitizeTerminalLine 防止配置值和远端错误信息通过控制字符操纵终端。
func sanitizeTerminalLine(line string) string {
	var safe strings.Builder
	safe.Grow(len(line))
	for _, character := range line {
		if character < 0x20 || character == 0x7f || character >= 0x80 && character <= 0x9f {
			safe.WriteRune(' ')
			continue
		}
		safe.WriteRune(character)
	}
	return safe.String()
}

// truncateRunes keeps UTF-8 text intact while enforcing a display width bound.
// truncateRunes 保持 UTF-8 文本完整，同时限制显示宽度。
func truncateRunes(value string, width int) string {
	if width <= 0 || utf8.RuneCountInString(value) <= width {
		return value
	}
	runes := []rune(value)
	if width == 1 {
		return string(runes[:1])
	}
	return string(runes[:width-1]) + "…"
}

// valueOrDash keeps empty paths and optional statuses visually explicit.
// valueOrDash 让空路径和可选状态在视觉上保持明确。
func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// sourceLabel localizes built-in names by stable source ID and derives a safe custom label.
// sourceLabel 按稳定源 ID 本地化内置名称，并为自定义源生成安全标签。
func (m *Model) sourceLabel(source SourceOption) string {
	switch source.Source.ID {
	case download.SourceIDGitHubOfficial:
		return m.label("GitHub 官方", "GitHub official")
	case download.SourceIDGhproxyNet:
		return "ghproxy.net"
	case download.SourceIDGhProxyOrg:
		return "gh-proxy.org"
	case download.SourceIDGhfastTop:
		return "ghfast.top"
	}
	if source.DisplayName != "" && m.language == LanguageChinese {
		return source.DisplayName
	}
	parsed, err := url.Parse(source.Source.Prefix)
	if err == nil && parsed.Hostname() != "" {
		return m.label("自定义 GitHub 代理：", "Custom GitHub proxy: ") + parsed.Hostname()
	}
	return m.label("自定义下载源", "Custom download source")
}

// storageLabel returns the language-specific storage mode name.
// storageLabel 返回特定语言的存储模式名称。
func (m *Model) storageLabel(option StorageOption) string {
	if m.language == LanguageEnglish && option.LabelEnglish != "" {
		return option.LabelEnglish
	}
	if m.language == LanguageChinese && option.LabelChinese != "" {
		return option.LabelChinese
	}
	return option.Label
}

// storageAlgorithm returns the language-specific retrieval explanation.
// storageAlgorithm 返回特定语言的检索说明。
func (m *Model) storageAlgorithm(option StorageOption) string {
	if m.language == LanguageEnglish && option.AlgorithmEnglish != "" {
		return option.AlgorithmEnglish
	}
	if m.language == LanguageChinese && option.AlgorithmChinese != "" {
		return option.AlgorithmChinese
	}
	return option.Algorithm
}

// storagePathHint returns the language-specific path or endpoint hint.
// storagePathHint 返回特定语言的路径或端点提示。
func (m *Model) storagePathHint(option StorageOption) string {
	if m.language == LanguageEnglish && option.PathHintEnglish != "" {
		return option.PathHintEnglish
	}
	if m.language == LanguageChinese && option.PathHintChinese != "" {
		return option.PathHintChinese
	}
	return option.PathHint
}

// toggleLabel renders a stable yes/no state without color.
// toggleLabel 渲染不依赖颜色的稳定是/否状态。
func toggleLabel(label string, enabled bool) string {
	if enabled {
		return "[x] " + label
	}
	return "[ ] " + label
}

// maskedValue prevents sensitive values from appearing in the rendered terminal view.
// maskedValue 防止敏感值出现在终端渲染内容中。
func maskedValue(value string) string {
	if value == "" {
		return "********"
	}
	return "********"
}

// boolState chooses one of two localized states.
// boolState 选择两个本地化状态之一。
func boolState(value bool, yes string, no string) string {
	if value {
		return yes
	}
	return no
}
