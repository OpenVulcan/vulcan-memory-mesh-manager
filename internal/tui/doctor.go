// This file renders the installed VMM diagnostic result in the TUI without mixing static validity with runtime readiness.
// 本文件在界面层展示已安装 VMM 诊断结果，并将静态有效性与运行时就绪状态分开。
package tui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// doctorRows builds scrollable, sanitized lines from the authoritative configuration and local health results.
// doctorRows 根据权威配置结果和本地健康结果构造可滚动的脱敏行，返回唯一的首页操作。
func (m *Model) doctorRows() []string {
	rows := []string{m.label("返回首页", "Back to home")}
	if m.savedValidation == nil || m.health == nil {
		return rows
	}
	lines := []string{
		m.label("配置：", "Configuration: ") + boolState(m.savedValidation.Valid, m.label("通过", "valid"), m.label("未通过", "invalid")),
		m.label("最近通过时间：", "Last successful check: ") + valueOrDash(m.snapshot.LastValidation),
		m.label("安装：", "Installation: ") + boolState(m.snapshot.Installed, m.label("完整", "complete"), m.label("未确认完整", "not verified complete")),
		m.label("运行时：", "Runtime: ") + m.healthClassText(m.health.Class),
		m.label("本地探测耗时：", "Local probe duration: ") + formatDurationMsec(m.health.ElapsedMsec),
	}
	if m.health.Error != "" {
		lines = append(lines, m.label("诊断码：", "Diagnostic code: ")+m.health.Error)
	}
	if m.snapshot.Incomplete {
		lines = append(lines, m.label("安装状态：", "Installation state: ")+m.integrityIssueText(m.snapshot.IntegrityIssue))
	}
	for _, message := range m.savedValidation.Errors {
		lines = append(lines, m.operationText(message))
	}
	width := m.renderWidth() - 4
	if width < 1 {
		width = 1
	}
	for _, line := range lines {
		rows = append(rows, strings.Split(ansi.Hardwrap(sanitizeTerminalLine(line), width, false), "\n")...)
	}
	return rows
}

// healthClassText translates only the fixed VMM health classes; the validated code remains visible separately.
// healthClassText 仅翻译 VMM 固定健康类别；已校验诊断码另行展示，便于准确定位。
func (m *Model) healthClassText(class string) string {
	switch class {
	case "ok":
		return m.label("就绪", "ready")
	case "unreachable":
		return m.label("不可达", "unreachable")
	case "configuration_invalid":
		return m.label("配置无效", "configuration invalid")
	case "storage_unavailable":
		return m.label("存储不可用", "storage unavailable")
	case "runtime_error":
		return m.label("运行时错误", "runtime error")
	default:
		return class
	}
}

// formatDurationMsec keeps the fixed health duration readable without exposing process output.
// formatDurationMsec 将固定健康探测耗时转换为可读文本，不包含进程原始输出。
func formatDurationMsec(value int64) string {
	return strconv.FormatInt(value, 10) + " ms"
}

// renderDoctor explains that the local health probe does not invoke a paid provider endpoint.
// renderDoctor 说明本地健康探测不会调用可能收费的供应商端点，并展示诊断结果。
func (m *Model) renderDoctor() []string {
	lines := []string{m.label("配置与运行诊断", "Configuration and runtime diagnostics"), m.label("配置静态检查与本地 gRPC 健康探测分开显示；不会调用供应商。", "Static configuration and local gRPC health are shown separately; no provider calls.")}
	for index, row := range m.doctorRows() {
		lines = append(lines, m.option(index, row))
	}
	return lines
}
