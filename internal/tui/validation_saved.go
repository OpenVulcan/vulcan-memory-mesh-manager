// This file presents saved-configuration checks independently of candidate installation validation.
// 本文件属于界面层，独立展示已保存配置检查，不复用候选安装校验状态。
package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// savedCheckRows provides scrollable sanitized diagnostics and a single return action.
// savedCheckRows 提供可滚动的脱敏诊断及一个返回动作，返回双语行列表。
func (m *Model) savedCheckRows() []string {
	rows := []string{m.label("返回首页", "Back to home")}
	if m.savedValidation == nil {
		return rows
	}
	lines := []string{boolState(m.savedValidation.Valid, m.label("配置检查通过", "Configuration check passed"), m.label("配置检查未通过", "Configuration check failed")), m.label("最近通过时间：", "Last successful check: ") + valueOrDash(m.snapshot.LastValidation)}
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

// renderSavedCheck distinguishes a current result from the historical timestamp and does not promise external connectivity.
// renderSavedCheck 区分当前结果与历史时间，不将静态校验当作外部服务连通性证明。
func (m *Model) renderSavedCheck() []string {
	lines := []string{m.label("已保存配置检查", "Saved configuration check"), m.label("检查配置、凭据引用和规则；不调用供应商、不启动数据库。", "Checks configuration, credential references and rules; no provider calls or database startup.")}
	for index, row := range m.savedCheckRows() {
		lines = append(lines, m.option(index, row))
	}
	return lines
}
