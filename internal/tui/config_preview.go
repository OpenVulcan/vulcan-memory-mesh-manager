// This file renders the validated configuration write preview without accessing files or secret values.
// 本文件展示校验后的配置写入预览，属于界面层，不访问文件或秘密值。
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// ConfigChange describes a schema field, rule digest, or credential name that will change.
// ConfigChange 描述将变化的 schema 字段、规则摘要或凭据名称，所有值必须预先脱敏。
type ConfigChange struct {
	// Path and Kind identify the exact field and the added, updated, removed, rule, or credential action.
	// Path 与 Kind 标识精确字段及新增、更新、移除、规则或凭据动作。
	Path, Kind string
	// Before and After contain display-safe values only; credential actions leave both empty.
	// Before 与 After 仅包含安全展示值；凭据动作将两者留空。
	Before, After string
}

// ConfigPreview is tied to one successful candidate validation and discarded on any plan edit.
// ConfigPreview 绑定一次成功的候选校验，计划一经编辑即丢弃。
type ConfigPreview struct {
	// Changes lists all schema-backed override changes and explicit auxiliary file writes.
	// Changes 列出 schema 覆盖变化及明确的辅助文件写入。
	Changes []ConfigChange
}

// previewRows wraps every change into independently scrollable lines so long values remain inspectable.
// previewRows 将每项变化换行为可独立滚动的行，确保长值可以完整查看，返回已脱敏文本行。
func (m *Model) previewRows() []string {
	rows := []string{m.label("返回确认页", "Back to confirmation")}
	if m.configPreview == nil {
		return rows
	}
	width := m.renderWidth() - 4
	if width < 1 {
		width = 1
	}
	for _, change := range m.configPreview.Changes {
		kind := m.label("更新", "updated")
		switch change.Kind {
		case "added":
			kind = m.label("新增", "added")
		case "removed":
			kind = m.label("移除", "removed")
		case "rule":
			kind = m.label("规则摘要", "rule digest")
		case "credential":
			kind = m.label("写入凭据，值已隐藏", "write credential, value hidden")
		}
		lines := []string{fmt.Sprintf("[%s] %s", kind, change.Path)}
		if change.Kind != "credential" {
			lines = append(lines, "- "+change.Before, "+ "+change.After)
		}
		for _, line := range lines {
			for _, paragraph := range strings.Split(line, "\n") {
				rows = append(rows, strings.Split(ansi.Hardwrap(sanitizeTerminalLine(paragraph), width, false), "\n")...)
			}
		}
	}
	return rows
}

// renderConfigPreview shows saved-user-override to candidate-user-override changes, not merged runtime provenance.
// renderConfigPreview 展示已保存用户覆盖到候选用户覆盖的变化，不将其冒充合并运行时来源。
func (m *Model) renderConfigPreview() []string {
	lines := []string{m.label("配置写入预览：已保存覆盖 → 候选覆盖", "Configuration writes: saved overrides → candidate overrides"), m.label("↑/↓ 滚动，Esc 返回；密钥隐藏，规则仅显示内容摘要。", "Scroll with arrows, Esc to return; secrets hidden, rule content shown as digests.")}
	if m.configPreview != nil && len(m.configPreview.Changes) == 0 {
		lines = append(lines, m.label("没有配置写入差异。", "No configuration write differences."))
	}
	for index, row := range m.previewRows() {
		lines = append(lines, m.option(index, row))
	}
	return lines
}
