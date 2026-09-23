// This file renders read-only effective configuration and source metadata received from the runtime.
// 本文件属于界面层，展示运行时返回的只读生效配置及来源元数据。
package tui

import (
	"github.com/charmbracelet/x/ansi"
	"strings"
)

// EffectiveField contains a redacted JSON leaf and origin metadata; Pointer uses canonical JSON Pointer syntax.
// EffectiveField 携带脱敏 JSON 叶子及来源元数据；Pointer 使用规范 JSON Pointer 语法。
type EffectiveField struct {
	Pointer, Value, Kind, File string
	Environment                []string
	Normalized                 bool
}

// EffectiveConfiguration is an explicit inspection snapshot; Candidate distinguishes unsaved configuration.
// EffectiveConfiguration 是明确查看操作的快照；Candidate 区分尚未保存的候选配置。
type EffectiveConfiguration struct {
	Candidate bool
	Fields    []EffectiveField
}

// effectiveRows wraps all values and origin labels into independently scrollable lines without truncating long paths.
// effectiveRows 将全部值和来源说明转换为可独立滚动的行，不截断长路径，返回双语展示行。
func (m *Model) effectiveRows() []string {
	rows := []string{m.label("返回", "Back")}
	if m.effective == nil {
		return rows
	}
	width := m.renderWidth() - 4
	if width < 1 {
		width = 1
	}
	for _, field := range m.effective.Fields {
		origin := m.label("运行时未提供来源", "Runtime did not provide origins")
		switch field.Kind {
		case "initial":
			origin = m.label("初始配置值", "Initial configuration")
		case "file":
			origin = m.label("配置文件：", "Configuration file: ") + field.File
		case "environment":
			origin = m.label("环境覆盖", "Environment override")
		case "normalization":
			origin = m.label("运行时默认或派生值", "Runtime default or derived value")
		}
		if len(field.Environment) > 0 {
			origin += " [" + strings.Join(field.Environment, ", ") + "]"
		}
		if field.Normalized {
			origin += m.label("；经归一化调整", "; normalized")
		}
		for _, line := range []string{field.Pointer + " = " + field.Value, "  " + origin} {
			rows = append(rows, strings.Split(ansi.Hardwrap(sanitizeTerminalLine(line), width, false), "\n")...)
		}
	}
	return rows
}

// renderEffective distinguishes candidate data and process environment from a running service's own environment.
// renderEffective 区分候选数据和当前进程环境，不将结果冒充已运行服务进程的内部配置。
func (m *Model) renderEffective() []string {
	title := m.label("已保存配置的生效值与来源", "Saved effective configuration and origins")
	if m.effective != nil && m.effective.Candidate {
		title = m.label("候选配置的生效值与来源（尚未保存）", "Candidate effective configuration and origins (not saved)")
	}
	lines := []string{title, m.label("按当前管理器环境解析；秘密字段省略。↑/↓ 滚动，Esc 返回。", "Resolved in the manager environment; secret fields omitted. Arrows scroll, Esc returns.")}
	for index, row := range m.effectiveRows() {
		lines = append(lines, m.option(index, row))
	}
	return lines
}
