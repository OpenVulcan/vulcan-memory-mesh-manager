// These tests exercise the actual keyboard path for optional configuration values.
// 这些界面测试执行可选配置值的真实键盘操作路径。
package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestNullShortcutKeepsZeroDistinct verifies clearing, saving, reopening, and changing a nullable scalar back to zero.
// TestNullShortcutKeepsZeroDistinct 验证置空、保存、重开及恢复为零，不将文本输入误判为空值。
func TestNullShortcutKeepsZeroDistinct(t *testing.T) {
	m := NewModel(ModelConfig{})
	m.setScreen(ScreenFieldEdit)
	m.editingField = -1
	m.operationScreen = ScreenConfigCheck
	m.configFields.Fields = []ConfigField{{Path: "threshold", Type: "number", Nullable: true, Editable: true, Value: "0.5"}, {Path: "label", Type: "string", Editable: true, Value: "original"}}
	m.validation = ValidationSummary{Valid: true}
	m.configPreview = &ConfigPreview{}
	_, cmd := m.updateKey(tea.KeyPressMsg(tea.Key{Code: 'n', Mod: tea.ModCtrl}))
	if cmd != nil || !m.configFields.Fields[0].Null || m.validation.Valid || m.configPreview != nil {
		t.Fatal("null shortcut did not stage and invalidate")
	}
	m.cursor = len(m.configFields.Fields)
	m.activateFieldSelection()
	if len(m.plan.ConfigFields) != 1 || !m.plan.ConfigFields[0].Null {
		t.Fatal("null intent was not saved to plan")
	}
	m.setScreen(ScreenFieldEdit)
	m.cursor = 0
	m.activateFieldSelection()
	m.input = "0"
	m.activateTextInput()
	if m.configFields.Fields[0].Null || m.configFields.Fields[0].Value != "0" {
		t.Fatal("explicit zero retained the null flag")
	}
	m.cursor = 1
	m.updateKey(tea.KeyPressMsg(tea.Key{Code: 'n', Mod: tea.ModCtrl}))
	if m.configFields.Fields[1].Changed || m.configFields.Fields[1].Null {
		t.Fatal("non-nullable string was cleared")
	}
	m.activateFieldSelection()
	m.input = "null"
	m.activateTextInput()
	if m.configFields.Fields[1].Null || m.configFields.Fields[1].Value != "null" {
		t.Fatal("literal null text was not kept as text")
	}
}
