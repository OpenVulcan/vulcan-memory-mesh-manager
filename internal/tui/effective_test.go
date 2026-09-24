// These tests verify bilingual effective-value presentation, scrolling, and return navigation.
// 这些测试验证双语生效值展示、滚动及返回导航，属于界面回归测试。
package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestEffectiveViewKeepsSourcesAndLongValuesReadable checks candidate labeling and every wrapped tail in a narrow terminal.
// TestEffectiveViewKeepsSourcesAndLongValuesReadable 检查候选标记及窄终端中换行长值的末尾是否可见。
func TestEffectiveViewKeepsSourcesAndLongValuesReadable(t *testing.T) {
	m := NewModel(ModelConfig{})
	m.language = LanguageChinese
	m.width, m.height = 40, 12
	m.operationScreen = ScreenConfirm
	m.effective = &EffectiveConfiguration{Candidate: true, Fields: []EffectiveField{{Pointer: "/logging/level", Value: strings.Repeat("长", 100) + "TAIL", Kind: "file", File: "config.yaml", Environment: []string{"LOG_LEVEL"}, Normalized: true}, {Pointer: "/memory_pipeline/min_similarity_score", Value: "null", Kind: "initial"}}}
	m.setScreen(ScreenEffective)
	rows := strings.Join(m.effectiveRows(), "\n")
	if !strings.Contains(m.render(), "尚未保存") || !strings.Contains(rows, "归一化") || !strings.Contains(rows, "LOG_LEVEL") || !strings.Contains(rows, "null") {
		t.Fatal("effective metadata lost")
	}
	found := false
	for index, row := range m.effectiveRows() {
		if strings.Contains(row, "TAIL") {
			m.cursor = index
			found = strings.Contains(m.render(), "TAIL")
		}
	}
	if !found {
		t.Fatal("effective long value truncated")
	}
	m.language = LanguageEnglish
	m.cursor = 0
	if !strings.Contains(m.render(), "not saved") {
		t.Fatal("effective language did not change")
	}
	_, cmd := m.handleEscape()
	if cmd != nil || m.screen != ScreenConfirm {
		t.Fatal("effective escape lost return page")
	}
	m.invalidateValidation()
	if m.effective != nil {
		t.Fatal("plan edit retained effective snapshot")
	}
}

// TestEffectiveEntryDispatchesCorrectContext follows real key and event routing for saved and candidate views.
// TestEffectiveEntryDispatchesCorrectContext 沿真实按键和事件路由验证已保存及候选查看上下文。
func TestEffectiveEntryDispatchesCorrectContext(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		controller := &testController{}
		m := NewModel(ModelConfig{Controller: controller, Initial: InstallationSnapshot{Installed: true, VMMVersion: "v0.1.0"}})
		origin := ScreenHome
		m.cursor = 12
		if candidate {
			origin = ScreenConfirm
			m.setScreen(origin)
			m.configPreview = &ConfigPreview{}
			m.validation = ValidationSummary{Valid: true}
			m.plan.Version = VersionOption{Tag: "v0.1.0"}
			m.cursor = 3
		}
		m = update(t, m, press(tea.KeyEnter, ""))
		if len(controller.requests) != 1 || controller.requests[0].Kind != OperationEffective || m.Screen() != ScreenEffective || m.effective == nil || m.effective.Candidate != candidate {
			t.Fatal("effective view lost operation context")
		}
		m = update(t, m, press(tea.KeyEscape, ""))
		if m.Screen() != origin {
			t.Fatal("effective view returned to wrong page")
		}
	}
}
