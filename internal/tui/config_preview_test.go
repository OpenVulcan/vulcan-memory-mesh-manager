// These tests cover preview navigation, long-value visibility, localization, and invalidation.
// 这些界面测试覆盖预览导航、长值可见性、多语言及编辑后失效。
package tui

import (
	"strings"
	"testing"
)

// TestConfigPreviewNavigationAndInvalidation proves review remains read-only and cannot survive a changed plan.
// TestConfigPreviewNavigationAndInvalidation 验证预览保持只读，且不能在计划修改后继续有效。
func TestConfigPreviewNavigationAndInvalidation(t *testing.T) {
	m := NewModel(ModelConfig{})
	m.language = LanguageChinese
	m.width, m.height = 40, 12
	m.validation = ValidationSummary{Valid: true}
	m.configPreview = &ConfigPreview{Changes: []ConfigChange{{Path: "grpc.listen_addr", Kind: "updated", Before: "old", After: strings.Repeat("长", 100) + "END"}, {Path: ".env / KEY", Kind: "credential"}}}
	m.setScreen(ScreenConfirm)
	m.cursor = 2
	_, cmd := m.activateSelection()
	if cmd != nil || m.screen != ScreenConfigPreview || !strings.Contains(m.render(), "配置写入预览") {
		t.Fatal("confirmation did not open read-only preview")
	}
	foundTail := false
	for index, row := range m.previewRows() {
		if strings.Contains(row, "END") {
			m.cursor = index
			foundTail = strings.Contains(m.render(), "END")
		}
	}
	if !foundTail {
		t.Fatal("long preview value was truncated instead of scrollable")
	}
	m.language = LanguageEnglish
	m.cursor = 0
	if !strings.Contains(m.render(), "Configuration writes") {
		t.Fatal("preview did not switch language")
	}
	_, cmd = m.handleEscape()
	if cmd != nil || m.screen != ScreenConfirm {
		t.Fatal("escape failed to return to confirmation")
	}
	m.invalidateValidation()
	if m.configPreview != nil || m.validation.Valid {
		t.Fatal("changed plan retained old preview")
	}
}
